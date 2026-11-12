"""Record WFS2 receiver metadata. See the project README for the wire and file schemas."""
import argparse
import csv
import json
import math
import re
import secrets
import signal
import sys
import time
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path

import serial
from protocol import Decoder, FIELDS, rows, status_fields
from width_survey import survey


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def camera_mac(value):
    value = value.lower().replace("-", ":")
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value):
        raise argparse.ArgumentTypeError("expected a six-octet MAC address")
    if value == "00:00:00:00:00:00":
        raise argparse.ArgumentTypeError("the all-zero address is reserved for untargeted capture")
    return value


def channel_mode(value):
    if value in ("auto", "scan"):
        return {"auto": 0, "scan": -1}[value]
    if value.isdecimal() and 1 <= int(value) <= 13:
        return int(value)
    raise argparse.ArgumentTypeError("use auto, scan or a channel from 1 to 13")


class Session:
    def __init__(self, info, folder, files):
        self.info = info
        self.folder = folder
        self.decoder = Decoder()
        self.raw = files.enter_context((folder / "raw_serial.bin").open("xb"))
        self.log = files.enter_context((folder / "status.jsonl").open("x", encoding="utf8"))
        self.writers = []
        self.outputs = [self.raw, self.log]
        for name in ("all_wifi_packets.csv", "camera_packets.csv"):
            stream = files.enter_context((folder / name).open("x", newline="", encoding="utf8"))
            writer = csv.DictWriter(stream, fieldnames=FIELDS)
            writer.writeheader()
            self.outputs.append(stream)
            self.writers.append(writer)
        self.count = Counter({k: 0 for k in ("rows", "camera_rows", "wire_gaps",
            "observation_gaps", "wire_backwards", "observation_backwards", "equal_adjacent_timestamps",
            "timestamp_decreases", "watchdog_messages", "foreign_frames", "bytes")})
        self.begun = self.ended = False
        self.last_seq = -1
        self.last_id = 0
        self.last_ts = None
        self.last_status = None
        self.tail = b""
        self.unframed_at_begin = None

    def consume(self, data, final=False):
        self.raw.write(data)
        self.count["bytes"] += len(data)
        marker = b"Task watchdog got triggered"
        joined = self.tail + data
        self.count["watchdog_messages"] += joined.count(marker)
        self.tail = joined[-(len(marker)-1):]
        received = utc()
        for kind, token, seq, payload in self.decoder.feed(data, final):
            if token != self.info["token"]:
                self.count["foreign_frames"] += 1
                continue
            gap = seq - self.last_seq - 1
            self.count["wire_gaps"] += max(0, gap)
            self.count["wire_backwards"] += gap < 0
            self.last_seq = seq
            if kind != b"P":
                self.last_status = status_fields(payload)
                entry = dict(self.last_status, kind=kind.decode(), wire_seq=seq, host_utc=received)
                self.log.write(json.dumps(entry) + "\n")
                if kind == b"B":
                    self.unframed_at_begin = self.decoder.errors["unframed_bytes"]
                self.begun |= kind == b"B"
                self.ended |= kind == b"E"
                continue
            for row in rows(received, seq, payload):
                self.writers[0].writerow(row)
                self.count["rows"] += 1
                if self.info["camera_mac"] in (row["addr1_ra"], row["addr2_ta"]):
                    self.writers[1].writerow(row)
                    self.count["camera_rows"] += 1
                ident = row["observation_id"]
                self.count["observation_gaps"] += max(0, ident - self.last_id - 1)
                self.count["observation_backwards"] += ident <= self.last_id
                self.last_id = ident
                ts = row["esp_timestamp_us"]
                if self.last_ts is not None:
                    self.count["equal_adjacent_timestamps"] += ts == self.last_ts
                    self.count["timestamp_decreases"] += ts < self.last_ts
                self.last_ts = ts

    def checkpoint(self):
        for stream in self.outputs:
            stream.flush()
        snapshot = dict(self.info, begin_received=self.begun, end_received=self.ended,
                        host=dict(self.count), decoder=dict(self.decoder.errors),
                        latest_firmware_status=self.last_status)
        if self.ended:
            s = self.last_status
            snapshot["eligible_minus_accounted"] = s["eligible"] - s["overflow"] - s["tx_lost"] - s["sent"]
            snapshot["sent_minus_rows"] = s["sent"] - self.count["rows"]
            snapshot["trailing_observation_gap"] = s["eligible"] - self.last_id
        temp = self.folder / "session.tmp"
        temp.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf8")
        # Windows readers and indexers can briefly block an atomic replacement.
        for attempt in range(10):
            try:
                temp.replace(self.folder / "session.json")
                break
            except PermissionError:
                if attempt == 9:
                    raise
                time.sleep(0.05)
        return snapshot


def record(args, *, folder=None):
    token = secrets.randbelow(0xffffffff) + 1
    if folder is None:
        folder = Path(args.output) / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ_")
                                      + f"{args.state}_{token:08x}")
    folder.mkdir(parents=True, exist_ok=False)
    print(f"Recording directory {folder.resolve()}", flush=True)
    info = dict(format="WFS2", token=token, opened_utc=utc(), camera_mac=args.camera,
                camera_state=args.state, requested_mode=args.channel, notes=args.notes,
                port=args.port, baud=args.baud, requested_seconds=args.duration,
                camera_filter="addr1_ra or addr2_ta equals camera_mac", result="in_progress")
    secondary = getattr(args, "secondary", None)
    if secondary:
        info.update(requested_width_mhz=40, requested_secondary=secondary)
    if getattr(args, "labels", None):
        info["device_labels"] = args.labels
    interrupted = False

    def on_interrupt(signum, frame):
        nonlocal interrupted
        interrupted = True

    with ExitStack() as files:
        session = Session(info, folder, files)
        session.checkpoint()
        previous = signal.signal(signal.SIGINT, on_interrupt)
        files.callback(signal.signal, signal.SIGINT, previous)
        stop_sent = None
        try:
            # Configure modem lines before opening. Flash/reset tools own EN/BOOT.
            link = serial.Serial(baudrate=args.baud, timeout=0.1, write_timeout=1)
            link.dtr = False
            link.rts = False
            link.port = args.port
            with link as port:
                wire_target = args.camera.replace(":", "") if args.camera else "000000000000"
                verb = {"above": "WIDE+", "below": "WIDE-"}.get(secondary, "START")
                start_command = f"\n{verb} {token:08x} {args.channel} {wire_target}\n".encode()
                opened = time.monotonic()
                last_start = last_frame = flushed = opened
                port.write(start_command)
                began_at = None
                while not session.ended:
                    data = port.read(min(32768, port.in_waiting or 1))
                    old_seq = session.last_seq
                    session.consume(data)
                    now = time.monotonic()
                    if old_seq != session.last_seq:
                        last_frame = now
                    if session.begun and began_at is None:
                        if secondary:
                            status = session.last_status
                            if (status.get("reported_primary") != args.channel or
                                    status.get("reported_secondary") != secondary or not status["locked"]):
                                port.write(f"STOP {token:08x}\n".encode())
                                raise RuntimeError("Receiver could not confirm the requested HT40 channel")
                        began_at = now
                    duration_met = began_at is not None and args.duration and now - began_at >= args.duration
                    if (interrupted or duration_met) and stop_sent is None:
                        port.write(f"STOP {token:08x}\n".encode())
                        stop_sent = now
                    if stop_sent is not None and not session.ended and now - stop_sent > 6:
                        raise TimeoutError("STOP sent but final firmware counters did not arrive")
                    if not session.begun and now - opened > 10:
                        if secondary:
                            raise TimeoutError("No HT40 BEGIN; check the port and install HT40-capable firmware")
                        raise TimeoutError("No valid BEGIN on this port; check transport, firmware and raw bytes")
                    if session.begun and now - last_frame > 6:
                        raise TimeoutError("No valid session frames or heartbeat for six seconds")
                    if not session.begun and stop_sent is None and now - last_start > 1:
                        port.write(start_command)
                        last_start = now
                    if now - flushed >= 2:
                        session.checkpoint()
                        print(f"Rows {session.count['rows']:,}   Camera {session.count['camera_rows']:,}", flush=True)
                        flushed = now
                if not session.begun or stop_sent is None:
                    raise RuntimeError("Unexpected session boundary; see status.jsonl")
                info["result"] = "completed"
        except (OSError, serial.SerialException, RuntimeError) as exc:
            info.update(result="incomplete", error=str(exc))
            print(str(exc), file=sys.stderr)
        finally:
            session.consume(b"", final=True)
            if interrupted:
                info["operator_stopped"] = True
            info["closed_utc"] = utc()
            summary = session.checkpoint()
        if info["result"] != "completed":
            return 1
        stats = session.last_status
        checks = {k: summary[k] for k in ("eligible_minus_accounted", "sent_minus_rows")}
        checks.update({k: stats[k] for k in ("overflow", "tx_lost", "tx_errors", "tune_errors",
                                               "malformed", "rx_errors", "unsupported")})
        checks.update({k: session.count[k] for k in ("wire_gaps", "wire_backwards", "observation_gaps",
                                                     "observation_backwards", "watchdog_messages")})
        checks.update({k: session.decoder.errors[k] for k in ("bad_headers", "crc_failures",
                                                              "trailing_partial_bytes")})
        checks["unframed_bytes_after_begin"] = session.decoder.errors["unframed_bytes"] - session.unframed_at_begin
        checks["empty_capture"] = session.count["rows"] == 0
        info["quality_findings"] = {k: v for k, v in checks.items() if v}
        review = bool(info["quality_findings"])
        info["quality_review_required"] = review
        session.checkpoint()
        print(f"Rows {session.count['rows']}, overflow {stats['overflow']}, "
              f"sent minus rows {summary['sent_minus_rows']}, quality review {review}")
        return 2 if review else 0


def load_labels(path):
    """Read operator annotations; offsets are seconds from the session BEGIN."""
    try:
        labels = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        if not isinstance(labels, list) or not labels:
            raise ValueError("expected a non-empty JSON list")
        for entry in labels:
            if not isinstance(entry, dict) or any(not isinstance(entry.get(k), str) or
                    not entry[k].strip() for k in ("mac", "alias", "device_class", "activity")):
                raise ValueError("each label needs mac, alias, device_class and activity")
            entry["mac"] = camera_mac(entry["mac"])
            start = entry.setdefault("start_s", 0)
            end = entry.setdefault("end_s", None)
            for value in (start,) if end is None else (start, end):
                if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                    raise ValueError("label times must be nonnegative finite seconds")
            if end is not None and end <= start:
                raise ValueError("end_s must exceed start_s")
        return labels
    except (OSError, ValueError, OverflowError) as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", required=True, help="serial port of the receiver")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--camera", type=camera_mac, help="test-device MAC for filtering and automatic lock")
    p.add_argument("--state", choices=("unknown", "idle", "streaming", "off", "motion",
                                     "motion-triggered", "background"), default="unknown")
    p.add_argument("--channel", type=channel_mode, help="auto, scan, or channel number")
    p.add_argument("--secondary", choices=("above", "below", "auto"),
                   help="fixed HT40 position, or auto to survey HT20 and HT40 for a target MAC")
    p.add_argument("--probe-seconds", type=float,
                   help="dwell per search setting with --secondary auto (default 2 seconds)")
    p.add_argument("--labels", type=load_labels, metavar="JSON_FILE",
                   help="optional per-device activity intervals, in seconds from BEGIN")
    p.add_argument("--notes", default="")
    p.add_argument("--output", default="recordings")
    p.add_argument("--duration", type=float, help="seconds after BEGIN; in a width survey, "
                   "seconds per comparison recording (default 60)")
    args = p.parse_args()
    if args.channel is None:
        args.channel = 0 if args.camera else -1
    if args.channel == 0 and not args.camera:
        p.error("--channel auto requires --camera")
    if args.secondary in ("above", "below") and (args.channel < 1 or
            not 1 <= args.channel + (4 if args.secondary == "above" else -4) <= 13):
        p.error("--secondary requires a fixed primary and secondary channel within 1..13")
    if args.duration is not None and (not math.isfinite(args.duration) or args.duration <= 0):
        p.error("--duration must be positive and finite")
    if args.probe_seconds is not None and (args.secondary != "auto" or
            not math.isfinite(args.probe_seconds) or args.probe_seconds <= 0):
        p.error("--probe-seconds requires --secondary auto and a positive finite duration")
    if args.secondary == "auto":
        if not args.camera or args.channel == -1:
            p.error("--secondary auto requires --camera and an automatic or fixed primary channel")
        return survey(args, record)
    return record(args)


if __name__ == "__main__":
    sys.exit(main())
