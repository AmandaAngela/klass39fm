#!/usr/bin/env python3
"""
Serial -> pcap converter for the ESP32-C5 sniffer (../esp32c5_sniffer.ino).

The ESP32 sends binary records over USB serial: a 22-byte record header followed by the
first bytes of each captured 802.11 frame. This script turns them into a standard pcap
file (radiotap + 802.11) that Wireshark opens directly, and can optionally stream the
same packets into a live Wireshark window.

Two ways to choose the channel:
  -c N           listen on channel N
  --mac ...      (no -c) hop through all channels looking for the MAC addresses you list,
                 then lock on their channel. With --mac, only frames to/from those MACs
                 are written (add --all to keep every frame on the channel).

Setup (PowerShell):
  pip install pyserial
Examples:
  python sniff_host.py -p COM5 -c 6 -o cam_test.pcap
  python sniff_host.py -p COM5 --mac aa:bb:cc:dd:ee:01=camera --mac aa:bb:cc:dd:ee:02=laptop -o test.pcap
  python sniff_host.py -p COM5 --mac aa:bb:cc:dd:ee:01=camera --band 2.4 -l -o cam.pcap

Guided stages (--stages): after locking on the channel, the script walks you through the
stages in DEFAULT_STAGES (or --stages-file). You press Enter to start each stage; it ends
after --stage-secs (or when you press Enter again). The start/end time of every stage is
written to NAME_<time>_stages.csv together with a ready-to-paste Wireshark filter.
  python sniff_host.py -p COM5 --band 2.4 --mac <cam>=camera --mac <laptop>=laptop --stages -o run1
"""
import argparse
import csv
import datetime
import os
import queue
import shutil
import struct
import subprocess
import sys
import threading
import time

# ---- where capture files go: the "datasets" folder next to this script ----
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "datasets")

# ---- stages for --stages (name, what to do). Edit here, or pass --stages-file ----
DEFAULT_STAGES = [
    ("cam_live_still",
     "Keep the camera's live view open (as during the search). Keep the scene STILL (nothing moving in view)."),
    ("cam_live_motion",
     "Keep live view open. Make continuous MOVEMENT in front of the camera."),
    ("cam_idle",
     "CLOSE the camera app everywhere (no live view). Camera stays powered on. Laptop idle."),
    ("cam_idle_laptop_youtube",
     "Keep the camera app closed (camera idle). Play a YouTube video on the laptop."),
    ("cam_idle_laptop_download",
     "Stop YouTube. Start a large file download on the laptop (camera still idle)."),
    ("cam_idle_laptop_videocall",
     "Stop the download. Start a VIDEO CALL on the laptop with its webcam ON (camera still idle). "
     "Call someone who is NOT on this Wi-Fi, e.g. a phone on mobile data."),
    ("cam_live_laptop_youtube",
     "End the call. Open the camera live view AND play YouTube on the laptop."),
]

# ---- record format sent by the firmware (must match RecHdr in the .ino) ----
MAGIC = b"\xA5\x5A"
REC_FRAME, REC_STATS, REC_TEXT, REC_EVENT = 0, 1, 2, 3
EV_CHANNEL, EV_SWEEP_DONE, EV_HOP_STOP = 1, 2, 3
# magic, type, channel, rx_ts, cb_ts, orig_len, cap_len, rssi, noise, rate, pkt_type, sum
HDR = struct.Struct("<2sBBIIHHbbBBH")
assert HDR.size == 22
STATS = struct.Struct("<IIIB")        # frames queued, frames dropped, ring buffer free, channel
EVENT = struct.Struct("<BBIH")        # event, channel, sweeps completed, dwell ms (+ width byte, unused here)
MAX_CAP = 4096
BAND_CODE = {"both": 0, "2.4": 2, "5": 5}


class Parser:
    """Splits the serial byte stream into records; skips garbage (boot text, corrupt bytes)."""

    def __init__(self):
        self.buf = bytearray()
        self.bad = 0                  # bytes skipped while resyncing

    def feed(self, chunk):
        buf = self.buf
        buf += chunk
        out = []
        while True:
            i = buf.find(MAGIC)
            if i < 0:
                if len(buf) > 1:
                    del buf[:-1]      # last byte may be the first half of MAGIC
                break
            if i:
                del buf[:i]
            if len(buf) < HDR.size:
                break
            fields = HDR.unpack_from(buf)
            typ, clen, s = fields[1], fields[6], fields[11]
            if typ > REC_EVENT or clen > MAX_CAP:
                del buf[:1]
                self.bad += 1
                continue
            total = HDR.size + clen
            if len(buf) < total:
                break
            if (sum(buf[:HDR.size - 2]) + sum(buf[HDR.size:total])) & 0xFFFF != s:
                del buf[:1]
                self.bad += 1
                continue
            out.append((fields, bytes(buf[HDR.size:total])))
            del buf[:total]
        return out


class Unwrap32:
    """The ESP32 sends a 32-bit microsecond counter that wraps every ~71.6 min; make it monotonic."""

    def __init__(self):
        self.last = None
        self.high = 0

    def __call__(self, v):
        if self.last is not None and v < self.last and self.last - v > 0x80000000:
            self.high += 1 << 32
        self.last = v
        return self.high + v


# ---- pcap writing ----
def chan_to_freq(ch):
    if ch == 14:
        return 2484
    if 1 <= ch <= 13:
        return 2407 + 5 * ch
    return 5000 + 5 * ch


def radiotap(ch, rssi, noise):
    """14-byte radiotap header: channel (bit 3), signal dBm (bit 5), noise dBm (bit 6)."""
    present = (1 << 3) | (1 << 5) | (1 << 6)
    chflags = 0x0080 if ch <= 14 else 0x0100      # 2 GHz / 5 GHz
    return struct.pack("<BBHIHHbb", 0, 0, 14, present, chan_to_freq(ch), chflags, rssi, noise)


def pcap_global_header():
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)   # 127 = radiotap


def pcap_record(ts, rt, data, orig_len):
    sec = int(ts)
    usec = int(round((ts - sec) * 1e6))
    if usec >= 1000000:
        sec, usec = sec + 1, usec - 1000000
    return struct.pack("<IIII", sec, usec, len(rt) + len(data), len(rt) + orig_len) + rt + data


def secondary_for(ch, secondary=None):
    """'a' (above) or 'b' (below) for a 40 MHz channel pair, or None if it can't be worked out.
    2.4 GHz: channels 1-4 can only pair upwards and 10-13 only downwards; 5-9 depend on the router.
    5 GHz: 40 MHz pairs are fixed (36+40, 44+48, ..., 149+153, 157+161)."""
    if secondary:
        return secondary[0]
    if 1 <= ch <= 4:
        return "a"
    if 10 <= ch <= 13:
        return "b"
    if 36 <= ch <= 144:
        return "a" if ((ch - 36) // 4) % 2 == 0 else "b"
    if 149 <= ch <= 161:
        return "a" if ((ch - 149) // 4) % 2 == 0 else "b"
    return None


def channel_command(ch, width, secondary):
    """Firmware command for the channel: 'c6' (20 MHz) or 'c6,a' / 'c6,b' (40 MHz)."""
    width = str(width)
    if width == "20" or (width == "auto" and not secondary):
        return f"c{ch}"
    sec = secondary_for(ch, secondary)
    if sec is None:
        if ch <= 14:
            print(f"\nWARNING: channel {ch} can pair with {ch - 4} or {ch + 4} for 40 MHz, depending on the "
                  f"router. Pass --secondary above|below (see the router's 2.4 GHz settings). "
                  f"Listening at 20 MHz instead.", file=sys.stderr)
        else:
            print(f"\nWARNING: channel {ch} has no standard 40 MHz pair. Listening at 20 MHz instead.",
                  file=sys.stderr)
        return f"c{ch}"
    return f"c{ch},{sec}"


def find_wireshark(explicit):
    if explicit:
        return explicit
    w = shutil.which("wireshark")
    if w:
        return w
    for c in (r"C:\Program Files\Wireshark\Wireshark.exe",
              r"C:\Program Files (x86)\Wireshark\Wireshark.exe"):
        if os.path.exists(c):
            return c
    return None


# ---- MAC handling ----
def parse_mac_arg(s):
    """'aa:bb:cc:dd:ee:ff' or 'aa-bb-...=name' -> (6 raw bytes, name)."""
    mac, _, name = s.partition("=")
    h = mac.lower().replace(":", "").replace("-", "").replace(".", "")
    if len(h) != 12:
        raise argparse.ArgumentTypeError(f"bad MAC address: {mac}")
    return bytes.fromhex(h), (name or mac)


def fmt_mac(b):
    return b.hex(":")


def frame_addrs(data):
    """Address 1, 2 and 3 of an 802.11 frame (whichever are present)."""
    return [data[o:o + 6] for o in (4, 10, 16) if len(data) >= o + 6]


SEC_LABEL = {0: "20 MHz", 1: "40 MHz above", 2: "40 MHz below"}


class MacSearch:
    """
    While the firmware hops, count how many frames each listed MAC sends or receives on each
    channel and listening width. After at least `min_sweeps` full sweeps, and once every MAC has
    been seen (or the timeout has passed with at least one seen), pick what to lock on:
      - each MAC's channel = the channel where it had the most frames while listening at 20 MHz
        (2.4 GHz frames leak into neighbouring channels, so "first seen" can be off by 1-2)
      - lock channel = the channel shared by the most listed MACs; ties go to the MAC listed first
      - lock width (only when 40 MHz was also scanned): 20 MHz, unless "40 MHz above" or "below"
        caught clearly more frames from the listed MACs on that channel (at least WIDTH_MIN_RATIO x
        and WIDTH_MIN_EXTRA more than 20 MHz). Every setting gets the same listening time per sweep.
    """

    def __init__(self, macs, min_sweeps, timeout):
        self.macs = macs                          # list of (bytes, name), in the order given
        self.counts = {m: {} for m, _ in macs}    # mac -> {(channel, sec): frames}
        self.min_sweeps, self.timeout = min_sweeps, timeout
        self.sweeps = 0
        self.t0 = time.time()

    def on_frame(self, ch, data, sec=0):
        for a in set(frame_addrs(data)):
            if a in self.counts:
                c = self.counts[a]
                c[(ch, sec)] = c.get((ch, sec), 0) + 1

    def per_channel_20(self, mac):
        return {ch: n for (ch, sec), n in self.counts[mac].items() if sec == 0}

    def best_channel(self, mac):
        c = self.per_channel_20(mac) or {ch: n for (ch, _), n in self.counts[mac].items()}
        return max(c, key=c.get) if c else None

    # A 40 MHz setting also receives every 20 MHz frame on the main channel, so for a device that
    # really sends 40 MHz frames it catches MANY more frames than 20 MHz. Small differences are just
    # chance (each setting is only heard for dwell x sweeps, e.g. 0.5 s, and traffic is bursty).
    WIDTH_MIN_RATIO = 1.5      # 40 MHz must catch at least 1.5x the frames of 20 MHz ...
    WIDTH_MIN_EXTRA = 20       # ... and at least 20 frames more, otherwise stay at 20 MHz

    def width_totals(self, ch):
        tot = {0: 0, 1: 0, 2: 0}
        for c in self.counts.values():
            for (cc, sec), n in c.items():
                if cc == ch:
                    tot[sec] += n
        return tot

    def best_width(self, ch):
        """20 MHz unless a 40 MHz setting on `ch` caught clearly more frames from the listed MACs."""
        tot = self.width_totals(ch)
        sec = max((1, 2), key=lambda s: tot[s])
        if tot[sec] >= self.WIDTH_MIN_RATIO * tot[0] and tot[sec] - tot[0] >= self.WIDTH_MIN_EXTRA:
            return sec
        return 0

    def found(self):
        return [m for m, _ in self.macs if self.counts[m]]

    def ready(self, now):
        if self.sweeps < self.min_sweeps or not self.found():
            return False
        return len(self.found()) == len(self.macs) or now - self.t0 >= self.timeout

    def decide(self):
        votes, order = {}, []
        for m, _ in self.macs:
            ch = self.best_channel(m)
            if ch is None:
                continue
            votes[ch] = votes.get(ch, 0) + 1
            if ch not in order:
                order.append(ch)
        return max(order, key=lambda ch: (votes[ch], -order.index(ch)))

    def report(self, lock_ch, lock_sec=None):
        print("\n\nMAC search result:", file=sys.stderr)
        for m, name in self.macs:
            c = self.counts[m]
            if not c:
                print(f"  {name:<12} {fmt_mac(m)}  NOT SEEN", file=sys.stderr)
                continue
            top = sorted(self.per_channel_20(m).items(), key=lambda kv: -kv[1])[:3]
            seen = ", ".join(f"ch {ch}: {n}" for ch, n in top) or "-"
            note = "" if self.best_channel(m) == lock_ch else "   <- on another channel, not captured"
            print(f"  {name:<12} {fmt_mac(m)}  frames per channel at 20 MHz: {seen}{note}", file=sys.stderr)
            widths = {sec: n for (ch, sec), n in c.items() if ch == lock_ch}
            if len(widths) > 1 or any(widths):
                print(f"  {'':<12} {'':<17}  on ch {lock_ch}: " +
                      ", ".join(f"{SEC_LABEL[s]}: {widths.get(s, 0)}" for s in (0, 1, 2)), file=sys.stderr)
        width = f" ({SEC_LABEL[lock_sec]})" if lock_sec is not None else ""
        print(f"locking on channel {lock_ch}{width}\n", file=sys.stderr)

    def status(self):
        parts = []
        for m, name in self.macs:
            ch = self.best_channel(m)
            parts.append(f"{name} {'ch ' + str(ch) if ch else '-'}")
        return " | ".join(parts)


def stdin_keys():
    """Queue that receives a line each time Enter is pressed (read on a background thread)."""
    q = queue.Queue()

    def reader():
        for line in sys.stdin:
            q.put(line)

    threading.Thread(target=reader, daemon=True).start()
    return q


def load_stages_file(path):
    """One stage per line: 'name: what to do'. Blank lines and lines starting with # are ignored."""
    stages = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, _, instr = line.partition(":")
            stages.append((name.strip(), instr.strip()))
    if not stages:
        raise SystemExit(f"no stages in {path}")
    return stages


def fmt_time(t):
    return datetime.datetime.fromtimestamp(t).isoformat(sep=" ", timespec="milliseconds")


class Stages:
    """
    Guided recording. For each stage: print what to do, wait for Enter, record the start time,
    end it after `secs` seconds (or on Enter), record the end time and the frames written in
    between. Rows are written to the CSV as each stage ends, so Ctrl+C keeps finished stages.
    Times are PC clock times, the same clock the pcap timestamps are anchored to.
    """

    FIELDS = ["stage", "name", "start_time", "end_time", "duration_s", "frames",
              "first_frame", "last_frame", "ended", "wireshark_filter"]

    def __init__(self, stages, secs, csv_path, keys):
        self.stages, self.secs, self.keys = stages, secs, keys
        self.csv_path = csv_path
        self.f = open(csv_path, "w", newline="")
        self.w = csv.writer(self.f)
        self.w.writerow(self.FIELDS)
        self.f.flush()
        self.idx = 0
        self.running = False
        self.start = self.planned_end = None
        self.first_no = self.last_no = None
        self.frames = 0
        self.done = False
        self._prompt()

    def _pressed(self):
        hit = False
        while True:
            try:
                self.keys.get_nowait()
                hit = True
            except queue.Empty:
                return hit

    def _prompt(self):
        self._pressed()                       # ignore Enter presses made before this prompt
        name, instr = self.stages[self.idx]
        print(f"\n\n=== Stage {self.idx + 1}/{len(self.stages)}: {name} ===\n{instr}\n"
              f"Press Enter when ready to start ({self.secs:.0f} s). Press Enter during the stage to end it early.",
              file=sys.stderr)

    def tick(self, now):
        pressed = self._pressed()
        if not self.running:
            if pressed:
                self.running, self.start, self.frames = True, now, 0
                self.first_no = self.last_no = None
                self.planned_end = now + self.secs
                print(f"\nstage {self.idx + 1} started at {fmt_time(now)}", file=sys.stderr)
        elif pressed or now >= self.planned_end:
            self._finish(now, "complete" if now >= self.planned_end else "ended early (Enter)")

    def wants(self):
        """Frames are recorded only while a stage is running (decided by when they reach the PC,
        so it does not depend on the ESP32's timestamps being in step with the PC clock)."""
        return self.running

    def on_frame(self, frame_no):
        """frame_no = this frame's position in the pcap (Wireshark's frame.number)."""
        self.frames += 1
        if self.first_no is None:
            self.first_no = frame_no
        self.last_no = frame_no

    def _finish(self, now, how):
        end = min(now, self.planned_end)
        name = self.stages[self.idx][0]
        filt = (f"frame.number >= {self.first_no} && frame.number <= {self.last_no}"
                if self.frames else "(no frames)")
        self.w.writerow([self.idx + 1, name, fmt_time(self.start), fmt_time(end),
                         f"{end - self.start:.1f}", self.frames, self.first_no or "", self.last_no or "",
                         how, filt])
        self.f.flush()
        print(f"\a\nstage {self.idx + 1} ({name}) {how}: {end - self.start:.0f} s, {self.frames} frames",
              file=sys.stderr)
        self.running = False
        self.idx += 1
        if self.idx >= len(self.stages):
            self.done = True
            print(f"\nall stages done; times saved to {self.csv_path}", file=sys.stderr)
        else:
            self._prompt()

    def label(self, now):
        if self.done:
            return "stages done"
        n = f"stage {self.idx + 1}/{len(self.stages)} {self.stages[self.idx][0]}"
        if self.running:
            return f"{n} {max(self.planned_end - now, 0):4.0f} s left"
        return f"{n} waiting for Enter"

    def close(self, now):
        if self.running:
            self._finish(now, "interrupted (Ctrl+C)")
        self.f.close()


def main():
    ap = argparse.ArgumentParser(description="ESP32-C5 sniffer: serial -> pcap (and optional live Wireshark)")
    ap.add_argument("-p", "--port", required=True, help="serial port, e.g. COM5")
    ap.add_argument("-c", "--channel", type=int, help="channel to sniff (1-13, 36-177)")
    ap.add_argument("--width", choices=["auto", "20", "40"], default="auto",
                    help="listening width once on the channel (40 is needed to receive 40 MHz frames). "
                         "auto: the MAC search hops every channel at 20 MHz, then every 40 MHz pair, and "
                         "locks on the setting that caught the most frames from your MACs. "
                         "With -c, auto = 20 MHz unless --secondary is given")
    ap.add_argument("--secondary", choices=["above", "below"],
                    help="with --width 40 (or -c): which neighbouring channel the router uses for 40 MHz. "
                         "Only needed for 2.4 GHz channels 5-9; others are worked out automatically")
    ap.add_argument("--mac", type=parse_mac_arg, action="append", default=[], metavar="MAC[=NAME]",
                    help="device to capture (repeatable). Without -c, hop channels until found, then lock")
    ap.add_argument("--all", action="store_true", help="with --mac: write every frame on the channel, not only theirs")
    ap.add_argument("-o", "--out", metavar="NAME",
                    help="file name prefix; date and time are appended: NAME_YYYYmmdd_HHMMSS.pcap, "
                         "saved in the 'datasets' folder next to this script unless NAME includes a folder "
                         "(default prefix: capture)")
    ap.add_argument("-l", "--live", action="store_true", help="also stream into a live Wireshark window")
    ap.add_argument("--wireshark", help="path to Wireshark.exe if not in the default location")
    ap.add_argument("-d", "--duration", type=float, help="stop after N seconds of capture (search time not counted)")
    ap.add_argument("-b", "--baud", type=int, default=2000000,
                    help="must match SERIAL_BAUD when using a USB-UART port; ignored on native USB")
    ap.add_argument("--ts", choices=["rx", "cb"], default="rx",
                    help="timestamp source: radio receive time (default) or firmware callback time")
    g = ap.add_argument_group("MAC search (used when --mac is given without -c)")
    g.add_argument("--band", choices=list(BAND_CODE), default="both", help="bands to search")
    g.add_argument("--dwell", type=int, default=250, help="ms per channel while searching")
    g.add_argument("--sweeps", type=int, default=2, help="minimum full sweeps before deciding")
    g.add_argument("--timeout", type=float, default=60,
                   help="lock after this many seconds even if some MACs were not seen")
    s = ap.add_argument_group("guided stages")
    s.add_argument("--stages", action="store_true",
                   help="walk through the recording stages and save each stage's start/end time")
    s.add_argument("--stage-secs", type=float, default=60, help="length of each stage in seconds")
    s.add_argument("--stages-file", help="text file with one 'name: what to do' per line "
                                         "(default: DEFAULT_STAGES in this script)")
    args = ap.parse_args()
    if args.stages_file:
        args.stages = True
    if args.stages and args.duration:
        print("note: -d is ignored with --stages (capture ends after the last stage)", file=sys.stderr)

    try:
        import serial
    except ImportError:
        sys.exit("pyserial missing: pip install pyserial")

    # -o NAME -> <OUTPUT_DIR>/NAME_<YYYYmmdd_HHMMSS>.pcap (".pcap" optional); no -o -> capture_<time>.pcap.
    # If NAME includes a folder (e.g. -o D:\caps\run1), that folder is used instead of OUTPUT_DIR.
    stamp = time.strftime("%Y%m%d_%H%M%S")
    name = args.out or "capture"
    if name.lower().endswith(".pcap"):
        name = name[:-5]
    if not os.path.dirname(name):
        name = os.path.join(OUTPUT_DIR, name)
    out = f"{name}_{stamp}.pcap"
    if os.path.dirname(out):
        os.makedirs(os.path.dirname(out), exist_ok=True)

    ser = serial.Serial()
    ser.port, ser.baudrate, ser.timeout = args.port, args.baud, 0.05
    ser.dtr = ser.rts = False          # don't reset the board / enter the bootloader on open
    ser.open()
    ser.reset_input_buffer()
    time.sleep(0.3)

    try:
        run(ser, args, out)
    finally:
        ser.close()


def discard_backlog(ser, secs=1.0):
    """The ESP32 keeps capturing while nothing reads the port, so old frames are waiting in its
    buffer when the script starts. Read and throw them away before recording anything."""
    t_end = time.time() + secs
    n = 0
    while time.time() < t_end:
        n += len(ser.read(ser.in_waiting or 1))
    return n


def run(ser, args, out, keys=None):
    n = discard_backlog(ser)
    if n:
        print(f"discarded {n} bytes of old frames buffered on the ESP32", file=sys.stderr)
    stage_list = None
    if args.stages:
        stage_list = load_stages_file(args.stages_file) if args.stages_file else DEFAULT_STAGES
        keys = keys or stdin_keys()
    stages = None

    def send(cmd):
        ser.write((cmd + "\n").encode())

    targets = {m for m, _ in args.mac}
    search = None
    lock_ch = args.channel
    if args.mac and args.channel is None:
        search = MacSearch(args.mac, args.sweeps, args.timeout)
        send(f"h{args.dwell},{BAND_CODE[args.band]},{1 if args.width == 'auto' else 0}")
        print(f"searching for {len(args.mac)} MAC(s) on band {args.band}, {args.dwell} ms per channel"
              f"{' (every channel at 20 MHz, then every 40 MHz pair)' if args.width == 'auto' else ''}. "
              "Make the devices active (stream, browse) so they transmit.", file=sys.stderr)
    else:
        send("x")
        if lock_ch is not None:
            send(channel_command(lock_ch, args.width, args.secondary))

    pcap = ws = None

    def open_outputs():
        nonlocal pcap, ws, stages
        pcap = open(out, "wb")
        pcap.write(pcap_global_header())
        if args.live:
            path = find_wireshark(args.wireshark)
            if path:
                ws = subprocess.Popen([path, "-k", "-i", "-"], stdin=subprocess.PIPE)
                ws.stdin.write(pcap_global_header())
            else:
                print("Wireshark not found (use --wireshark PATH); writing the file only.", file=sys.stderr)
        what = "frames to/from the listed MACs" if targets and not args.all else "all frames"
        print(f"writing {what} to {out}  (Ctrl+C to stop)", file=sys.stderr)
        if stage_list:
            stages = Stages(stage_list, args.stage_secs, out[:-5] + "_stages.csv", keys)

    if search is None:
        open_outputs()

    parser, unwrap = Parser(), Unwrap32()
    written = filtered = 0
    esp = {"frames": 0, "drops": 0, "ch": 0}
    base = None
    clock = {"offset": None, "last_u": None, "back": 0, "max_delay": 0.0, "warned": False}
    prev = (0, 0, time.time())
    t_capture = last_print = time.time()

    try:
        while True:
            now = time.time()
            if stages is not None:
                stages.tick(now)
                if stages.done:
                    break
            elif search is None and args.duration and now - t_capture >= args.duration:
                break
            for fields, data in parser.feed(ser.read(ser.in_waiting or 1)):
                (_, typ, ch, rx_ts, cb_ts, orig_len, _, rssi, noise, _, _, _) = fields
                if typ == REC_TEXT:
                    print(f"\n[esp] {data.decode(errors='replace')}", file=sys.stderr)
                    continue
                if typ == REC_STATS:
                    if len(data) >= STATS.size:
                        f, d, _, c = STATS.unpack_from(data)
                        if base is None:
                            # The firmware counts since the board booted (including time when no
                            # script was reading, when everything is dropped). Count from now.
                            base = (f, d)
                        esp.update(frames=f - base[0], drops=d - base[1], ch=c)
                    continue
                if typ == REC_EVENT:
                    if search is not None and len(data) >= EVENT.size:
                        ev, _, sweeps, _ = EVENT.unpack_from(data)
                        if ev == EV_SWEEP_DONE:
                            search.sweeps = sweeps
                    continue

                # ---- a captured frame
                u = unwrap(rx_ts if args.ts == "rx" else cb_ts)
                arrival = time.time()
                # ---- align the ESP32 clock with the PC clock.
                # pcap time = device time + offset. A frame can only reach the PC *after* it was
                # captured, so arrival - device_time is the true offset plus that frame's delay.
                # The smallest value seen belongs to the least-delayed frame, i.e. the best offset.
                # (Anchoring on the first frame went wrong when that frame had sat in the ESP32's
                # buffer for minutes before the script started reading.)
                cand = arrival - u / 1e6
                if clock["offset"] is None or cand < clock["offset"]:
                    clock["offset"] = cand
                ts = u / 1e6 + clock["offset"]
                # ---- clock check: timestamps should only move forward, and frames should arrive promptly
                if clock["last_u"] is not None and u < clock["last_u"] - 1000:
                    clock["back"] += 1                 # timestamp went backwards by > 1 ms
                clock["last_u"] = u
                delay = arrival - ts
                clock["max_delay"] = max(clock["max_delay"], delay)
                if (delay > 2 or clock["back"]) and not clock["warned"]:
                    clock["warned"] = True
                    print(f"\nWARNING: ESP32 '{args.ts}' timestamps look wrong: a frame arrived {delay:.1f} s "
                          f"after its timestamp, {clock['back']} backward jumps. Frame timing in the pcap "
                          f"may be wrong; try --ts {'cb' if args.ts == 'rx' else 'rx'}.", file=sys.stderr)
                if search is not None:
                    search.on_frame(ch, data, fields[10] >> 4)   # high 4 bits of pkt_type = width
                    continue
                if lock_ch is not None and ch != lock_ch:
                    continue                           # still queued from before the lock
                if targets and not args.all and not (set(frame_addrs(data)) & targets):
                    filtered += 1
                    continue
                if stages is not None and not stages.wants():
                    continue                           # between stages: not recorded
                pkt = pcap_record(ts, radiotap(ch, rssi, noise), data, orig_len)
                pcap.write(pkt)
                written += 1
                if stages is not None:
                    stages.on_frame(written)           # written == this frame's number in Wireshark
                if ws:
                    try:
                        ws.stdin.write(pkt)
                    except OSError:
                        print("\nWireshark closed; still writing the file.", file=sys.stderr)
                        ws = None

            # ---- search finished?
            if search is not None and search.ready(now):
                lock_ch = search.decide()
                if args.width == "auto":
                    sec = search.best_width(lock_ch)
                    send(f"c{lock_ch}" + {0: "", 1: ",a", 2: ",b"}[sec])
                    search.report(lock_ch, sec)
                else:
                    send(channel_command(lock_ch, args.width, args.secondary))
                    search.report(lock_ch)
                search = None
                t_capture = time.time()
                open_outputs()

            if now - last_print >= 1.0:
                last_print = now
                pf, pd, pt = prev
                dt = max(now - pt, 1e-3)
                prev = (esp["frames"], esp["drops"], now)
                if search is not None:
                    line = (f"searching: ch {esp['ch']:>3} | sweep {search.sweeps}/{args.sweeps} | "
                            f"{search.status()}")
                else:
                    pcap.flush()
                    if ws:
                        try:
                            ws.stdin.flush()
                        except OSError:
                            ws = None
                    line = ((f"{stages.label(now)} | " if stages is not None else "") +
                            f"ch {esp['ch']:>3} | esp captured {(esp['frames'] - pf) / dt:6.0f}/s  "
                            f"dropped {(esp['drops'] - pd) / dt:4.0f}/s (total {esp['drops']}) | "
                            f"written {written}" + (f" | other devices skipped {filtered}" if targets else "") +
                            f" | skipped bytes {parser.bad}")
                if stages is not None and not stages.running:
                    line = None                        # waiting for Enter: the prompt is enough
                if line:
                    print("\r" + line + "   ", end="", file=sys.stderr, flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        if search is not None:
            send("x")
        if stages is not None:
            stages.close(time.time())
        if pcap:
            pcap.close()
        if ws:
            try:
                ws.stdin.close()
            except OSError:
                pass
        print(f"\ndone: {written} frames -> {out if pcap else '(nothing written)'} | "
              f"esp drops {esp['drops']} | skipped bytes {parser.bad}", file=sys.stderr)
        print(f"clock check ({args.ts} timestamps): frames reached the PC at most {clock['max_delay']:.3f} s "
              f"after their timestamp, {clock['back']} backward jumps", file=sys.stderr)


if __name__ == "__main__":
    main()
