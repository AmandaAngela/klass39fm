"""Search for a transmitter, then collect comparable fixed-channel recordings."""
import csv
import json
import secrets
from copy import copy
from datetime import datetime, timezone
from pathlib import Path

from device_features import measured_seconds


def settings(primary):
    yield None
    if primary + 4 <= 13:
        yield "above"
    if primary - 4 >= 1:
        yield "below"


def target_measurements(folder, mac, primary):
    tx = data = size = ht40 = retries = 0
    rx_data = rx_ht40 = 0
    with (folder / "camera_packets.csv").open(newline="", encoding="utf8") as f:
        for row in csv.DictReader(f):
            if int(row["channel"]) != primary:
                continue
            carries_data = row["frame_type"] == "2" and not (int(row["frame_subtype"]) & 4)
            is_ht40 = row["phy_sig_mode"] == "1" and row["phy_cwb"] == "1"
            if carries_data and row["addr1_ra"] == mac:
                rx_data += 1
                rx_ht40 += is_ht40
            if row["addr2_ta"] != mac:
                continue
            tx += 1
            if not carries_data:
                continue
            data += 1
            size += int(row["frame_length_bytes"])
            retries += int(row["retry"])
            ht40 += is_ht40
    seconds = measured_seconds(folder)
    return dict(target_tx_frames=tx, target_tx_data_frames=data, target_tx_frame_bytes=size,
                target_tx_retry_frames=retries, target_tx_ht40_data_frames=ht40,
                target_rx_data_frames=rx_data, target_rx_ht40_data_frames=rx_ht40,
                measured_seconds=seconds, target_tx_data_frames_per_s=round(data / seconds, 3),
                target_tx_frame_bytes_per_s=round(size / seconds, 3))


def survey(args, record):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    root = Path(args.output) / f"{stamp}_width_survey_{secrets.token_hex(4)}"
    root.mkdir(parents=True, exist_ok=False)
    report = dict(target_mac=args.camera, result="in_progress", primary=None, runs=[])
    probe_time = args.probe_seconds or 2
    compare_time = args.duration or 60
    print(f"Width survey {root.resolve()}", flush=True)

    def save():
        temp = root / "survey.tmp"
        temp.write_text(json.dumps(report, indent=2) + "\n", encoding="utf8")
        temp.replace(root / "survey.json")

    def capture(phase, primary, secondary, seconds):
        run = copy(args)
        run.channel, run.secondary, run.duration = primary, secondary, seconds
        name = f"{phase}_ch{primary}_{secondary or '20MHz'}_{secrets.token_hex(4)}"
        entry = dict(phase=phase, primary=primary, secondary=secondary or "none",
                     requested_seconds=seconds, folder=name, result="in_progress")
        report["runs"].append(entry)
        save()
        folder = root / name
        code = record(run, folder=folder)
        meta = json.loads((folder / "session.json").read_text(encoding="utf8"))
        entry.update(result=meta["result"], quality_findings=meta.get("quality_findings", {}))
        if meta.get("operator_stopped"):
            raise KeyboardInterrupt
        if code == 1:
            entry["error"] = meta.get("error", f"Incomplete recording in {name}")
            status = meta.get("latest_firmware_status") or {}
            if status.get("tune_errors") and not status["locked"]:
                entry["result"] = "tune_failed"
                save()
                return 0
            raise RuntimeError(entry["error"])
        entry.update(target_measurements(folder, args.camera, primary))
        print(f"Channel {primary} ({secondary or '20 MHz'}): {entry['target_tx_frames']} "
              f"target TX frames, {entry['target_tx_ht40_data_frames']} HT40 data", flush=True)
        save()
        return entry["target_tx_frames"]

    try:
        # A target visible only on a wide pair must be discoverable from a cold start.
        primaries = [args.channel] if args.channel else range(1, 14)
        for primary in primaries:
            for secondary in settings(primary):
                if capture("probe", primary, secondary, probe_time):
                    report["primary"] = primary
                    break
            if report["primary"] is not None:
                break
        if report["primary"] is None:
            report["result"] = "target_not_observed"
            return 2

        primary = report["primary"]
        for secondary in settings(primary):
            capture("compare", primary, secondary, compare_time)
        comparisons = [r for r in report["runs"] if r["phase"] == "compare"]
        report["result"] = "completed"
        report["target_tx_ht40_observed_in_comparison"] = any(
            r.get("target_tx_ht40_data_frames", 0) for r in comparisons)
        # Empty off-channel probes are expected. Preserve their original findings.
        review = any(k != "empty_capture" or r["phase"] == "compare"
                     for r in report["runs"] for k in r["quality_findings"])
        if any(r["result"] == "tune_failed" for r in report["runs"]):
            review = True
        if not any(r.get("target_tx_data_frames", 0) for r in comparisons):
            review = True
        report["quality_review_required"] = review
        return 2 if review else 0
    except KeyboardInterrupt:
        report["result"] = "interrupted"
        return 1
    except (OSError, RuntimeError, ValueError) as exc:
        report.update(result="incomplete", error=str(exc))
        return 1
    finally:
        save()
        print(f"Survey {report['result']}. Results in {root / 'survey.json'}", flush=True)
