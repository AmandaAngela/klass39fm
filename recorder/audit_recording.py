"""Replay a completed WFS2 raw archive and compare its saved CSV and status rows."""
import argparse
import csv
import json
import sys
from collections import Counter
from contextlib import ExitStack
from pathlib import Path

from protocol import Decoder, KNOWN_FIELD_SETS, rows, status_fields


def audit(folder):
    meta = json.loads((folder / "session.json").read_text(encoding="utf8"))
    totals = Counter()
    decoder = Decoder()
    with ExitStack() as files:
        def reading(name):
            return files.enter_context((folder / name).open(encoding="utf8", newline=""))

        raw = files.enter_context((folder / "raw_serial.bin").open("rb"))
        all_rows = csv.DictReader(reading("all_wifi_packets.csv"))
        camera_rows = csv.DictReader(reading("camera_packets.csv"))
        statuses = reading("status.jsonl")
        # Either schema is valid: version-2 archives predate the PHY columns.
        columns = tuple(all_rows.fieldnames or ())
        if columns not in KNOWN_FIELD_SETS or tuple(camera_rows.fieldnames or ()) != columns:
            raise ValueError("CSV schema mismatch")
        begin = end = False
        last = None
        while True:
            chunk = raw.read(65536)
            for kind, token, seq, payload in decoder.feed(chunk, final=not chunk):
                if token != meta["token"]:
                    continue
                if kind != b"P":
                    saved = json.loads(next(statuses, "{}"))
                    last = status_fields(payload)
                    if (saved.get("kind") != kind.decode() or saved.get("wire_seq") != seq
                            or any(saved.get(k) != v for k, v in last.items())):
                        raise ValueError(f"Status mismatch at wire frame {seq}")
                    begin |= kind == b"B"
                    end |= kind == b"E"
                    continue
                for fields in rows("", seq, payload):
                    actual = next(all_rows, None)
                    # Compare only the columns this archive carries, so a version-2
                    # CSV is not failed for lacking the PHY fields.
                    if actual is None or any(actual[k] != str(fields.get(k, ""))
                                             for k in columns if k != "host_utc"):
                        raise ValueError(f"Observation mismatch at ID {fields['observation_id']}")
                    totals["rows"] += 1
                    if meta["camera_mac"] in (fields["addr1_ra"], fields["addr2_ta"]):
                        if next(camera_rows, None) != actual:
                            raise ValueError(f"Camera CSV mismatch at ID {fields['observation_id']}")
                        totals["camera_rows"] += 1
            if not chunk:
                break
        if any(next(stream, None) is not None for stream in (all_rows, camera_rows, statuses)):
            raise ValueError("Decoded files contain additional rows")
        if not (begin and end and meta["result"] == "completed"):
            raise ValueError("Session boundaries incomplete")
        if last != meta["latest_firmware_status"]:
            raise ValueError("Final status differs from session metadata")
        if totals["rows"] != meta["host"]["rows"] or totals["camera_rows"] != meta["host"]["camera_rows"]:
            raise ValueError("Row totals differ from session metadata")
        if last["eligible"] != last["sent"] + last["overflow"] + last["tx_lost"]:
            raise ValueError("Final firmware counters do not reconcile")
        if last["sent"] != totals["rows"]:
            raise ValueError("Firmware sent count differs from CSV rows")
    return dict(rows=totals["rows"], camera_rows=totals["camera_rows"], decoder=dict(decoder.errors),
                overflow=last["overflow"], tx_lost=last["tx_lost"],
                quality_review_required=meta.get("quality_review_required"))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("folder", type=Path)
    args = p.parse_args()
    try:
        print(json.dumps(audit(args.folder), indent=2))
    except (OSError, ValueError, KeyError) as exc:
        sys.exit(f"Audit failed: {exc}")
