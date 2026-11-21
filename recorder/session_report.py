"""Write a per-session Stage 1 README without changing captured observations."""
import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from audit_recording import audit


def ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def write_session_readme(folder, context=None):
    folder = Path(folder)
    context_file = folder / "recording_context.json"
    saved_context = (json.loads(context_file.read_text(encoding="utf-8-sig"))
                     if context_file.exists() else {})
    if context:
        saved_context.update(context)
        context_file.write_text(json.dumps(saved_context, indent=2) + "\n", encoding="utf8")
    context = saved_context
    meta = json.loads((folder / "session.json").read_text(encoding="utf-8-sig"))
    status = meta.get("latest_firmware_status") or {}
    target = meta.get("camera_mac")
    types, modes, widths = Counter(), Counter(), Counter()
    total = tx = rx = data_tx = data_rx = data_bytes = retries = 0
    with (folder / "all_wifi_packets.csv").open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        columns = reader.fieldnames or []
        for row in reader:
            total += 1
            types[row["frame_type"]] += 1
            if not target:
                continue
            outgoing = row["addr2_ta"] == target
            incoming = row["addr1_ra"] == target
            tx += outgoing
            rx += incoming
            if row["frame_type"] == "2" and not (int(row["frame_subtype"]) & 4):
                data_rx += incoming
                if outgoing:
                    data_tx += 1
                    data_bytes += int(row["frame_length_bytes"])
                    retries += int(row["retry"])
                    modes[row.get("phy_sig_mode", "")] += 1
                    widths[row.get("phy_cwb", "")] += 1
    begin = end = None
    with (folder / "status.jsonl").open(encoding="utf-8-sig") as stream:
        for line in stream:
            entry = json.loads(line)
            if entry["kind"] == "B":
                begin = entry["uptime_us"]
            elif entry["kind"] == "E":
                end = entry["uptime_us"]
    seconds = (end - begin) / 1e6 if begin is not None and end is not None else None
    if meta.get("result") == "completed":
        try:
            replay = "Passed: raw measurements, CSV/status and counters reconcile."
            audit(folder)
        except (OSError, ValueError, KeyError, StopIteration) as exc:
            replay = f"FAILED: {exc}. Review before using this session."
    else:
        replay = "Not a completed-session pass; inspect the incomplete boundaries/error."
    discovery = meta.get("collection_discovery") or context.get("collection_discovery") or {}
    requested = meta.get("requested_mode", -1)
    mode = "auto" if requested == 0 else "scan" if requested == -1 else requested
    width = meta.get("requested_width_mhz", 20)
    secondary = meta.get("requested_secondary", "none")
    command = ["python $rec", "--port " + ps_quote(meta.get("port", "PORT")),
               "--baud " + str(meta.get("baud", 921600)),
               "--state " + ps_quote(meta.get("camera_state", "unknown"))]
    if target:
        command.append("--camera " + ps_quote(target))
    if discovery:
        channel = discovery.get("channel", 0)
        command.extend(["--channel " + str("auto" if not channel else channel),
                        "--secondary auto", "--probe-seconds " + str(discovery["probe_seconds"])])
    else:
        command.append("--channel " + str(mode))
        if secondary != "none":
            command.append("--secondary " + secondary)
    duration = discovery.get("comparison_seconds", meta.get("requested_seconds"))
    if duration is not None:
        command.append("--duration " + str(duration))
    command.append("--output " + ps_quote(context.get("recording_output_root",
        meta.get("recording_output_root", str(folder.parent)))))
    command.append("--notes " + ps_quote(meta.get("notes", "")))
    labels = meta.get("device_labels", [])
    label_commands = ""
    if labels:
        label_commands = ("$labelsPath = Join-Path $env:TEMP 'wifi_session_labels.json'\n"
                          + ps_quote(json.dumps(labels)) + " | Set-Content -LiteralPath $labelsPath -Encoding utf8\n")
        command.append("--labels $labelsPath")
    setup = context.get("setup", "AP/SSID, topology, distance, placement, obstructions and workload settings were not supplied to this report. Do not infer them from receiver channel alone.")
    basis = context.get("identity_basis", json.dumps(labels) if labels else "No device identity/activity labels supplied; no class inferred.")
    findings = json.dumps(meta.get("quality_findings", {}), sort_keys=True)
    measured = f"{seconds:.6f} s" if seconds is not None else "Unavailable: BEGIN/END incomplete"
    rate = f"{data_tx / seconds:.3f}" if seconds and seconds > 0 else "unavailable"
    suggestions = []
    if meta.get('result') != 'completed' or meta.get('quality_findings') or replay.startswith('FAILED'):
        suggestions.append('Acquisition/replay findings are present: review counters and boundaries before selecting usable intervals; do not interpolate away missing traffic.')
    if target and not data_tx:
        suggestions.append('No attributable outgoing data was decoded. For a busy workload, investigate receiver visibility; for confirmed idle/off, retain that state and analyse sparse coverage separately.')
    if retries:
        suggestions.append(f'{retries} outgoing data frames carry retry flags. Compare retry-inclusive and documented retry-aware features in derived copies; retain raw retries.')
    if width == 40 and not widths.get('1'):
        suggestions.append('This 40 MHz receiver run decoded no target outgoing data marked 40 MHz. Do not relabel its frames as wide just because of the receiver setting.')
    if total > tx:
        suggestions.append('Other transmitters contribute to the channel CSV. Build target-originated features using addr2_ta; do not assign the target class to every channel row.')
    if len(columns) != 47:
        suggestions.append(f'This archive has {len(columns)} columns. Select a shared named feature set and record unavailable fields when combining schemas.')
    stage2 = '\n'.join('- ' + s for s in suggestions) or '- No specific acquisition warning was identified by these checks; inspect coverage and setup before selecting features.'
    text = f"""# Recording {meta.get('token', 0):08x}: {meta.get('camera_state', 'unknown')}

## 1. Summary of this recording

Saved Stage 1 Wi-Fi observations for this session only. Result: **{meta.get('result', 'unknown')}**. Opened (UTC): {meta.get('opened_utc', 'unknown')}. Target MAC: `{target or 'none; untargeted'}`. Activity setting: `{meta.get('camera_state', 'unknown')}`. Labels are operator annotations, not classifier output.

{basis}

## 2. Files and code used

| File in this folder | Meaning |
| --- | --- |
| `all_wifi_packets.csv` | All decoded channel observations, including other devices. |
| `camera_packets.csv` | Immediate receiver/transmitter target matches; historical filename for any device class. |
| `raw_serial.bin` | Exact exported serial measurement stream for replay; not full Wi-Fi frame bodies. |
| `status.jsonl` | BEGIN/status/END, tuning/lock, counters and firmware identity. |
| `session.json` | Settings, notes, labels, corrections and acquisition outcome. |
| `README.md` | Explanation of this individual recording. |
| `recording_context.json` (if present) | Locally supplied setup/identity/review context, retained when regenerating this README; not radio measurements. |
| `traffic_check.json` (if present) | Per-column target availability, applicable-field failures and minimum-traffic screening thresholds; does not prove RF completeness. |

Repository code used: `main/main.c` configures Wi-Fi and commands; `main/capture.[ch]` parses headers/RX metadata and queues records; `main/transport.c` delivers them. Under `recorder/`, `record_wifi.py` saves data, `protocol.py` decodes/derives fields, `width_survey.py` performs automatic comparisons, `audit_recording.py` replays outputs and `session_report.py` writes this report. Separate descriptive feature analysis uses `device_features.py`; no classifier is applied.

## 3. Steps to replicate collection

Run from the repository root with Python containing pyserial and firmware built for the identified chip. Original receiver target: `{status.get('target', 'unknown')}`; IDF: `{status.get('idf', 'unknown')}`; firmware SHA: `{status.get('firmware_sha256', 'unknown')}`. Port names and addresses must be checked again. A rebuild need not reproduce the original binary byte for byte.

```powershell
python -m serial.tools.list_ports -v
$rec = 'recorder/record_wifi.py'
{label_commands}{' '.join(command)}
python recorder/audit_recording.py {ps_quote(str(folder))}
```

Discovery provenance: `{json.dumps(discovery) if discovery else 'Not recorded as a width-survey child; command above repeats the recorded mode.'}`. Normal new dataset collections start with `--channel auto --secondary auto`. Automatic discovery finds supported receiver settings, then fixed comparisons preserve time coverage. Retrospective direct-mode commands alone do not replace this normal survey procedure. The audit command checks the saved session here; use the new emitted folder after a repeat. Reuse confirmed operator activity, and recheck changed MACs.

## 4. Setup, data collected, processing and outcome

{setup}

Receiver request: channel/mode `{mode}`, width **{width} MHz**, secondary `{secondary}`. Final channel `{status.get('channel', 'unknown')}`, lock `{status.get('locked', 'unknown')}`, driver primary `{status.get('reported_primary', 'not exported for this mode')}`, secondary `{status.get('reported_secondary', 'not exported for this mode')}`. These are receiver settings; actual decoded width is a separate per-frame field. Requested duration: {meta.get('requested_seconds', 'unspecified')} s; measured BEGIN-to-END duration: **{measured}**.

| Observed measurement | Value |
| --- | ---: |
| All decoded channel observations | {total} |
| Management / data / control observations | {types['0']} / {types['2']} / {types['1']} |
| Target-address matches (host counter) | {meta.get('host', {}).get('camera_rows', 0)} |
| Target outgoing / incoming data frames | {data_tx} / {data_rx} |
| Target outgoing data frames per measured second | {rate} |
| Target outgoing data-frame bytes, including retries/overhead | {data_bytes} |
| Retry-marked outgoing data frames | {retries} |

Outgoing data PHY modes (0 legacy, 1 HT, 2 HE, 3 VHT; empty unavailable): `{dict(modes)}`. Outgoing data widths (0 = 20 MHz, 1 = 40 MHz; empty unavailable): `{dict(widths)}`. A wide receiver session can contain only 20 MHz frames. Beacons are management subtype 8.

CSV has **{len(columns)} columns**. MAC-header information includes frame control, type/subtype, DS/retry, available addresses, sequence/fragment and QoS TID. Driver metadata supplies receive time, RSSI/noise, frame length and applicable PHY fields; C5 additionally exports raw signal/format metadata and selected derived HE/coding fields. Host bookkeeping supplies batch/observation IDs and receipt time. Host derives original source/destination from DS/address fields; RSSI belongs to the immediate transmitter, not a forwarded original source. Missing fields are not measured zeros. No frame-body bytes, FCS value or CSI are exported. Frame-byte rates are not application bitrate.

The driver delivers callbacks; firmware validates available headers/RX state, queues selected measurements and exports CRC-protected batches. The host preserves reads, decodes batches, filters the target CSV, derives header/PHY fields and records counters. Raw rows, retries and timestamps are preserved; no smoothing, deduplication or model classification is performed. Raw 32-bit Wi-Fi timestamps can wrap. Source/curation metadata: `{json.dumps(meta.get('curation', {}))}`. Existing label corrections remain in `session.json` history.

Replay: **{replay}** Acquisition findings: `{findings}`. Error, if any: `{meta.get('error', 'none')}`. A passing replay checks saved bytes/exports, not RF transmissions never delivered by the driver. {context.get('review', 'Review operator setup/identity and acquisition findings before treating this as a labelled training sample; this README does not automatically promote data.')}

Original operator notes: {meta.get('notes', 'none')}

{context.get('additional_findings', '')}

## 5. Suggestions/recommendations for Stage 2

{stage2}

Preserve these originals. Use attributable outgoing data and target-address matches deliberately; router-originated matches are not target transmissions. Handle missing PHY values and timestamp wrap explicitly. Keep discovery, incomplete attempts and fixed comparisons separate; do not encode an invisible busy device as a quiet negative. Document any retry-aware/windowed derived view. Keep all sessions, receiver widths and changed MACs of the same physical device/experiment together in evaluation. Use common named features or a documented schema migration across 23/31/47-column archives. Record missing setup facts on future runs. These are preprocessing proposals; no classifier or cleaning transform was run here.
"""
    (folder / "README.md").write_text(text, encoding="utf8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("--context", type=Path, help="Optional local JSON with setup, identity_basis, review and additional_findings")
    args = parser.parse_args()
    write_session_readme(args.folder, json.loads(args.context.read_text(encoding="utf-8-sig")) if args.context else None)
