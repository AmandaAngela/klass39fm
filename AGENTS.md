# Wi-Fi recorder working guide

## Purpose and experiment inputs

Collect reproducible passive Wi-Fi observations for camera/non-camera research. Read `CAPSTONE_CONTEXT.md` for the research objective and `README.md` for the recorder interface. Prefer measurements that can generalise across device models.

Obtain device identity, active Wi-Fi MAC, connected band, activity and desired duration from the current chat or an ignored local experiment record. Reuse facts already supplied by the operator. Ask only for missing information needed to label or perform the experiment. MAC addresses can change when a device joins a different network or uses private addressing.

Keep real MAC addresses, network names, serial numbers, personal filesystem paths and previous experiment results in local data. This guide deliberately uses variables. Device addresses and channels from an earlier chat are observations to recheck. New devices are supported. There is no fixed device allowlist.

A class label identifies the physical device. An activity label identifies its state during a recording. An idle camera retains the camera class. A purifier's activity is unspecified until the operator describes it. Give a device a non-camera label using confirmed identity rather than its observed traffic pattern.

## Receiver and capture capabilities

The current firmware targets ESP32-S3 with ESP-IDF v6.1. It listens passively to supported 2.4 GHz 802.11b/g/n transmissions using a single spatial stream. The configured country plan and channels are in `main/main.c`. The current implementation uses channels 1-13. Match the operating channel plan when changing environments.

The firmware receives management, data and control callbacks. It exports selected per-frame measurements in 45-byte records. Current CSV exports have 31 columns describing timestamps, frame length, addresses, type/subtype, sequence and retry information, QoS TID, RSSI, noise floor and PHY metadata.

- `raw_serial.bin` preserves bytes exported by this firmware. Its observations contain selected measurements. Wi-Fi frame bodies and CSI require a separate capture-format implementation.
- More callback fields and frame bytes may help later feature discovery. Their omission reflects the present capture design. It does not establish that they lack value. Any addition needs protocol compatibility, capture-loss checks and host replay support.
- A 2x2-capable transmitter can emit single-stream frames the receiver decodes. Actual multi-stream transmissions and unsupported PHY modes may expose only limited driver information or be rejected by the parser. Wi-Fi 6 activity can include compatible legacy control frames even when HE data is unavailable.
- Other bands, channel-hopping intervals, radio reception failures, parser exclusions and queue/transport losses all affect visibility. Application counters cannot count transmissions the driver never delivered.
- Missing decoded data from a busy device is a visibility finding. Check band, active MAC, channel, distance, decoding mode and recorded errors before interpreting its behaviour.

## Local shell and tool setup

Run commands from the repository root. Use an activated ESP-IDF v6.1 environment for building. Locate the installed SDK from the local environment or installation inventory and activate its export script. Keep SDK paths and tool paths in that shell's environment. Store machine-specific activation details locally.

For recording, use a Python environment containing `pyserial`. Verify its interpreter instead of assuming that `python` resolves to an installed interpreter. A Windows application alias may resolve to the Store launcher.

```powershell
python --version
python -m serial.tools.list_ports -v
```

The tested S3 transport is native USB Serial/JTAG. On targets using the UART fallback, firmware transport is 921600 baud and the recorder needs `--baud 921600`. Native USB line baud is nominal. Enumerate ports again after resets or reconnects. Close a competing monitor before opening the receiver.

## Build and flash

Use the receiver port discovered in the current environment as `$port`. Identify the chip before selecting a target or flashing it.

```powershell
python -m esptool --port $port chip-id
idf.py --version
```

For a fresh ESP32-S3 checkout, select the target once. For an existing configured checkout, preserve its configuration unless the task calls for changing it.

```powershell
idf.py set-target esp32s3
idf.py build
idf.py -p $port flash
```

After flashing, check that the recorder receives BEGIN, status and END messages. Compare the reported target and firmware SHA against the local build. Successful flash verification alone does not validate radio reception at a requested width.

For an authorised build/flash/debug task, carry the work through boot verification and recoverable failures. Keep unrelated source edits and existing recordings intact. A new firmware schema must preserve supported old archives or document the migration.

## Recording commands and labels

Set these paths in the current shell.

```powershell
$rec = 'esp32_camera_recorder/esp32_camera_recorder/record_wifi.py'
$audit = 'esp32_camera_recorder/esp32_camera_recorder/audit_recording.py'
$features = 'esp32_camera_recorder/esp32_camera_recorder/device_features.py'
```

Set `$targetMac`, `$port`, `$state`, `$deviceClass`, `$deviceAlias`, `$activity` and `$groupPrefix` from the current experiment. The automatic survey supplies the primary channel. A camera state can be `streaming`, `idle`, `off`, `motion`, `motion-triggered`, `background` or `unknown`. For non-camera devices use `--state unknown` and supply their actual class/activity through labels. `--camera` is the existing CLI name for any target MAC, including a non-camera device.

Save label inputs under an ignored recording directory. This example explicitly serialises a JSON array, including when there is only one device.

```powershell
New-Item -ItemType Directory -Force 'recordings/labels' | Out-Null
$labelsPath = Join-Path 'recordings/labels' (([guid]::NewGuid().ToString()) + '.json')
$labels = @(@{
    mac = $targetMac
    alias = $deviceAlias
    device_class = $deviceClass
    activity = $activity
    start_s = 0
    end_s = $null
})
ConvertTo-Json -InputObject $labels -Depth 4 | Set-Content -LiteralPath $labelsPath -Encoding utf8
```

Use `camera` or `non-camera` for the binary class and a descriptive alias for the device type. Label interval offsets are seconds from each session's BEGIN. For sequential sessions, record state changes and update labels for the session where they occurred. Preserve the previous label and the operator's correction basis when revising a completed session's metadata.

### Always start recording with automatic discovery at both widths

For every new recording run or repeat, use both `--channel auto` and `--secondary auto`. This applies to camera and non-camera targets, including when a primary channel was known in an earlier run. Supply the target MAC from the current experiment and let the recorder search the supported 20 MHz channels and legal 40 MHz pairs.

```powershell
python $rec --port $port --camera $targetMac --state $state --channel auto --secondary auto --probe-seconds 2 --duration 90 --labels $labelsPath --output recordings/discovery
```

The survey produces nested search/comparison folders and selects the first setting where target transmission is detected. Review that selection using attributable traffic and, when available, the connected network's channel information. One probe request or an isolated adjacent-channel observation is insufficient evidence for an application-traffic channel. Increase `--probe-seconds` for a quiet target. Investigate a weak or missing lock and retry automatic discovery as appropriate.

After discovery, the helper holds the selected primary while recording 20 MHz and each valid 40 MHz setting. This fixed measurement phase preserves timing coverage. Every requested repeat starts a fresh automatic survey. Channel reacquisition during an already running fixed comparison is outside the current helper's behaviour.

Keep the survey under `recordings/discovery`. Its probe phase supplies channel evidence. Promote only reviewed fixed-channel comparison sessions into the organised dataset.

### Collect each receiver setting

The automatic command above records one 90-second session at 20 MHz and at every valid 40 MHz setting on the discovered primary. `--duration` applies separately to each comparison. Follow an explicit operator request for a different duration. Keep activity and placement consistent across the sequential runs. Capture different primary channels sequentially with one receiver.

`$groupPrefix` describes the destination class and activity, such as `camera_streaming`, `camera_idle` or `negative_phone`. Use a stable lowercase device-type slug for non-camera groups. After reviewing a survey, place its completed comparison sessions directly under `dataset/<groupPrefix>_20mhz` or `dataset/<groupPrefix>_40mhz`, followed by the timestamped session folder. Retain the above/below distinction in the metadata and manifest. Preserve discovery logs under the survey source path.

Check the exit code and session quality after each command before continuing. Exit 0 means completed without flagged acquisition findings, 1 means incomplete, and 2 means completed with findings requiring review. A quiet device can legitimately have very little traffic. State this explicitly in the review.

Above means primary + 4 channel numbers. Below means primary - 4. The receiver listens to that pair together. Driver readback in `status.jsonl` must confirm the requested primary/secondary and lock. A frame's actual width is `phy_cwb`, interpreted alongside `phy_sig_mode`. A wide receiver setting can still deliver 20 MHz frames. Use target HT data with `phy_cwb=1` as evidence that HT40 frames were decoded.

Inform the operator when an activity-dependent capture finishes so they can stop the workload. Monitor an authorised recording until it completes, fails with a diagnosed cause, or the operator stops it. Preserve interrupted attempts with their actual status and retry recoverable failures.

## Folder layout and file meanings

```text
dataset/
  camera_streaming_20mhz/<timestamp>_streaming_<session>/
  camera_streaming_40mhz/<timestamp>_streaming_<session>/
  camera_idle_20mhz/<timestamp>_idle_<session>/
  camera_idle_40mhz/<timestamp>_idle_<session>/
  negative_<device-type>_20mhz/<timestamp>_unknown_<session>/
  negative_<device-type>_40mhz/<timestamp>_unknown_<session>/
  manifest.csv
recordings/
  discovery/
  diagnostics/
  labels/
  collection_logs/
finaliser/
  <same class/activity/width groups>/<timestamped session>/
  manifest.csv
  session_features.csv
  excluded.csv
  review.json
```

Each session preserves all five recorder outputs.

| File | Meaning |
| --- | --- |
| `all_wifi_packets.csv` | All decoded observations on the receiver channel, including other devices |
| `camera_packets.csv` | Target MAC in immediate receiver or transmitter address, for either device class |
| `raw_serial.bin` | Exact exported firmware stream used for replay |
| `status.jsonl` | Boundaries, receiver settings, counters and firmware identity |
| `session.json` | Target, activity labels, notes, host counters and result |

Select training input using `target_packets_csv` and device-class labels in the manifest. The full channel CSV can contain multiple classes. Use `addr2_ta` for attributable outgoing transmissions. Received RSSI belongs to the actual transmitter. Short ACK frames have no transmitter address.

Preserve raw rows, retry transmissions, repeated timestamps and identifiers. ESP timestamps are raw 32-bit microseconds and wrap after about 71.6 minutes. Host timestamps mark batch receipt. Derive timing with documented wrap handling. Frame length includes FCS and Wi-Fi overhead. Throughput estimates based on these lengths include retries.

Keep original archived schemas and capture configurations identifiable. Older 23-column recordings lack eight PHY fields. Some 31-column recordings used firmware with control capture disabled. Record those differences in the manifest. Empty or absent values need an explicit treatment in feature extraction.

## Review and feature commands

Set `$sessionFolder` to the actual completed session path emitted by the recorder.

```powershell
python $audit $sessionFolder
python $features $sessionFolder --mac $targetMac --measured-duration --json
python $features $sessionFolder --mac $targetMac --burst-windows --window-ms 100 --burst-gap-ms 10
```

Replay compares decoded measurements, target filtering and status against raw bytes. Also review the session's quality findings, BEGIN/END, tuning readback, queue overflow, transport loss, CRC failures, missing identifiers and timestamp anomalies. A passing replay can still report acquisition loss. Retain source data for diagnosis.

The feature script's default summary denominator can use requested duration or a fallback. Prefer `--measured-duration`. Burst windows start at the first observed frame and stop at the last observed frame's window. Their silent leading/trailing coverage differs from complete BEGIN-to-END coverage. Keep that distinction in derived datasets.

## Finalisation and model suitability

The operator has chosen to exclude the earlier PC YouTube samples with largely undecoded data traffic from the current training collection. This is a visibility-based decision about those recordings. A newly verified PC or phone capture can provide a useful negative, particularly during an upload or video call.

| Evidence | Use |
| --- | --- |
| Confirmed camera streaming with decoded data | Active-camera positive |
| Confirmed camera idle with sparse observations | Camera label with separate idle-performance analysis |
| Confirmed non-camera device with decoded traffic | Negative for its documented activity |
| Busy target with mostly control frames and missing data | Control-feature research or visibility diagnosis. Review suitability for data-frame features |
| Only discovery messages, absent target, or channel sweep | Discovery/diagnosis |
| Incomplete or quality-flagged recording | Review, document and retry as appropriate |

Promote completed, labelled, fixed-channel sessions after replay and acquisition review. An observed wide setting also requires matching driver readback. Confirm target traffic and common feature definitions. Sparse observations alone do not invalidate an accurately labelled idle sample.

Copy verified sessions into `finaliser` under direct group/session paths. Deduplicate source copies using session identity and raw-file hashes. Verify copied bytes and replay again. Keep source paths, class, activity, primary, receiver width, secondary, duration, schema, quality findings and target packet path in the manifest. Record excluded sessions and reasons. New sessions are appended without silently removing earlier reviewed sessions or changing operator labels.

Local one-off curation scripts may encode an earlier inventory, fixed devices or a fresh-output assumption. Inspect them before reuse. The recorder and audit CLI commands above are maintained source entry points. There is currently no general incremental finaliser CLI. Perform and verify the documented curation steps or implement a reusable helper when the task requires one.

Use the same preprocessing, feature order, window lengths and fitted transforms at training and inference. Keep all windows from a session in one evaluation partition. Hold out physical devices when evaluating generalisation. Device identity, MAC, channel, receiver width, network peer and RSSI can expose collection conditions. Assess those dependencies rather than treating a high score on a small set of known devices as evidence of general camera detection.

More bytes or fields do not automatically improve a model. Full frame bytes would preserve additional headers and future feature choices, while protected frame bodies can remain encrypted. Propose schema extensions with measured transport/memory impact and backward-compatible replay. Record receiver limitations as limitations, with useful control observations retained when relevant.

## Source changes and Git hygiene

- Commit source code, public instructions, generic configuration templates and synthetic tests.
- Keep captures, manifests, analysis reports, device labels, archive files and machine-specific context inside ignored local output directories.
- `dataset/`, `recordings/`, `finaliser/` and `finaliser.building/` are local outputs. `AGENTS.md` is intended to be tracked.
- Use variables or placeholders in published examples. Keep real device identifiers, SSIDs, experiment notes, tokens and personal paths out of tracked documents.
- Check both untracked files and the staged diff before committing. Ignore rules do not untrack files already in Git. Avoid force-adding ignored capture outputs.
- Inspect the current diff and preserve unrelated work. Make acquisition/schema changes together with host decoding and audit changes. Add a regression test when an actual uncovered failure requires it.

```powershell
python -m unittest discover -s esp32_camera_recorder/esp32_camera_recorder -v
git diff --check
git status --short --untracked-files=normal
git diff --cached --stat
git diff --cached
```

Review tool output and diffs for private values before sharing them. Successful tests verify software behaviour within their scope. Validate receiver behaviour on hardware and preserve the evidence for any claimed capture capability.
