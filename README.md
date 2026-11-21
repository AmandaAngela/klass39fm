# Passive Wi-Fi research recorder

Collect reproducible Stage 1 measurements with an ESP32-C5 or ESP32-S3. Run one interactive script; it asks for the experiment details, searches the supported 2.4 GHz settings, records 20 MHz and legal 40 MHz comparisons, checks the data and writes an explanation **inside every recording folder**. Device classes come from the operator. This repository does not classify cameras from traffic.

## Start collecting

For a new machine, you need Git, Python 3.10 or newer, an ESP32-C5 or ESP32-S3, and a USB data cable. This is a hardware recorder: cloning the repository does not make a blank ESP ready to capture.

1. Clone the source using the commands below.
2. For a new/unflashed ESP, install ESP-IDF v6.1 and follow [build/flash instructions](docs/firmware.md) once, using the correct chip target. A receiver already running this firmware can skip that step.
3. Connect the receiver, close other serial monitors, install the Python dependency and run the collector. Install the board's USB-serial driver if its port does not appear. No API key, AI service, existing profile or dataset is required.

Windows PowerShell (run from wherever you want the checkout):

```powershell
git clone https://github.com/AmandaAngela/klass39fm.git
cd klass39fm
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe collect.py --check
.\.venv\Scripts\python.exe collect.py
```

An existing Python environment with pyserial also works: `python collect.py`.
The ESP must already have the matching firmware; see [building and troubleshooting](docs/firmware.md). ESP-IDF is needed to build firmware, not for daily recording. Close other serial monitors.

On Linux/macOS, create the environment with `python3 -m venv .venv`, then use `.venv/bin/python` in place of `.\.venv\Scripts\python.exe`. The host software uses pyserial; serial drivers/device permissions must be configured for that OS. Windows is the hardware-tested setup. WSL additionally requires USB passthrough and is not the simplest Windows route. A virtual environment must be created locally; do not copy or commit someone else's `.venv`.

`collect.py --help` checks that the CLI can load without a receiver. `--check` enumerates/selects a port; it does not test radio reception or flash firmware. The first traffic preflight checks the firmware target and actual observations. Current firmware operates on **2.4 GHz only**.

The script asks for the receiver type and current MAC (or guided discovery). It automatically selects the single USB serial connection, ignoring Bluetooth ports. A saved profile can recognise the same USB adapter after its port changes. If several possible receivers are connected, unplug extras or use --port; it does not guess. USB bridge names do not prove chip identity, so firmware verification still checks the selected receiver. It then runs an **unlabelled traffic check before asking for the dataset class/name**. Start the intended workload for that check. It automatically surveys both widths and records ten seconds at 20 MHz and each legal 40 MHz setting on the selected primary.

Each setting must pass raw replay, receiver/quality checks, the 47-column schema check and applicable-field checks. Default minimum traffic is **20 outgoing payload-carrying data frames and 1 such frame/second**, measured over the fixed capture. Frames only addressed to the target, probes, ACKs and data-null frames do not satisfy this requirement. These are conservative screening thresholds, not a validated detector of incomplete traffic or 2x2 transmissions.

If any setting fails, the script prints **CHECK WITH AI**, saves the diagnostic evidence under runs/, and stops before the full dataset recording. Share that run's traffic_check.json and reports for review. Confirmed idle/low-rate devices may legitimately fail this gate; their data is preserved for review rather than called useless. For a justified experiment, thresholds can be supplied explicitly with --min-data-frames and --min-data-rate, and check duration with --preflight-seconds. The actual thresholds are recorded in profiles and reports.

After passing, the script asks **camera or non-camera**, then **device name/model**, activity, duration and setup. Camera maps to positive; non-camera maps to negative. This mapping comes from operator-confirmed identity, not traffic shape. Include connected band, topology, receiver placement/distance and workload settings in setup; unknown details remain unknown. An idle camera remains positive.

Not every one of the 47 fields applies to every PHY/frame/receiver. For example, HE fields are blank on legacy traffic, and S3 has no C5 extensions. The check reports populated counts for all 47 columns and requires fields applicable to the observed data. It cannot promise all 47 values or complete radio coverage.

Enter a known active MAC and state its source (device/router settings or a separately verified power test), or enter `find`. A traffic-volume guess is not accepted as confirmed identity. `find` guides three steps: turn the device on and start its activity; unplug only that device while leaving the ESP/router/other devices running; power it on and restart the same activity. Each default scan takes roughly a minute.

After the three steps, find **automatically selects a candidate; there is no MAC-selection or identity-confirmation question**. It considers non-beacon transmitters absent during OFF with at least 20 data frames after restart. It ranks same-address ON/OFF/ON matches first, then outgoing data counts after/before restart, using address order only to break exact ties. This is a reproducible heuristic, not a probability or camera classifier.

A unique same-address match with at least 20 data frames in both ON scans receives power_test_supported identity status. A changed-address or competing-candidate selection is provisional. Both can proceed through traffic preflight and recording; provisional collections stay together under runs/<run_id>/review/ and are not eligible as confirmed training samples. If no candidate has enough data, find stops with evidence for review. You still perform the physical power changes and confirm readiness for each scan. No identity is inferred from MAC prefix or traffic shape.

Keep the workload stable through the check and full capture. Full collection starts a fresh automatic survey of both widths, then records fixed comparisons. Each full recording must pass the same traffic checks before it enters dataset/. If traffic stops after preflight, the affected recording stays in runs/ for review. A 90-second setting gives two or three comparisons plus preflight and discovery time. Default probe dwell is two seconds; use `--probe-seconds 5` for a quiet target. No transmission means automatic discovery cannot lock a fully powered-off target; use a documented fixed-channel diagnostic baseline instead.

Profiles are saved privately. Repeat with:
```powershell
python collect.py --profile profiles/<device_alias>.json --seconds 90
```
Current MAC, identity and activity are reconfirmed. Exit 0 means acquisition checks passed; 1 means failure/interruption; 2 means no target, unresolved identity or findings needing review. Acquisition checks are not a declaration of model suitability.

## Where everything goes

```text
collect.py                  Entry point for normal recording
recorder/                   Python capture, discovery, audit and reporting
main/                       ESP firmware
tests/                      Synthetic protocol/workflow regression tests
docs/                       Measurement definitions and firmware instructions
profiles/                   Private reusable experiment inputs
recordings/
  c5/                       Current C5 collection (s3/ for new S3 work)
    README.md               Local collection index
    manifest.csv            Session labels, paths, hashes and acquisition status
    dataset/
      <device>_<UTCdate-time>_<activity>_<positive-or-negative>_<run-id>/
        README.md           Collection summary and links to receiver tests
        20mhz/              First receiver test, with its own files and README
        40mhz_above/         When legal on the selected primary
        40mhz_below/         When legal on the selected primary
    runs/<run_id>/           Discovery evidence, run report and review attempts
archive/                    Private historical experiments and migration index
build/                      Ignored, regenerable firmware build outputs
AGENTS.md                   Instructions for future AI assistants
CAPSTONE_CONTEXT.md         Research objective and scope
```

Browse `recordings/c5/dataset/` for acquisition-checked collections. **One run creates one device/date/activity folder**, containing the separate 20 MHz and legal 40 MHz receiver tests. The two or three child folders are sequential observations of the same activity, not duplicated recordings. A primary near the band edge has only one legal 40 MHz position, giving two recordings; a middle primary can have both, giving three. The run ID avoids overwriting repeats.

All comparisons stay together. If any full comparison has acquisition findings or identity is provisional, the entire collection uses the same layout under runs/<run_id>/review/ instead of dataset/. Its manifest entries have review_required and training_eligible=false. Each child has its own five-section README; the parent README explains the receiver settings. Historical collections retain their paths unless explicitly reorganised with verified path updates. Preflight is diagnostic, not a labelled dataset.

There is no additional automatic finaliser copy. Future training selections should reference canonical sessions through a selection manifest and write derived features separately. Historical copies remain in the private archive, with original paths preserved inside its ZIP. Archives, profiles, capture outputs and machine-specific configuration are ignored by Git.

## What each recording contains

| File | Purpose |
| --- | --- |
| README.md | This recording's summary, files/code, reproduction steps, setup/results and Stage 2 suggestions |
| all_wifi_packets.csv | All decoded channel observations, including unrelated devices |
| camera_packets.csv | Target in immediate receiver/transmitter address; filename also applies to negatives |
| raw_serial.bin | Exact exported measurement stream for replay; not full Wi-Fi frames |
| status.jsonl | BEGIN/status/END, receiver tuning, counters and firmware identity |
| session.json | Operator labels, capture settings and acquisition outcome |
| recording_context.json | Setup and review explanation retained when regenerating the README |
| traffic_check.json | All 47 columns' target availability, applicable-field failures, counts/rates and screening thresholds |

README statistics and suggestions are generated from the actual recording. Rule-based suggestions mention findings such as retries, missing data or no decoded wide frames; they do not clean data or discover the best model features. AI is optional for interpreting patterns or difficult identity/visibility cases. Unknown setup facts cannot be reconstructed by a template.

## Measurements and processing

The firmware saves selected MAC-header and radio metadata from supported management, data and control callbacks. Host code decodes batches, derives header/PHY fields and filters target-address rows. It preserves raw observations, retries and timestamps. Current CSVs have 47 columns; replay also accepts older 23/31-column archives.

See [measurement definitions and rationale](docs/measurements.md) for fields, omissions, receiver limits and Stage 2 cautions. The frame body, FCS bytes and CSI are currently not exported. Their omission does not prove they are useless.

## Source files and review tools

| Script in recorder/ | Responsibility |
| --- | --- |
| collection.py | Prompts, profiles, controlled identity discovery, acquisition checks, canonical folders and manifest |
| traffic_check.py | Conditional field availability and minimum outgoing-data screening; no camera or 2x2 classification |
| record_wifi.py | Serial session capture and quality counters; advanced CLI |
| width_survey.py | Automatic primary/secondary survey and fixed comparisons |
| protocol.py | Versioned wire decoding and CSV field derivation |
| audit_recording.py | Replay raw bytes and compare saved exports/counters |
| session_report.py | Generate or refresh an individual five-section README |
| device_features.py | Descriptive rates and burst windows; no classification |

```powershell
python recorder/audit_recording.py $sessionFolder
python recorder/session_report.py $sessionFolder
python recorder/device_features.py $sessionFolder --mac $targetMac --measured-duration --json
python -m unittest discover -s tests -v
git diff --check
```

Source changes must update relevant instructions. Each new recording must have its own explanation; a top-level README alone does not fulfil this requirement.

## Publishing source updates

Commit source, firmware, generic instructions and synthetic tests together so the wire schema and host decoder stay compatible. Git should contain collect.py, requirements.txt, recorder/, main/, tests/, docs/, README.md and AGENTS.md, along with build/editor configuration. It should not contain .venv/, build/, profiles/, recordings/ or archive/. The ignore rules keep generated/local files out; they do not protect files already tracked.

From the repository root, after validation:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
git diff --check
git status --short --untracked-files=normal
git add -A
git diff --cached --stat
git diff --cached
# Review the staged file list and content for private data before these steps:
git commit -m "Add C5 collection workflow with traffic checks and grouped recordings"
git push origin main
```

The commands assume the intended branch is main and origin points to this repository. Use a branch/PR if the remote requires it. If the remote moved ahead, fetch and integrate the changes before pushing; do not force-push over other work. Git records the old nested Python folder as removed/moved and adds recorder/; uploading only collect.py would leave an incomplete release. Capture output folders are created when the script runs and need not exist in a fresh clone.
