# Firmware setup and advanced capture

Daily collection needs Python, pyserial and a flashed receiver. Building requires an activated ESP-IDF v6.1 shell. Locate its export script from the local installation; do not put machine-specific SDK/tool paths in tracked files.

The tested SDK tag is **v6.1**, commit `fff9895c82d744c7237be8847347bdd1b07c6643`. Install the toolchain for the target you will build (esp32c5 and/or esp32s3), open the activated SDK shell and change into this repository. The collector's requirements.txt installs only pyserial; it does not install ESP-IDF/esptool or flash the device. Firmware binaries and generated sdkconfig files are local build outputs, so a source-only clone must build them. This project currently uses SDK defaults, with separate generated configurations per target as shown below.

## Identify, build, flash and verify

```powershell
python -m serial.tools.list_ports -v
$port = Read-Host "Receiver port"
python -m esptool --port $port chip-id
idf.py --version
```

Use the detected target, with isolated configuration/build directories:

```powershell
idf.py -B build/c5 -DIDF_TARGET=esp32c5 -DSDKCONFIG=build/c5/sdkconfig build
idf.py -B build/c5 -DIDF_TARGET=esp32c5 -DSDKCONFIG=build/c5/sdkconfig -p $port flash
```

For S3, substitute `s3` and `esp32s3`. Preserve an existing target configuration unless changing it is intended. CMakeLists.txt and main/CMakeLists.txt define the build. main/main.c configures Wi-Fi, country plan, commands/status and batches; capture.c/capture.h define parsing, counters and the queue; transport.c/transport.h implement native USB Serial/JTAG and UART0.

The firmware accepts commands on native USB or UART0; replies use the last command interface. It handles one active receiver session, channel/width and capture scope at a time; the survey script ends each session before starting the next comparison. Capture scope is target-MAC endpoint frames or all decoded channel frames. Use one recorder/monitor at a time. UART baud is 921600; native USB baud is nominal. Board wiring/connector still matters. Enumerate again after resets. Current firmware channel plan is MY, 1–13, 2.4 GHz; verify the locally appropriate plan when changing environment.

Verify BEGIN/status/END, reported chip and firmware SHA against the build after flashing. Flash verification is not validation of reception at every PHY/width. The interactive collector checks expected receiver target on its first capture. Native USB on C5 and particular PHY modes require validation on the actual connection/workload.

## Advanced commands

Normal labelled runs use collect.py. For scripted capture or documented diagnostics:

```powershell
python recorder/record_wifi.py --port $port --baud 921600 --camera $targetMac --capture-scope target --state streaming --channel auto --secondary auto --probe-seconds 2 --duration 90 --output recordings/c5/runs
```

Use operator labels JSON with `--labels $labelsPath`; it is an array of objects containing mac, alias, device_class, activity, start_s and end_s. Offsets are from each session's BEGIN. Non-camera low-level state is unknown; its actual activity belongs in labels. The advanced command does not automatically organise a labelled dataset; collect.py does.

The width survey finishes all supported probes, preferring the strongest attributable 20 MHz data rate, then wide-only data, then sparse/control traffic. This heuristic can still choose poorly for a scanning/quiet client. Read survey.json and increase dwell or investigate. Compare sessions hold a primary and do not reacquire mid-session. Above/below means primary plus/minus four channel numbers. The receiver listens to the pair; it does not scan the secondary as an independent device.

A deliberate powered-off/background or visibility diagnostic can use a fixed primary:
```powershell
python recorder/record_wifi.py --port $port --baud 921600 --channel $primary --duration 20 --state off --notes "Controlled powered-off baseline" --output recordings/c5/runs
```
Add `--secondary above` or `below` for a legal wide pair. The baseline is diagnostic, not automatically a target-labelled dataset. No active target means automatic MAC discovery cannot lock.

## Failures and recovery

- Access denied: close competing monitors, verify port and cable. Do not assume a COM number persists.
- No BEGIN/heartbeat: check booted image, transport/baud and raw bytes. Preserve failed sessions and retry after diagnosis.
- Wrong target: select the correct receiver/profile or flash the proper binary. The collector stops instead of labelling it as the requested chip.
- Tune mismatch: inspect requested versus reported primary/secondary; keep the failed evidence.
- Overflow/transport/CRC findings: inspect high-water/counters, host load and link. Repeat under documented conditions. Never silently remove loss from the report.
- No target: recheck active MAC, band, channel, physical state, placement and decodability. A busy device can be invisible to this receiver.
- Ctrl+C: stops the current capture and survey; unfinished or operator-stopped attempts stay available for review.

Tests: `python -m unittest discover -s tests -v`. Hardware reception needs separate experimental evidence. The new collection interface does not require reflashing when the receiver already uses the compatible S3/C5 firmware.
