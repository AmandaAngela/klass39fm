# Portable Wi-Fi camera research recorder

This prototype records passive 802.11 management, data and control frame metadata visible to one receiver. It can discover active transmitters, follow a known test transmitter, or listen on a fixed channel. It requires no router credentials. Camera state is an operator-supplied experiment label. Other traffic, including uploads and video calls, can resemble a camera stream.

## Build and flash

Open an ESP-IDF v6.1 PowerShell environment in the project root. In a fresh checkout select the ESP32-S3 target before building. Existing configured workspaces can start at the build step.

```powershell
idf.py set-target esp32s3
idf.py build
python -m serial.tools.list_ports -v
$port = Read-Host "Receiver serial port"
python -m esptool --port $port chip-id
idf.py -p $port flash
```

Confirm the board and port before flashing. Close IDF Monitor or any other process holding the receiver port. The tested interface uses native USB Serial/JTAG (Espressif VID 303A, PID 1001). Connect the board's native USB connector. A separate USB-to-UART bridge on this board carries console output. USB line baud is nominal. The fallback on targets without Serial/JTAG uses UART0 at 921600 baud and requires validation on the target. The firmware uses the MY country plan (channels 1–13). Verify the local channel plan before moving the receiver.

## Record an experiment

From the project root in the activated shell:

```powershell
$rec = 'esp32_camera_recorder/esp32_camera_recorder/record_wifi.py'
python $rec --port $port --state unknown --channel scan --duration 20
$camera = Read-Host "Test-device MAC address"
$channel = Read-Host "Test-device channel"
python $rec --port $port --camera $camera --state idle --channel auto --duration 60
python $rec --port $port --camera $camera --state streaming --channel $channel --duration 60
python $rec --port $port --camera $camera --state off --channel $channel --duration 60
python $rec --port $port --camera $camera --state motion-triggered --channel $channel
```

- `scan` cycles channels every 500 ms. `auto` requires a test MAC and locks when address 2 matches it. Without a channel argument, supplying a MAC selects automatic locking and omitting the MAC selects scanning. Untargeted recordings contain all decoded observations and a header-only camera CSV. Channel transitions and lock status appear in `status.jsonl`.
- A channel number locks immediately, including when the target is off. Use a fixed channel for comparable time series. Each START applies a fresh mode and camera address. The state choices also include `background`, `unknown` and `motion`.
- Omit `--duration` to record until Ctrl+C. On a normal stop the host requests STOP and waits for the receiver to drain its ring and send its final counters. Abrupt process termination can leave a partial session. Each run creates an exclusive UTC-timestamped directory with a random session token.
- In `--notes` record a device or model alias, ground-truth basis, environment, distance, obstructions, network setup, receiver placement, stream settings and any state changes. Keep mixed or uncertain states labelled accordingly. The receiver can listen without joining the network.

## Session files and measurements

| File | Contents |
| --- | --- |
| `raw_serial.bin` | Exact bytes returned by serial reads, including diagnostics, corrupt frames and partial tails. No payload capture or host timestamp insertion. |
| `all_wifi_packets.csv` | Every decoded observation in valid WFS2 batches for this session, in delivery order. |
| `camera_packets.csv` | Rows from the complete CSV with the known MAC as the immediate transmitter or receiver (addr2 or addr1). This includes both link directions and excludes broadcast beacons merely mentioning that network. |
| `status.jsonl` | BEGIN, heartbeat/channel and END snapshots, with device uptime, tuned channel, lock, counters, build SHA, IDF and target. |
| `session.json` | Settings, operator label and notes, UTC times, firmware and host counters, result and final reconciliation. Periodically checkpointed. |

`esp_timestamp_us` is the raw 32-bit Wi-Fi RX clock. It wraps after about 71.6 minutes. The recorder counts adjacent equal values and decreases and preserves both. `host_utc` is the host time the read completing a batch was processed. Several observations may share it. Neither time is a synthetic inter-arrival estimate. Sequence and retry flags provide context for repeated observations. Reordering, aggregation, retries, fragmentation and timestamp precision complicate interpretation.

`frame_length_bytes` is IDF's reported `sig_len`, including FCS. RSSI is in dBm. The rows retain raw frame and sequence control, type/subtype, To DS, From DS, retry, sequence, fragment and QoS TID where present. Addresses 1 and 2 are the immediate receiver and transmitter. Raw addresses 3 and 4 support source/destination derivation from the DS bits. Missing addr4 and TID are blank. `wire_seq` identifies a transfer, and `observation_id` counts eligible frames before the ring can drop them. No smoothing, deduplication, unwrapping, synthetic filling or address-based classification is applied.

## Review capture quality

1. Check `result`, `begin_received` and `end_received`. An interrupted link may prevent measuring trailing losses. `completed` means both boundaries arrived after a normal stop. Check counters even for a completed session.
2. At END, `eligible = sent + overflow + tx_lost`. `sent_minus_rows` should be zero. `overflow` counts eligible frames rejected by the full 1,024-slot ring. `tx_lost` counts records abandoned when the final drain cannot deliver them. A full USB TX buffer causes a bounded retry, counted in `tx_errors`. Retried packets keep their observation IDs. `high_water` is peak occupied slots. All firmware counts restart for each session.
3. Examine `malformed`, `unsupported` and `rx_errors` (callback records excluded before eligibility), tune errors, wire gaps, observation gaps, CRC errors, trailing partial bytes and watchdog messages. An observation gap can already be explained by queue overflow or transport loss. Do not add these counters to estimate total loss. Boot or console text can appear as unframed bytes. Review the raw file when unexplained bytes occur.
4. Check `locked` and the observed channel over time. During hopping the radio misses traffic on every other channel. Even all-zero application loss counters cannot measure frames the radio or driver never delivered. This S3 prototype observes 2.4 GHz management, data and control frames and stores metadata only. A silent, wired-only or out-of-band device can remain invisible.
5. Keep original observations and identifiers for experimental grouping. Generate derived features separately. Hold out whole devices and sessions when evaluating generalisation. These data alone do not establish that a device is a camera, hidden or unauthorised.

## Troubleshooting and checks

- **Serial port access denied.** Close any competing serial monitor or recorder. Enumerate ports again and check the native connector and USB cable. Re-run the chip probe before flashing if the port changes.
- **No BEGIN or heartbeat.** Check that the updated image booted, the port is the native interface, and the correct recorder was started. A monitor will show binary bytes during recording. Keep the failed session's raw bytes and JSON for diagnosis. A new recorder can start a fresh session after a host disconnect.
- **Queue or transport drops.** Inspect the high-water mark, terminal counters, host disk/CPU load, CRC failures and gaps. Repeat at the same channel and traffic condition. Keep the failed recording and document the condition.
- **No camera rows.** Verify the state, test MAC, band and channel. Check whether auto mode is still sweeping. A powered-off camera cannot lock the receiver through its own transmissions.
- **Build identification.** The recorder reports the firmware ELF SHA. If Windows reports console encoding problems, set `$env:PYTHONUTF8='1'` for that shell.
- **Regression tests.** Run `python -m unittest discover -s esp32_camera_recorder/esp32_camera_recorder -v`. Recorder exit codes are 0 for completion without flagged quality issues, 1 for an incomplete run and 2 for completion with quality issues.

Recording files contain real wireless addresses and experiment notes. Keep original sessions and local research logs in private storage.

## Optional experiment settings

For a fixed-channel 40 MHz experiment, flash the updated firmware and add
`--secondary above` or `--secondary below` to the recording command. Match the
access point's primary channel and secondary position. Both 20 MHz channels
must fit in channels 1–13. For example:

```powershell
python $rec --port $port --camera $camera --state streaming --channel 6 --secondary above --duration 60
```

Wide recordings use the extended WFS2 v4 status. The recorder compares driver
readback (`reported_primary` and `reported_secondary`) with the request. To test
physical reception, use a known HT40 transmitter and look for its data rows with
`phy_sig_mode=1` and `phy_cwb=1`. A successful tune alone measures configuration.
Leave out `--secondary` for the original recording commands and firmware.

### Automatic 20/40 MHz survey for a known MAC

With the HT40-capable firmware installed, the PC recorder can drive the search.
Keep the test device doing the same activity throughout the comparison.

```powershell
$rec = 'esp32_camera_recorder/esp32_camera_recorder/record_wifi.py'
python $rec --port $port --camera $camera --state streaming --channel auto --secondary auto --duration 60
```

For each primary from 1 through 13 it tries 20 MHz, then each valid secondary
above or below (four channel numbers away). It spends two seconds recording
at each setting by default. Increase `--probe-seconds` for a quiet transmitter.
The search stops at the first primary with a decoded **transmission from the target**
on that primary. A frame merely addressed to the MAC does not select a channel.
If one full sweep finds nothing, the result is `target_not_observed`; a quiet
device or one the receiver cannot decode may still be present. To search only a
known primary, replace `--channel auto` with its channel number.

Once the target is heard, the recorder takes a fresh fixed-channel recording at
20 MHz and at **every valid 40 MHz setting on that primary**, including when
the initial sighting was at 20 MHz. `--duration` applies to each comparison
(default 60 seconds). Search and comparison runs each have their own raw bytes,
packet CSVs, timestamps and counters. Label offsets start at each run's BEGIN.
Ctrl+C ends the whole survey.

Open `survey.json` in the printed survey directory. Compare entries with
`phase=compare` using target data frames/s, frame bytes/s, retries and counts
of data frames sent and received at HT40. Width evidence uses the frame's HT
mode and width flag. An HT40 receiver setting can deliver 20 MHz frames as well.
Rates use measured BEGIN-to-END time including drain; frame bytes include Wi-Fi
overhead and retries. Use each comparison folder with `device_features.py
--burst-windows` to examine timing. Review tune failures, missing target data
and capture losses alongside the counts. Measurements are sequential, so repeat
the activity across runs to assess how consistently a difference appears.

Optionally pass `--labels labels.json` with any recording. The recorder copies
these operator annotations into `session.json`. Times are seconds from BEGIN;
omitting start or end means session start or session end. The same device may
have several activity intervals. For example:

```json
[
  {"mac":"02:00:00:00:00:01","alias":"camera A","device_class":"camera","activity":"live view","start_s":10,"end_s":40},
  {"mac":"02:00:00:00:00:02","alias":"phone B","device_class":"phone","activity":"video call"}
]
```

For existing or new fixed-channel recordings, export outgoing traffic for one
device in 100 ms windows, or opt into elapsed-time rates in the usual summary:

```powershell
$features = 'esp32_camera_recorder/esp32_camera_recorder/device_features.py'
python $features $folder --mac $camera --burst-windows
python $features $folder --mac $camera --measured-duration
```

Window output is CSV (or use `--json`). Its time origin is the first observed
Wi-Fi frame; it ends with the window containing the last observed frame.
Empty intervening windows have zero counts. Lengths include Wi-Fi overhead and
retries; retry counts are shown separately. Only data subtypes carrying data are
included. A new burst starts after a gap of at least 10 ms. Adjust this analysis
threshold with `--burst-gap-ms` and window size with `--window-ms`. Gap and
burst-period medians use the later frame's window. These bursts describe radio
traffic. The optional measured duration uses device BEGIN through END (including
the final drain). Default summary calculations retain their original denominator.

For a read-only consistency check, run `python esp32_camera_recorder/esp32_camera_recorder/audit_recording.py <session-folder>`. It replays the raw file, compares every decoded measurement, filtered row and status record against the exports, and checks terminal counts. Host receipt times exist only in the exports. A passing replay can still report firmware drops.
