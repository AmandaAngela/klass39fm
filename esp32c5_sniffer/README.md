# ESP32-C5 Wi‑Fi sniffer: camera vs non-camera 802.11 header capture

This folder holds a small capture-and-analysis toolchain built for the capstone's first question: **is the information visible in 802.11 frame headers enough to tell a Wi‑Fi camera's traffic apart from other devices' traffic?**

An ESP32-C5 runs in promiscuous mode and passes every frame it hears to a PC over USB. A Python script turns those frames into a standard `.pcap` (openable in Wireshark), keeps only the devices you name by MAC address, and walks you through timed recording **stages** (camera still, camera with motion, laptop on YouTube, laptop on a video call, and so on). A second script then summarises each stage's header statistics into tables.

The scripts only **capture and describe** traffic, no camera/non-camera classifier.

---

## Files

```
esp32c5_sniffer/
├── esp32c5_sniffer.ino          ESP32-C5 firmware (Arduino IDE)
├── README.md                    this file
└── host/
    ├── sniff_host.py            PC side: serial → pcap, MAC search, guided stages
    ├── analyze_stages.py        per-stage header statistics → 2 tables (+ CSV)
    └── datasets/                captures (created automatically)
        ├── runN_<date>_<time>.pcap          the frames (radiotap + 802.11)
        ├── runN_<date>_<time>_stages.csv    start/end and frame range of each stage
        ├── runN_<date>_<time>_links.csv     analyze_stages.py table 1
        └── runN_<date>_<time>_timing.csv    analyze_stages.py table 2
```

| File | What it does |
|---|---|
| `esp32c5_sniffer.ino` | Puts the ESP32-C5 in promiscuous mode without joining any network. Copies the first 128 bytes of every management and data frame, plus the radio's receive info (time, length, RSSI, noise, PHY format), into a ring buffer, and streams it to the PC as framed binary records. Changes channel, width or hopping on commands from the PC. |
| `sniff_host.py` | Reads the records, checks them, and writes a pcap. Optionally searches all channels for your devices' MACs and locks on their channel, filters to those MACs, guides you through the stages, and streams live into Wireshark. |
| `analyze_stages.py` | Uses Wireshark's `tshark` to read the pcap's header fields. Splits frames by stage (from `_stages.csv`) and calculates per-link and per-flow statistics. |

---

## Hardware and software

- **Board:** ESP32-C5 dev board (1×1 radio, 2.4 + 5 GHz), external omnidirectional antenna, USB-C to the PC.
- **Arduino IDE:** board package **"esp32 by Espressif" ≥ 3.3.0** (3.3.12 used).
- **PC:** Windows, **Python 3** with `pip install pyserial`, and **Wireshark** (for `tshark`, the analysis and viewing).

---

## How to collect data (steps used for the runs)

### 1. Flash the firmware
1. Open `esp32c5_sniffer.ino` in Arduino IDE.
2. In the Tools menu:
   - **Board:** ESP32C5 Dev Module
   - **USB CDC On Boot:** *Enabled* if connected to the chip's native USB port; *Disabled* if connected to the USB-UART port (then baud matters)
   - **Core Debug Level:** None
3. Click Upload. Then **close the Serial Monitor**: the ESP32 sends binary data, and only one program can use the port.

Only management and data frames are forwarded, control frames mainly deal with the WiFi standard so it's not used.

### 2. Prepare the devices
- **Find each device's MAC.**
  - Camera: from its app's device info, or the router's client list.
  - Laptop: from `netsh wlan show interfaces`, "Physical address".
  - Phone: use the network's **private/random MAC**, not the hardware one.
- **Make the laptop decodable.** The 1×1 ESP32-C5 cannot decode 2-stream or 40 MHz 802.11n/ax data. In Device Manager → Wi‑Fi adapter → Advanced, set **"802.11n/ac/ax Wireless Mode" = Disabled**, which forces 802.11a/g. Check with `netsh wlan show interfaces`: Radio type 802.11g, rate ≤ 54 Mbps. Set it back afterwards.
- **Keep the devices active during the search:** camera live view open, something playing on the laptop.

### 3. Run a guided capture
From `host/` (example command):
```powershell
pip install pyserial
```
```powershell
python sniff_host.py -p COM8 --band 2.4 --mac 60:15:6f:2e:63:91=camera --mac 70:15:fb:08:b2:5e=laptop --stages -o capture1
```
Set COM8 to your own laptop's port to the ESP32 and MAC addresses to your camera and laptop (and other devices you are connecting to).

What happens:
1. **Search:** it hops all 2.4 GHz channels with both 20 MHz or 40 MHz bandwidth until it has seen your MACs, prints how many frames each was heard with on each channel, then locks on their channel.
2. **Stages:** it prints each stage's instructions. Set the scene, press **Enter**, and the stage runs for 60 s (Enter again ends it early). Only frames inside stages are written.
3. **Output:** `datasets/capture1_<date>_<time>.pcap` + `_stages.csv`, then a summary line, e.g. `esp drops 0`, and a clock check (frames should reach the PC within a few hundredths of a second).

The default stages (edit `DEFAULT_STAGES` in `sniff_host.py`, or pass `--stages-file`):

| # | Stage | What you do |
|---|---|---|
| 1 | `cam_live_still` | camera live view open, scene still |
| 2 | `cam_live_motion` | live view open, movement in front of the camera |
| 3 | `cam_idle` | camera app closed |
| 4 | `cam_idle_laptop_youtube` | laptop plays YouTube |
| 5 | `cam_idle_laptop_download` | laptop downloads a large file |
| 6 | `cam_idle_laptop_videocall` | laptop video call, webcam on (call someone not on this Wi‑Fi) |
| 7 | `cam_live_laptop_youtube` | camera live view open and laptop plays YouTube |

### 4. Analyse
```powershell
python analyze_stages.py datasets\capture1_20261122_005018.pcap --mac 60:15:6f:2e:63:91=camera --mac 70:15:fb:08:b2:5e=laptop
```

### 5. Look at it in Wireshark
Open the pcap. Paste a stage's `wireshark_filter` from `_stages.csv` (e.g. `frame.number >= 1 && frame.number <= 12313`), and add `&& wlan.addr == <mac>` to show one device.

---

## `sniff_host.py` options

| Option | Default | Meaning |
|---|---|---|
| `-p, --port` | (required) | serial port, e.g. `COM5` |
| `-c, --channel` | none | listen on this channel and skip the search |
| `--mac MAC[=NAME]` | none | device to capture (repeat for each). Without `-c`, the script searches for them. Only frames with one of these MACs in address 1, 2 or 3 are written. |
| `--all` | off | with `--mac`: write every frame on the channel, not only the listed devices' |
| `-o, --out NAME` | `capture` | file prefix. Date and time are appended, and the file goes in `host/datasets/` unless NAME includes a folder. |
| `-d, --duration` | none (until Ctrl+C) | stop after N seconds of capture (ignored with `--stages`) |
| `-l, --live` | off | also stream into a live Wireshark window |
| `--wireshark` | auto-detected | path to Wireshark.exe |
| `-b, --baud` | 2000000 | must match `SERIAL_BAUD` on a USB-UART port; ignored on native USB |
| `--ts {rx,cb}` | `rx` | timestamp source: radio receive time, or firmware callback time |
| `--width {auto,20,40}` | `auto` | listening width after the search. `auto` searches every channel at 20 MHz, then every 40 MHz pairing, and picks 40 MHz only if it caught ≥ 1.5× the frames (and ≥ 20 more) than 20 MHz. With `-c`, `auto` means 20 MHz. |
| `--secondary {above,below}` | auto | the 40 MHz pairing; only needed for 2.4 GHz channels 5–9 |
| `--band {both,2.4,5}` | `both` | bands to search |
| `--dwell` | 250 ms | time on each channel while searching |
| `--sweeps` | 2 | minimum full sweeps before deciding |
| `--timeout` | 60 s | lock after this long even if some MACs weren't seen (only once at least one has been seen) |
| `--stages` | off | guided stages; saves `_stages.csv` |
| `--stage-secs` | 60 | length of each stage |
| `--stages-file` | built-in list | text file with one `name: what to do` per line |

**How the search decides:**
- **Each device's channel:** the channel where it was heard most at 20 MHz. At 2.4 GHz, frames also leak faintly into neighbouring channels.
- **Lock channel:** the channel shared by the most listed devices; ties go to the device listed first.

---

## `analyze_stages.py`: what it calculates

```
python analyze_stages.py <pcap> [--mac MAC=NAME ...] [--stages FILE] [--burst-gap-ms 5] [--tshark PATH]
```
It needs Wireshark (`tshark`) and plain Python, with no extra packages. It works for any number and names of stages, because it reads them from `_stages.csv`. The router is detected automatically as the most common BSSID.

### Table 1: `_links.csv`, one row per stage × link (transmitter → receiver)
| Column | Meaning |
|---|---|
| `frames`, `frames_per_s`, `kB_per_s` | amount of traffic |
| `len_med`, `len_p10`, `len_p90` | 802.11 frame length (bytes, FCS excluded): median, 10th and 90th percentile |
| `pct_over_1000B` | share of frames longer than 1000 B |
| `retry`, `pwr_mgmt`, `more_data` | share of frames with that Frame Control flag set |
| `gap_med_ms`, `gap_p90_ms` | time between consecutive frames of the link |
| `rssi_med` | median signal strength at the ESP32 (dBm) |
| `seq_missing` | share of sequence numbers skipped between captured data frames, i.e. frames sent but not captured (Null frames excluded) |
| `types`, `tids` | frame type/subtype counts; QoS TID counts |

### Table 2: `_timing.csv`, one row per stage × named device × direction (data frames with the router)
| Column | Meaning |
|---|---|
| `kB_per_s` | bytes per second |
| `active_s` | seconds of the stage with any traffic |
| `cv_per_s` | std dev ÷ mean of bytes per second: 0 = perfectly steady, above 1 = bursty |
| `bursts_per_s` | groups of frames separated by more than `--burst-gap-ms` (default 5 ms) |
| `burst_kB_med/p90/max` | size of those groups |
| `idle_gap_p90_ms` | 90th percentile of the gaps between bursts |
| `upload_share` | share of the device's data bytes that it sent rather than received |

---

## What data was collected, and how

### Setup (run 8, 2026-11-22)
- **Router:** TP-Link (`30:de:4b:1e:f2:be`), 2.4 GHz **channel 7**. The ESP32 listened at **20 MHz**.
- **Camera:** TP-Link camera (`60:15:6f:2e:63:91`) on the same router, viewed through its phone app. The phone (`ba:1b:92:59:0a:f2`, random MAC) was on the same Wi‑Fi.
- **Non-camera:** laptop (`70:15:fb:08:b2:5e`) on the same router, adapter forced to **802.11a/g** so the ESP32 can decode its data.
- **Receiver:** ESP32-C5 near the devices (camera RSSI about −14 dBm, laptop about −24 dBm).
- **Stages:** the 7 default stages, 60 s each. Stage 6 was a **Discord call where only the laptop sent video**; the other user had camera and microphone off but watched the laptop's video.
- **Quality:** 163,830 frames written. Camera sequence numbers 0–2% missing; laptop uplink 0% missing; router → laptop 31–40% missing in the quiet stages. The ESP32's drop count is only shown in the console at the end of a run, so it isn't recorded here.

### Which frames, and what is taken from them
An 802.11 frame is **MAC header + (encrypted) payload + FCS**. Without the Wi‑Fi password the payload is unreadable, so all useful information comes from the **MAC header** and from the **ESP32 radio's receive measurements**.

- **Captured:** management frames (beacons, probes, action…) and data frames (QoS Data, Null/QoS-Null). Control frames (ACK, RTS/CTS, BlockAck) are **not** captured by default (`CAPTURE_CTRL 0`).
- **Kept per frame:** the first 128 bytes (snap length), which covers the whole MAC header, the CCMP header and the start of the encrypted payload. The FCS is removed.

| Source | Fields | How they're used |
|---|---|---|
| **MAC header** | Frame Control: type/subtype, To DS / From DS (→ direction up/down), Retry, Power Mgmt, More Data, Protected | frame kinds, direction, flag rates |
| | Duration/ID | kept in the pcap, not analysed |
| | Address 1 (receiver), Address 2 (transmitter), Address 3 (BSSID/source/destination) | which device and link; the MAC filter |
| | Sequence Control (sequence number) | detecting frames that weren't captured; retransmissions |
| | QoS Control → **TID** (priority) | QoS marking per device |
| | CCMP header (packet number) | kept in the pcap, not analysed |
| **Beacon body** (management frames) | SSID, router's advertised channel | MAC search, channel check |
| **ESP32 radio** (not in the frame) | frame **length on air**, **receive time** (µs), **RSSI**, **noise floor**, PHY format | sizes, timing, signal |
| **Firmware** | channel listened on, listening width | labelling, search |

### How the frames are processed
1. **Firmware:**
   - wraps each frame in a 22-byte record header (marker, time, length, RSSI, noise, PHY format, checksum)
   - queues it in a ring buffer and streams it over USB
   - counts frames dropped when the buffer is full
2. **`sniff_host.py`:**
   - finds and checks records (skipping boot text and corrupted bytes)
   - converts ESP32 time to PC time (wrap-around fixed; the clocks are lined up using the least-delayed frame)
   - keeps only the listed MACs and only frames inside stages
   - writes each frame to the pcap as a **radiotap header (channel, RSSI, noise) + the 802.11 bytes**, with the true frame length
   - the PHY format and listening width are not yet written to the pcap
3. **`analyze_stages.py`:**
   - reads header fields with `tshark`
   - removes the 14-byte radiotap header from lengths
   - splits frames by stage, groups them by link, and calculates the two tables above

### Results summary (run 8)
Camera → router and laptop ↔ router data frames:

The last four columns describe each row's **main direction**: the direction that carries most of the device's bytes (upload for the camera and the call, download for YouTube and the download).

| Stage | Device | Upload kB/s | Download kB/s | Upload share | Main direction | Active s | CV of bytes per second | Bursts/s | Frame size (median) | Notes |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 live still | camera | 156 | 6.8 | 96% | upload | 60/60 | 0.16 | 36.6 | 1530 B | return frames 102 B (ACK-sized) |
| 2 live motion | camera | **200** (+28%) | 8.0 | 96% | upload | 60/60 | 0.11 | 36.5 | 1530 B | 90th-percentile burst grows 7.4 → 13.3 kB |
| 3 idle | camera | ~0 | ~0 | n/a | n/a | 2/60 | n/a | n/a | n/a | about 3 small frames per minute |
| 4 YouTube | laptop | 3.6 | 130 | 3% | download | 53/60 | **2.36** | 3.0 | 1328 B | chunks with silences between them (largest 989 kB) |
| 5 download | laptop | 43 | **1,978** | 2% | download | 60/60 | 0.21 | 3.8* | 1550 B | continuous; **TID 1** (background) |
| 6 one-way call | laptop | **51** | 3.7 | **93%** | upload | 60/60 | **0.15** | 23.6 | 972 B | return frames 126 B |
| 7 live + YouTube | camera | 164 | 6.9 | 96% | upload | 60/60 | 0.17 | 37.3 | 1530 B | the camera's pattern is unchanged by the laptop |
| 7 live + YouTube | laptop | 3.7 | 148 | 2% | download | 55/60 | **2.61** | 3.2 | 1328 B | chunked YouTube download |

\* The download is nearly continuous, so frames rarely have a gap above 5 ms. They merge into a few very long "bursts" (median 181 kB), so its burst rate is low even though traffic never stops.

**CV: coefficient of variation: how much a value jumps around relative to its average.
- CV = standard deviation ÷ mean
- in analyze_stages.py it's calculated from bytes per second
- close to 0: steady stream, >1: bursty (mostly quiet with occasional big spikes)

Across all stages: the camera's retry rate was 1%; its power-save flag was never set; its TID was always 0.

**Main observations:**
1. **Camera live vs idle** is a very large difference: about 150–200 kB/s of mostly full-size frames vs about 3 frames per minute.
2. **Motion** raises the camera's upload by about 28% and makes its larger bursts bigger, while the burst rate stays the same.
3. **The camera vs laptop browsing, YouTube and downloads** differ clearly in **direction** (camera 96% upload vs laptop 2–3%) and **steadiness** (camera active every second with low CV; YouTube chunked).
4. **A one-way video call looks very similar to the camera.** It's mostly upload (93%), steady every second (CV 0.15), sends regular bursts, and gets small return frames. Its lower rate and smaller frames overlap with the camera's own variation: in run 7 the camera dropped to 40–89 kB/s with a 1020 B median. So these header statistics alone don't separate a camera from one-way video. That case needs another signal, e.g. checking whether the traffic responds to movement in front of the suspected camera (SCamF-style).

### Caveats on the dataset
| Run | Problem |
|---|---|
| run3 | laptop in normal Wi‑Fi mode: its data frames could not be decoded (about 94–100% missing) |
| run4 | no video-call stage yet |
| run5 | the download was still running during the WhatsApp call (stage 6); separable by TID (download = TID 1) |
| run6 | two-way Discord call; about 31% of router → laptop frames missing |
| run7 | the "one-way call" stage contains no video upload (laptop sent ~4 kB/s); the camera streamed at reduced quality, and kept streaming ~30 s into the idle stage |
| run8 | clean (used for the summary above) |
| all | one camera, one laptop (in 802.11g mode, so its frame sizes, rates and retries aren't typical), 60 s per stage, one run per condition |

---

## Suggestions for the next stage (cleaning, and one stream per device link)

The next pipeline step reconstructs video frames from the 802.11 traffic. Ideas for preparing the data:

1. **Export once, then work from a table.** Use `tshark` (as `analyze_stages.py` does) to export one row per frame:
   - time, length (minus the 14-byte radiotap header)
   - type/subtype, To/From DS
   - transmitter, receiver
   - sequence number, retry flag, TID, RSSI
   - stage (from the frame ranges in `_stages.csv`)

   Keep the raw pcap untouched.
2. **Define a stream as (transmitter, receiver, TID).** 802.11 numbers frames separately per receiver and TID, so this is the natural "link".
   - For a camera the main stream is **camera → router, TID 0**, with **router → camera** as its acknowledgement stream.
   - Keep the direction explicit (To DS = upload, From DS = download).
3. **Keep only the frames that carry data.**
   - Use QoS Data / Data frames for video reconstruction.
   - Drop management frames, Null/QoS-Null (power-save signalling), and broadcast/multicast frames. Keep them in a side table if needed for context.
4. **Remove retransmissions.** A frame with the Retry flag and the **same sequence number** as the previous frame of that stream is a repeat of the same data: keep the first copy for sizes, but count retries separately.
5. **Account for missing frames.**
   - The sequence number goes 0–4095 and wraps, so unwrap it per stream.
   - A jump larger than 1 means frames were sent but not captured. Record the gap count per time window (as `seq_missing` does), so windows with heavy loss can be excluded or flagged instead of looking like low traffic.
6. **Group frames into bursts as candidate video frames.**
   - Within a stream, frames separated by less than a gap threshold form one burst (`analyze_stages.py` uses 5 ms). In the camera data, bursts come at about 23–37 per second, close to a video frame rate. Occasional very large bursts are likely keyframes.
   - Tune the threshold against ground truth: the camera app's reported frame rate and bitrate, or a screen recording of the live view. Check that sequence numbers within a burst are consecutive.
7. **Use fixed time windows for features**, e.g. 10 s, matching the SCamF window: volume, mean gap between frames, frames per burst, bursts per second, burst size, upload share. Mark any window that crosses a stage boundary, or where the scene was being changed, so it's excluded.
8. **Record the conditions with each capture.** Run, stage, channel/width, the laptop's Wi‑Fi mode, the camera's stream quality (HD/SD), and where the viewer was (same Wi‑Fi or mobile data). Runs 7 and 8 show the camera's rate depends on these.
