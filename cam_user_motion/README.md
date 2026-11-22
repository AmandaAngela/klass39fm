# cam_user_motion: do the camera's inter-frame sizes follow user movement?

Tests the Stage 6 assumption: with motion compensation, movement in view makes **P-frames
(inter-frames) larger**, and that change is visible over the air without decrypting anything.
Key frames are not needed (Stage 4 drops them). They come on a fixed schedule (GOP), so motion
does not trigger them.

| Script | What it does |
|---|---|
| `record_rtsp.py` | Laptop pulls the camera's RTSP stream with ffprobe and logs each encoded frame's size and key flag (ground truth). |
| `check_cbr_vbr.py` | Is the encoder CBR (bitrate held constant, no motion signal) or VBR (bitrate follows the scene)? |
| `compare_bursts.py` | Burst-sum frame sizes from the ESP32 sniffer vs ffprobe's real frame sizes, plus the P-frame ratios to the empty room from each. |
| `motion_stages.txt` | Stage list: control first (you move behind the camera, out of its view), then empty room / wave / walk / standing still in view / dance. The camera is never turned, so every stage films the same scene. Last come lighting stages with nobody in view (light toggled, then light off long enough for IR night mode, each followed by a settle stage; night vision stays on AUTO). They test whether a lighting change alone makes P-frames grow (a false Stage 6 signal) or triggers an extra key frame, and they are kept out of the comparisons. |
| `common.py` | Shared code (pcap reading, burst grouping, stage handling). |

Stage kinds (from the names, see `common.py`): **empty** (nobody in view, the baseline for every ratio), **present** (you in view, standing still), **motion**, **control** (you move out of view), **other** (lighting, settle). Empty and present are separate because standing still in view already made P-frames 1.47x larger than the empty room. For older runs that named every still stage `still_N`, mark the in-view ones: `--kind still_3=present still_4=present`.

## Setup

```powershell
winget install Gyan.FFmpeg
```
```powershell
pip install numpy scipy matplotlib pyserial
```
Wireshark (tshark) must be installed, as for `analyze_stages.py`.

TP-Link Tapo RTSP: Tapo app > camera > Settings > Advanced > Camera account. Then use
`rtsp://USER:PASS@<camera-ip>:554/stream1` (`stream2` = low quality). Test it first:
```powershell
ffprobe -rtsp_transport tcp "rtsp://USER:PASS@192.168.1.50:554/stream1"
```

## Test 1: CBR or VBR (laptop only)

```powershell
python record_rtsp.py "rtsp://USER:PASS@192.168.1.50:554/stream1" --stages -o tplink
```
```powershell
python check_cbr_vbr.py --frames datasets\tplink_<time>_frames.csv
```
Follow the stage prompts (Enter starts each 60 s stage). The verdict compares the bitrate in
motion stages with empty-room stages, over one-GOP windows: ratio >= 1.30 is VBR, <= 1.15 is constant bitrate.
A CBR camera gives Stage 6 little or nothing to work with, whatever the sniffer does.

## Test 2: sniffer vs ground truth (ESP32-C5 + laptop together)

Close the camera app on every phone, so the laptop's RTSP stream is the only video on air.

1. Start the RTSP recorder and the ESP32 sniffer. Run both these commands in separate terminals.
```powershell
python record_rtsp.py "rtsp://USER:PASS@192.168.1.50:554/stream1" --secs 900 -o motion1
```
```powershell
python ..\esp32c5_sniffer\host\sniff_host.py -p COM8 --band 2.4 --mac 60:15:6F:2E:63:91=camera --stages --stages-file motion_stages.txt -o datasets\motion1
```

2. Analyze the pcap contents to compare bursts (keyframes vs interframes) and for another CBR/VBR check.
```powershell
python check_cbr_vbr.py --pcap datasets\motion1_<time>.pcap --cam <cam-mac> --frames datasets\motion1_<time>_frames.csv
```
```powershell
python compare_bursts.py --pcap datasets\motion1_<time>.pcap --frames datasets\motion1_<time>_frames.csv --cam <cam-mac> --plot
```
Check if the ESP32 sniffer can determine CBR/VBR over the air and agree with test1's conclusion.


### Reading compare_bursts.py

- **clock offset / correlation**: the two logs are lined up by cross-correlating their byte
  series. A correlation below 0.3 means wrong MAC, a second stream on air, or heavy loss.
- **frames with a burst**: share of real frames the sniffer found. **frames with >1 burst**:
  frames split by a pause on air (raise `--burst-gap-ms`).
- **size**: `air = a x frame + b`. `a` is about 1.03-1.10 (802.11/IP/TCP/RTP overhead). Pearson r
  near 1 means burst sums track real frame sizes. "with missed-frame fill" adds the median packet
  length for each skipped sequence number inside a burst. Packets missed at a burst's very start
  or end cannot be seen, so some bursts still read low.
- **key frame flag**: precision/recall of the Stage 4 rule (burst > k x neighbour median).
- **per stage**: P-frame medians from ffprobe and from air. The claim holds for this camera if
  **motion/empty > 1** with a small p-value in both rows, and **control/empty is close to 1**
  (movement the camera cannot see should not count).

## Results summary (as of 22/11/26)

Test 1 was performed: the video frames of the TP-Link's RTSP stream (stream1) were logged with
`record_rtsp.py` and analysed with `check_cbr_vbr.py` to see how frame sizes change with a user's
movements. Two runs, 60 s per stage:

- Run 1: `datasets\tplink_20261122_130023_frames.csv` (first stage list; control stage turned the camera to a wall)
- Run 2: `datasets\tplink_20261122_153630_frames.csv` (control first, lighting stages added). Analysed with
  `--kind still_3=present still_4=present`, because the user was in view, standing still, in those stages.

### Bitrate: capped VBR

| Run 2 | P-frame median | key frame median | bitrate |
|---|---|---|---|
| empty room | 4.2 KB | 86 KB | 841 kbit/s |
| person in view, standing still | 6.2 KB | 92 KB | 1132 kbit/s |
| person moving (wave, walk, dance) | 8.2 KB | 47 KB | 1187 kbit/s |
| control (moving behind the camera) | 4.9 KB | 86 KB | 943 kbit/s |

- Empty room → person in view: run 2's bitrate rises 1.35x.
- Person still → person moving: run 2's bitrate rises only 1.05x, P-frames grow 1.32x and key
  frames shrink by half (92 → 47 KB).
- The bitrate hit a ceiling of ~1.2 Mbit/s (run 1's motion stages sat at the same level), so the
  camera uses **capped VBR**: the bitrate follows the scene up to the ceiling, then motion moves bits
  from key frames to P-frames within it.
- Compared with the empty room, P-frames are 1.95x larger in motion and 1.48x with a person standing
  still. The control (motion the camera cannot see) gave 1.18x: mostly clean, with a small leak
  (possibly shadows or reflections).

Motion did not add key frames (30 per stage in every stage; all key-frame intervals 1.92-2.08 s).
Motion made the key frames smaller and the inter-frames bigger.

### Stimuli that change inter-frame sizes

- Lighting shows that a camera can see the room. It does not show that it sees the user.
- Movement shows that a camera sees the user specifically, and where (Stage 7 localisation).

### Lighting (run 2, night vision on AUTO)

- Extra key frames: 32 instead of 30, at irregular times, about one per switch. Each switch restarts
  the 2 s key-frame schedule. Motion never did that.
- Bigger P-frames: median 7.3 KB, 1.74x the empty room. That is close to motion's 1.95x.
- The pattern is different, though. P-frame bytes spike at each switch (up to 562 kB in one second,
  against about 100-130 kB normally), then settle. Motion raises P-frames for as long as the user
  keeps moving.
- Light off long enough for night mode: P-frames fell to about 350 B, 12x smaller than the empty
  room. The dark state shrinks frames; it is the switching that makes them spike.
- For our pipeline, a light switch produces a forced key frame plus P-frame spikes around it:
  - Stage 4 would drop the forced key frame, if it is recognised by size, but the P-frame spikes
    remain for Stage 6.
  - The forced key frame is a signal in its own right: a key frame off the usual 2 s schedule,
    right when the light switched.

Caveats: one camera (TP-Link), two runs. The lighting run had no recorded switch times and night
vision on AUTO, so the effect of the brightness change cannot be separated from IR mode switching.
Run 1 and run 2 had different scene/lighting (run 1 key frames ~117 KB vs ~86 KB), so compare them
only roughly. Test 2 (sniffer vs ground truth) has not been run yet.

## Limits

- Lighting: IR night mode or auto-exposure changes the bitrate without motion. Keep the light the same.
- Frame rate: some cameras raise fps with motion. Compare `ff_fps` across stages. Per-frame size
  (this test) and bitrate (Test 1) answer different questions.
- RTSP vs app/cloud stream: the camera may encode the stream the phone app gets with different
  settings. The test tells you about the RTSP stream's encoder only.
- The X5 mini camera probably has no RTSP. For it, only the over-the-air side can be measured,
  using the method validated here on the TP-Link.
