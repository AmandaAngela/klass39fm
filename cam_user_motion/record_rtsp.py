#!/usr/bin/env python3
"""
Receiver-side ground truth: log every encoded video frame the camera sends over RTSP.

Runs ffprobe on the camera's RTSP stream and writes one row per encoded video frame
(= one packet in ffprobe terms): its size in bytes and whether it is a key frame. Nothing is
decoded or saved as video. This is what the camera's encoder really produced, so it is the
reference for check_cbr_vbr.py and compare_bursts.py.

Needs: ffprobe (part of FFmpeg: winget install Gyan.FFmpeg). Python standard library only.

Usage (PowerShell):
  # 3 minutes, no stages (stage times then come from sniff_host.py --stages running at the same time)
  python record_rtsp.py "rtsp://USER:PASS@192.168.1.50:554/stream1" --secs 180 -o tplink

  # on its own, walking through the stages in motion_stages.txt (Enter starts each stage)
  python record_rtsp.py "rtsp://USER:PASS@192.168.1.50:554/stream1" --stages -o tplink

Writes into .\\datasets\\:
  NAME_<time>_frames.csv   arrival, pts_time, dts_time, size, flags   (flags contains K = key frame)
                           pts_time = PC clock (epoch s) when ffprobe received the frame
                           (-use_wallclock_as_timestamps). The camera's own RTP timestamps are not
                           used: on the TP-Link they jumped +-0.35 s about once a second (RTCP resync).
  NAME_<time>_stages.csv   (only with --stages) same columns as sniff_host.py's stages CSV

Tapo/TP-Link: create a "camera account" in the Tapo app (Camera settings > Advanced > Camera
account); stream1 = high quality, stream2 = low quality.
"""
import argparse
import csv
import datetime
import os
import queue
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(HERE, "datasets")
DEFAULT_STAGES_FILE = os.path.join(HERE, "motion_stages.txt")


def find_ffprobe(explicit):
    import shutil
    for c in (explicit, shutil.which("ffprobe"),
              os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WinGet\Links\ffprobe.exe"),
              r"C:\ffmpeg\bin\ffprobe.exe", r"C:\Program Files\ffmpeg\bin\ffprobe.exe"):
        if c and os.path.exists(c):
            return c
    sys.exit("ffprobe not found: install FFmpeg (winget install Gyan.FFmpeg, then open a new terminal) "
             "or pass --ffprobe PATH")


def load_stages_file(path):
    """One stage per line: 'name: what to do'. Same format as sniff_host.py --stages-file."""
    stages = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                name, _, instr = line.partition(":")
                stages.append((name.strip(), instr.strip()))
    if not stages:
        sys.exit(f"no stages in {path}")
    return stages


def fmt_time(t):
    return datetime.datetime.fromtimestamp(t).isoformat(sep=" ", timespec="milliseconds")


def key_reader(q):
    for line in sys.stdin:
        q.put(line)


def main():
    ap = argparse.ArgumentParser(description="Log the size and type of every video frame of an RTSP stream")
    ap.add_argument("url", help="rtsp://user:pass@ip:554/stream1")
    ap.add_argument("-o", "--name", default="rtsp", help="file name prefix (default rtsp)")
    ap.add_argument("--secs", type=float, help="stop after this many seconds (default: Ctrl+C, or end of stages)")
    ap.add_argument("--transport", default="tcp", choices=["tcp", "udp"], help="RTSP transport (default tcp)")
    ap.add_argument("--ffprobe", help="path to ffprobe.exe")
    ap.add_argument("--stages", action="store_true", help="walk through stages and save their times")
    ap.add_argument("--stages-file", default=DEFAULT_STAGES_FILE, help="'name: what to do' per line")
    ap.add_argument("--stage-secs", type=float, default=60, help="length of each stage (default 60 s)")
    args = ap.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(OUTPUT_DIR, f"{args.name}_{stamp}")
    cmd = [find_ffprobe(args.ffprobe), "-v", "error", "-rtsp_transport", args.transport,
           "-use_wallclock_as_timestamps", "1",
           "-select_streams", "v:0", "-show_entries", "packet=pts_time,dts_time,size,flags",
           "-of", "compact=p=0", args.url]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

    fout = open(base + "_frames.csv", "w", newline="")
    w = csv.writer(fout)
    w.writerow(["arrival", "pts_time", "dts_time", "size", "flags"])
    count = {"frames": 0, "keys": 0, "bytes": 0}
    lock = threading.Lock()

    def reader():
        for line in proc.stdout:
            arrival = time.time()
            kv = dict(p.split("=", 1) for p in line.strip().split("|") if "=" in p)
            if "size" not in kv:
                continue
            with lock:
                w.writerow([f"{arrival:.6f}", kv.get("pts_time", ""), kv.get("dts_time", ""),
                            kv["size"], kv.get("flags", "")])
                count["frames"] += 1
                count["bytes"] += int(kv["size"])
                count["keys"] += "K" in kv.get("flags", "")

    threading.Thread(target=reader, daemon=True).start()
    err_lines = []
    threading.Thread(target=lambda: err_lines.extend(proc.stderr), daemon=True).start()

    stages, keys, sw, sf = None, queue.Queue(), None, None
    if args.stages:
        stages = load_stages_file(args.stages_file)
        threading.Thread(target=key_reader, args=(keys,), daemon=True).start()
        sf = open(base + "_stages.csv", "w", newline="")
        sw = csv.writer(sf)
        sw.writerow(["stage", "name", "start_time", "end_time", "duration_s", "frames", "first_frame",
                     "last_frame", "ended", "wireshark_filter"])
    st_idx, st_start, st_frames0, prompted = 0, None, 0, False

    def drain():
        hit = False
        while not keys.empty():
            keys.get_nowait()
            hit = True
        return hit

    t_start = last_print = time.time()
    print(f"recording to {base}_frames.csv  (Ctrl+C to stop)", file=sys.stderr)
    try:
        while proc.poll() is None:
            time.sleep(0.1)
            now = time.time()
            if args.secs and now - t_start >= args.secs:
                break
            if stages is not None:
                if st_idx >= len(stages):
                    break
                if st_start is None and not prompted:
                    drain()
                    name, instr = stages[st_idx]
                    print(f"\n\n=== Stage {st_idx + 1}/{len(stages)}: {name} ===\n{instr}\n"
                          f"Press Enter to start ({args.stage_secs:.0f} s); Enter again ends it early.",
                          file=sys.stderr)
                    prompted = True
                pressed = drain()
                if st_start is None and pressed:
                    st_start, st_frames0 = now, count["frames"]
                    print(f"stage {st_idx + 1} started at {fmt_time(now)}", file=sys.stderr)
                elif st_start is not None and (pressed or now - st_start >= args.stage_secs):
                    end = min(now, st_start + args.stage_secs)
                    how = "complete" if now - st_start >= args.stage_secs else "ended early (Enter)"
                    sw.writerow([st_idx + 1, stages[st_idx][0], fmt_time(st_start), fmt_time(end),
                                 f"{end - st_start:.1f}", count["frames"] - st_frames0, "", "", how, ""])
                    sf.flush()
                    print(f"\a\nstage {st_idx + 1} ({stages[st_idx][0]}) {how}", file=sys.stderr)
                    st_idx, st_start, prompted = st_idx + 1, None, False
            if now - last_print >= 2:
                last_print = now
                with lock:
                    fout.flush()
                    c = dict(count)
                el = now - t_start
                print(f"\r{el:6.0f} s  frames {c['frames']:6d} ({c['frames'] / el:4.1f}/s)  key {c['keys']:4d}  "
                      f"{c['bytes'] * 8 / el / 1000:7.0f} kbit/s avg", end="", file=sys.stderr)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        try:
            proc.wait(3)
        except subprocess.TimeoutExpired:
            proc.kill()
        time.sleep(0.2)
        with lock:
            fout.close()
        if sf:
            sf.close()
    print(f"\n{count['frames']} frames ({count['keys']} key frames) saved to {base}_frames.csv", file=sys.stderr)
    if stages is not None:
        print(f"stage times saved to {base}_stages.csv", file=sys.stderr)
    if count["frames"] == 0:
        print("no frames received. ffprobe said:\n" + "".join(err_lines[-10:]), file=sys.stderr)


if __name__ == "__main__":
    main()
