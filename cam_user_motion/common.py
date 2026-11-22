"""
Shared helpers for the cam_user_motion scripts.

  - read the camera's uplink from a sniff_host.py pcap (via tshark)
  - split that uplink into bursts (one burst ~ one encoded video frame)
  - read the ffprobe packet log written by record_rtsp.py (receiver-side ground truth)
  - read a _stages.csv (from sniff_host.py --stages or record_rtsp.py --stages)

Python 3 + numpy. tshark (Wireshark) is needed only for pcap input.
"""
import csv
import datetime
import os
import shutil
import statistics as st
import subprocess
import sys
from collections import Counter, deque

RADIOTAP_LEN = 14          # sniff_host.py writes a 14-byte radiotap header before each frame
TSHARK_FIELDS = ["frame.number", "frame.time_epoch", "frame.len", "wlan.fc.type", "wlan.fc.subtype",
                 "wlan.fc.retry", "wlan.ra", "wlan.ta", "wlan.bssid", "wlan.seq", "wlan.qos.tid"]


# ---------------------------------------------------------------- general
def norm_mac(m):
    return m.strip().lower().replace("-", ":")


def is_group(mac):
    return bool(mac) and int(mac[:2], 16) & 1


def pct(values, p):
    v = sorted(values)
    return v[min(len(v) - 1, int(p / 100 * len(v)))] if v else float("nan")


def med(values):
    return st.median(values) if values else float("nan")


def parse_time(s):
    """Stage CSV times are local PC time written by datetime.isoformat -> epoch seconds."""
    return datetime.datetime.fromisoformat(s.strip()).timestamp()


def find_exe(explicit, name, candidates):
    for c in (explicit, shutil.which(name), *candidates):
        if c and os.path.exists(c):
            return c
    return None


def write_csv(path, rows):
    if not rows:
        return
    keys = list(rows[0].keys())
    for r in rows[1:]:
        keys += [k for k in r if k not in keys]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow({k: (round(v, 5) if isinstance(v, float) else v) for k, v in r.items()})
    print(f"saved {path}", file=sys.stderr)


def cell(v, spec):
    if isinstance(v, float) and v != v:
        return "-"
    return format(v, spec) if spec and isinstance(v, (int, float)) else str(v)


def print_table(rows, cols, left=1):
    """cols = (key, width, format spec); the first `left` columns are left-aligned."""
    print(" ".join(f"{h:<{n}}" if j < left else f"{h:>{n}}" for j, (h, n, _) in enumerate(cols)))
    for r in rows:
        print(" ".join(f"{cell(r[k], f):<{n}}" if j < left else f"{cell(r[k], f):>{n}}"
                       for j, (k, n, f) in enumerate(cols)))


# ---------------------------------------------------------------- stages
def load_stages(path):
    """Rows of a _stages.csv as dicts with t0/t1 (epoch s) and, for sniff_host stages, frame numbers."""
    out = []
    for r in csv.DictReader(open(path, newline="")):
        if not r.get("start_time") or not r.get("end_time"):
            continue
        out.append({
            "stage": r["stage"], "name": r["name"],
            "t0": parse_time(r["start_time"]), "t1": parse_time(r["end_time"]),
            "first": int(r["first_frame"]) if r.get("first_frame") else None,
            "last": int(r["last_frame"]) if r.get("last_frame") else None,
        })
    return out


# Stage kinds, from the stage name (case-insensitive substrings), checked in this order:
#   control  you move, but the camera cannot see it            control / away / outside / behind
#   present  you are in view but standing still                 present
#   empty    nobody in view, nothing moves (the baseline)       empty / still
#   motion   you move in front of the camera                    motion / wave / walk / dance / move
#   other    anything else (lighting, settle): listed per stage, left out of the comparisons
# "still" counts as empty so older runs (still_1, ...) still work. If some of their still stages
# had you in view, mark them with --kind still_3=present (see add_kind_args).
KINDS = ("empty", "present", "motion", "control", "other")
EMPTY_WORDS = ("empty", "still")
PRESENT_WORDS = ("present",)
MOTION_WORDS = ("motion", "wave", "walk", "dance", "move")
CONTROL_WORDS = ("control", "away", "outside", "behind")


def stage_kind(name, empty=None, motion=None, present=None, overrides=None):
    """Kind of a stage from its name (see the table above). overrides = {stage name: kind}."""
    if overrides and name in overrides:
        return overrides[name]
    n = name.lower()
    for kind, words in (("control", CONTROL_WORDS), ("present", present or PRESENT_WORDS),
                        ("empty", empty or EMPTY_WORDS), ("motion", motion or MOTION_WORDS)):
        if any(w in n for w in words):
            return kind
    return "other"


def add_kind_args(ap):
    """Command-line options that control stage_kind; use with kind_from_args."""
    ap.add_argument("--empty", "--still", dest="empty", nargs="+",
                    help="words marking empty-room stages (default: empty still)")
    ap.add_argument("--present", nargs="+", help="words marking person-in-view-but-still stages (default: present)")
    ap.add_argument("--motion", nargs="+", help="words marking motion stages (default: motion wave walk dance move)")
    ap.add_argument("--kind", nargs="+", default=[], metavar="STAGE=KIND",
                    help=f"set the kind of named stages, e.g. --kind still_3=present still_4=present "
                         f"(kinds: {', '.join(KINDS)})")


def kind_from_args(args):
    """stage name -> kind, using the options from add_kind_args."""
    overrides = {}
    for item in args.kind:
        name, _, kind = item.partition("=")
        if kind not in KINDS:
            sys.exit(f"--kind {item}: kind must be one of {', '.join(KINDS)}")
        overrides[name] = kind
    return lambda name: stage_kind(name, args.empty, args.motion, args.present, overrides)


# ---------------------------------------------------------------- pcap (over the air)
def read_uplink(pcap, cam, tshark=None, min_pkt=120):
    """Camera -> router data frames from the pcap, de-duplicated.

    Returns (packets, info). packets = list of dicts n, t, len, seq, tid (sorted by time).
      - only Data / QoS Data frames transmitted by the camera to a unicast receiver
      - a frame whose (TID, sequence number) was already captured is a retransmission -> dropped
        (a retry whose first copy the ESP32 missed is kept: it is the only copy we have)
      - frames shorter than min_pkt bytes (TCP ACKs, keep-alives) are dropped
    """
    exe = find_exe(tshark, "tshark", [r"C:\Program Files\Wireshark\tshark.exe",
                                      r"C:\Program Files (x86)\Wireshark\tshark.exe"])
    if not exe:
        sys.exit("tshark not found: install Wireshark or pass --tshark PATH")
    cam = norm_mac(cam)
    cmd = [exe, "-r", pcap, "-T", "fields", "-E", "separator=,", "-E", "occurrence=f",
           "-Y", f"wlan.ta == {cam} && wlan.fc.type == 2"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    pk, seen = [], {}
    info = Counter()
    for line in out.splitlines():
        v = dict(zip(TSHARK_FIELDS, line.split(",")))
        if v["wlan.fc.subtype"] not in ("0", "8") or is_group(v["wlan.ra"]):
            info["not_unicast_data"] += 1
            continue
        length = int(v["frame.len"]) - RADIOTAP_LEN
        if length < min_pkt:
            info["short"] += 1
            continue
        tid = v["wlan.qos.tid"] or "-"
        seq = int(v["wlan.seq"]) if v["wlan.seq"] else None
        if seq is not None:
            recent = seen.setdefault(tid, deque(maxlen=256))   # seq numbers wrap at 4096: keep recent ones only
            if seq in recent:
                info["retransmission"] += 1
                continue
            recent.append(seq)
        pk.append({"n": int(v["frame.number"]), "t": float(v["frame.time_epoch"]), "len": length,
                   "seq": seq, "tid": tid})
        info["kept"] += 1
    pk.sort(key=lambda p: p["t"])
    return pk, info


def bursts_from_packets(pk, gap_ms=8.0, fill_missing=True, min_burst=400):
    """Group packets closer than gap_ms into bursts. One burst ~ one encoded video frame.

    fill_missing: frames the ESP32 did not capture show up as skipped sequence numbers. Inside a
    burst, each skipped number is counted as one packet of the burst's median length.
    Bursts smaller than min_burst bytes (audio, control traffic) are dropped.

    Returns list of dicts: t (first packet), t_end, n_pkts, bytes (captured), missing, est_bytes.
    """
    gap = gap_ms / 1000
    bursts, cur = [], []

    def close(c):
        lens = [p["len"] for p in c]
        missing = 0
        if fill_missing:
            last = {}
            for p in c:
                s = p["seq"]
                if s is None:
                    continue
                if p["tid"] in last:
                    d = (s - last[p["tid"]]) % 4096
                    if 1 < d < 64:          # small forward jump = frames missed; large = reordering
                        missing += d - 1
                last[p["tid"]] = s
        b = sum(lens)
        bursts.append({"t": c[0]["t"], "t_end": c[-1]["t"], "n_pkts": len(c), "bytes": b,
                       "missing": missing, "est_bytes": b + missing * st.median(lens)})

    for p in pk:
        if cur and p["t"] - cur[-1]["t"] > gap:
            close(cur)
            cur = []
        cur.append(p)
    if cur:
        close(cur)
    return [b for b in bursts if b["est_bytes"] >= min_burst]


def flag_key_bursts(bursts, k=3.0, window=31):
    """Mark bursts much bigger than the running median of their neighbours as likely key frames
    (Stage 4 style). Adds b['key'] = True/False. Uses est_bytes."""
    sizes = [b["est_bytes"] for b in bursts]
    h = window // 2
    for i, b in enumerate(bursts):
        nb = sizes[max(0, i - h): i] + sizes[i + 1: i + 1 + h]
        b["key"] = bool(nb) and b["est_bytes"] > k * st.median(nb)
    return bursts


# ---------------------------------------------------------------- ffprobe log (receiver side)
def load_frames(path):
    """Frames CSV from record_rtsp.py -> list of dicts t (PC epoch s), size, key, pts.

    Each line holds arrival (PC time when the line was read) and pts (stream time). ffprobe's
    output is buffered, so arrival is late by a varying amount. The real offset between stream
    time and PC time is the smallest arrival - pts seen (the least-delayed line), the same trick
    sniff_host.py uses for the ESP32 clock. t = pts + that offset."""
    rows = []
    for r in csv.DictReader(open(path, newline="")):
        pts = r["pts_time"] if r["pts_time"] not in ("", "N/A") else r["dts_time"]
        if pts in ("", "N/A"):
            continue
        rows.append({"arrival": float(r["arrival"]), "pts": float(pts), "size": int(r["size"]),
                     "key": "K" in r["flags"]})
    if not rows:
        sys.exit(f"no frames in {path}")
    back = sum(1 for a, b in zip(rows, rows[1:]) if b["pts"] < a["pts"] - 1.0)
    if back:
        print(f"WARNING: stream time jumped backwards {back} times in {path} (stream restarted?); "
              f"timing after a jump may be off", file=sys.stderr)
    off = min(r["arrival"] - r["pts"] for r in rows)
    for r in rows:
        r["t"] = r["pts"] + off
    rows.sort(key=lambda r: r["t"])
    return rows


def in_stage(items, s):
    return [x for x in items if s["t0"] <= x["t"] < s["t1"]]


def stage_packets(pk, s):
    """Packets of one sniff_host stage: by frame number when the stages CSV has them (exact),
    else by time."""
    if s["first"] is not None:
        return [p for p in pk if s["first"] <= p["n"] <= s["last"]]
    return in_stage(pk, s)
