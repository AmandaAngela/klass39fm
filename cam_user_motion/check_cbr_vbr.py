#!/usr/bin/env python3
"""
Does the camera's encoder hold its bitrate constant (CBR) or let it follow the scene (VBR)?

Why it matters: Stage 6 expects inter-frame (P-frame) sizes to rise when someone moves in view.
A constant bitrate does NOT rule that out: a rate-controlled encoder can keep the total per GOP
fixed and move bits from the key frame to the P-frames when there is motion (seen on the
TP-Link, 2026-11-22: total 1.09x, P-frames 1.41x, key frames ~0.5x). So the script reports two
separate things:

1. Bitrate (total traffic). Measured over windows of one GOP (key frame interval), so each
   window holds exactly one key frame.
     ratio = median window bitrate in motion stages / median in empty-room stages
       ratio >= 1.30   -> VBR: the total bitrate follows the scene
       ratio <= 1.15   -> constant bitrate: the total is held (near) constant
       in between      -> unclear (repeat with stronger motion / longer stages)
   A capped-VBR encoder (VBR up to a maximum) also reads as VBR here.

2. How the bits are split between frame types (what Stage 4 + 6 use):
     P ratio = median P-frame size in motion / in the empty room      (Stage 6 signal)
     I ratio = median key frame size in motion / in the empty room
   "bits shift from key frames to P-frames" is reported when the bitrate is constant, the
   P ratio >= --p-ratio (1.20) and the I ratio <= --i-ratio (0.85).
   Stage 6 signal: "present" when the P ratio >= --p-ratio and a one-sided Mann-Whitney test of
   P-frame sizes (motion > empty) gives p < 0.01, else "weak or absent". Neighbouring frames are
   not independent, so the p-value is optimistic; treat the ratio as the main number.

Stage kinds come from the stage names (see common.py): empty (nobody in view, the baseline),
present (you in view, standing still), motion, control (you move out of view), other (lighting,
settle: listed only). Ratios are to the empty room. Older runs named every still stage still_N;
mark the ones where you were in view with --kind still_3=present still_4=present.

Input, one or both:
  --frames FILE    record_rtsp.py frames CSV (exact frame sizes from the stream: best)
  --pcap FILE --cam MAC   sniff_host.py capture (over-the-air estimate from bursts)
and the stage times:
  --stages FILE    _stages.csv from sniff_host.py --stages or record_rtsp.py --stages
                   (default: the _stages.csv next to the pcap or frames file)

Usage (PowerShell):
  python check_cbr_vbr.py --frames datasets\\tplink_20261123_101500_frames.csv
  python check_cbr_vbr.py --pcap ..\\esp32c5_sniffer\\host\\datasets\\run6_x.pcap --cam 60:15:6f:2e:63:91
Prints a table per stage and the verdict; saves <input>_cbrvbr.csv.
"""
import argparse
import os
import statistics as st
import sys

import common as C


def windows(items, t0, t1, w, size_key):
    """Bitrate (kbit/s) of each full window of w seconds between t0 and t1."""
    out = []
    n = int((t1 - t0) // w)
    for i in range(n):
        a, b = t0 + i * w, t0 + (i + 1) * w
        out.append(sum(x[size_key] for x in items if a <= x["t"] < b) * 8 / w / 1000)
    return out


def analyse(label, items, stages, size_key, window, args, kind_of):
    """items: list with t, <size_key>, key. One source (ffprobe frames or air bursts)."""
    keys_t = [x["t"] for x in items if x["key"]]
    gaps = [b - a for a, b in zip(keys_t, keys_t[1:]) if b - a > 0.2]
    gop = C.med(gaps)
    w = window or (round(gop * 2) / 2 if gop == gop and gop >= 0.5 else 2.0)   # nearest 0.5 s
    w = max(w, 0.5)
    print(f"\n== {label}: GOP (key frame interval) median {gop:.2f} s -> window {w:g} s")

    kinds = ("empty", "present", "motion", "control")
    rows = []
    win_k, p_k, i_k = ({k: [] for k in kinds} for _ in range(3))
    for s in stages:
        fr = C.in_stage(items, s)
        dur = s["t1"] - s["t0"]
        if not fr or dur <= 0:
            print(f"   stage {s['stage']} {s['name']}: no frames, skipped")
            continue
        kind = kind_of(s["name"])
        wins = windows(fr, s["t0"], s["t1"], w, size_key)
        p = [x[size_key] for x in fr if not x["key"]]
        i = [x[size_key] for x in fr if x["key"]]
        if kind in win_k:
            win_k[kind] += wins
            p_k[kind] += p
            i_k[kind] += i
        mean_w = st.mean(wins) if wins else float("nan")
        rows.append({
            "source": label, "stage": s["stage"], "name": s["name"], "kind": kind,
            "duration_s": dur, "frames": len(fr), "fps": len(fr) / dur,
            "kbit_s": sum(x[size_key] for x in fr) * 8 / dur / 1000,
            "windows": len(wins), "win_kbit_med": C.med(wins),
            "win_cv": (st.pstdev(wins) / mean_w) if len(wins) > 1 and mean_w else float("nan"),
            "key_frames": len(i), "I_B_med": C.med(i), "P_B_med": C.med(p), "P_B_p90": C.pct(p, 90),
        })

    cols = [("stage", 5, ""), ("name", 22, ""), ("kind", 8, ""), ("fps", 6, ".1f"), ("kbit_s", 8, ".0f"),
            ("windows", 8, "d"), ("win_kbit_med", 13, ".0f"), ("win_cv", 7, ".2f"), ("key_frames", 11, "d"),
            ("I_B_med", 8, ".0f"), ("P_B_med", 8, ".0f"), ("P_B_p90", 8, ".0f")]
    C.print_table(rows, cols, left=3)

    empty, motion = win_k["empty"], win_k["motion"]
    if len(empty) < 2 or len(motion) < 2:
        print(f"   not enough empty/motion windows (empty {len(empty)}, motion {len(motion)}): need stage names "
              f"with an empty-room word and a motion word (see --empty/--motion/--kind)", file=sys.stderr)
        return rows, None
    cv = lambda v: st.pstdev(v) / st.mean(v) if st.mean(v) else float("nan")

    def rel(d, a, b="empty"):
        return C.med(d[a]) / C.med(d[b]) if d[a] and d[b] and C.med(d[b]) else float("nan")
    try:
        from scipy.stats import mannwhitneyu
        mw = lambda a, b: mannwhitneyu(a, b, alternative="greater").pvalue if a and b else float("nan")
    except ImportError:
        mw = lambda a, b: float("nan")
    ratio, p_ratio, i_ratio = rel(win_k, "motion"), rel(p_k, "motion"), rel(i_k, "motion")
    shown = [k for k in kinds if win_k[k]]

    print(f"\n   1. bitrate (one-GOP windows), kbit/s   (ratios are to the empty room)")
    for k in shown:
        v = win_k[k]
        r = "" if k == "empty" else f"   ratio {rel(win_k, k):.2f}"
        print(f"      {k:8s}: n={len(v):3d}  median {C.med(v):7.0f}  CV {cv(v):.2f}{r}")
    pval = mw(motion, empty)
    print(f"      Mann-Whitney (motion > empty) p = {pval:.2g}")

    print(f"\n   2. frame sizes, median bytes " + "".join(f"{k:>10s}" for k in shown))
    for name, d in (("key frames (I)", i_k), ("P-frames", p_k)):
        print(f"      {name:23s}" + "".join(f"{C.med(d[k]):10.0f}" for k in shown))
        print(f"      {'  ratio to empty':23s}" + "".join(f"{rel(d, k):10.2f}" for k in shown))
    p_pval = mw(p_k["motion"], p_k["empty"])
    print(f"      Mann-Whitney P-frames (motion > empty) p = {p_pval:.2g}")
    if p_k["present"]:
        print(f"      P-frames motion / person standing still = {rel(p_k, 'motion', 'present'):.2f}   "
              f"(p = {mw(p_k['motion'], p_k['present']):.2g})")

    if ratio >= args.vbr_ratio:
        verdict, why = "VBR", f"total bitrate rises {ratio:.2f}x with motion (vs empty room)"
    elif ratio <= args.cbr_ratio:
        verdict, why = "constant bitrate", f"total bitrate changes only {ratio:.2f}x between empty room and motion"
    else:
        verdict, why = "unclear", (f"ratio {ratio:.2f} is between {args.cbr_ratio} and {args.vbr_ratio}; "
                                   f"repeat with stronger/longer motion")
    shift = verdict == "constant bitrate" and p_ratio >= args.p_ratio and i_ratio <= args.i_ratio
    if shift:
        why += (f", but bits shift from key frames ({i_ratio:.2f}x) to P-frames ({p_ratio:.2f}x) "
                f"inside the same budget")
    signal = "present" if p_ratio >= args.p_ratio and p_pval < 0.01 else "weak or absent"
    print(f"\n   BITRATE ({label}): {verdict} - {why}")
    print(f"   STAGE 6 SIGNAL ({label}): {signal} - P-frames {p_ratio:.2f}x larger in motion than in the "
          f"empty room (threshold {args.p_ratio:g}x)")
    return rows, {"source": label, "verdict": verdict, "ratio": ratio, "p_ratio": p_ratio, "i_ratio": i_ratio,
                  "shift": shift, "signal": signal, "p_value": pval}


def main():
    ap = argparse.ArgumentParser(description="Check whether a camera encodes at constant or variable bitrate")
    ap.add_argument("--frames", help="record_rtsp.py _frames.csv")
    ap.add_argument("--pcap", help="sniff_host.py capture")
    ap.add_argument("--cam", help="camera MAC (needed with --pcap)")
    ap.add_argument("--stages", help="_stages.csv (default: next to the pcap, else next to the frames file)")
    ap.add_argument("--window", type=float, help="window length in s (default: one GOP)")
    ap.add_argument("--vbr-ratio", type=float, default=1.30, help="ratio at/above which = VBR (default 1.30)")
    ap.add_argument("--cbr-ratio", type=float, default=1.15, help="ratio at/below which = CBR-like (default 1.15)")
    ap.add_argument("--p-ratio", type=float, default=1.20,
                    help="P-frame motion/still ratio at/above which the Stage 6 signal counts (default 1.20)")
    ap.add_argument("--i-ratio", type=float, default=0.85,
                    help="key frame motion/still ratio at/below which key frames count as shrinking (default 0.85)")
    C.add_kind_args(ap)
    ap.add_argument("--burst-gap-ms", type=float, default=8.0, help="pcap: gap that ends a burst (default 8 ms)")
    ap.add_argument("--min-burst", type=int, default=400, help="pcap: ignore bursts below this many bytes")
    ap.add_argument("--key-k", type=float, default=3.0, help="pcap: burst > k x neighbour median = key frame")
    ap.add_argument("--tshark", help="path to tshark.exe")
    args = ap.parse_args()
    if not args.frames and not args.pcap:
        ap.error("give --frames and/or --pcap")
    if args.pcap and not args.cam:
        ap.error("--pcap needs --cam MAC")

    def guess(p, suffix):
        return p[: -len(suffix)] + "_stages.csv" if p and p.endswith(suffix) else None
    stages_csv = args.stages or next((g for g in (guess(args.pcap, ".pcap"), guess(args.frames, "_frames.csv"))
                                      if g and os.path.exists(g)), None)
    if not stages_csv:
        ap.error("no _stages.csv found next to the input; pass --stages")
    stages = C.load_stages(stages_csv)
    kind_of = C.kind_from_args(args)
    print(f"stages: {stages_csv} ({len(stages)} stages)", file=sys.stderr)

    all_rows, verdicts = [], []
    if args.frames:
        fr = C.load_frames(args.frames)
        # ffprobe time vs stage times: both PC clock. Stage boundaries by time.
        rows, v = analyse("ffprobe", fr, stages, "size", args.window, args, kind_of)
        all_rows += rows
        verdicts.append(v)
    if args.pcap:
        pk, info = C.read_uplink(args.pcap, args.cam, args.tshark)
        print(f"\npcap: camera uplink {dict(info)}")
        bursts = []
        for s in stages:          # bursts per stage (sniff_host records only during stages)
            b = C.bursts_from_packets(C.stage_packets(pk, s), args.burst_gap_ms, True, args.min_burst)
            for x in b:            # pin to the stage (pcap time can sit a few ms before the stage start)
                x["t"] = min(max(x["t"], s["t0"]), s["t1"] - 1e-6)
            bursts += C.flag_key_bursts(b, args.key_k)
        rows, v = analyse("air", bursts, stages, "est_bytes", args.window, args, kind_of)
        all_rows += rows
        verdicts.append(v)

    base = os.path.splitext(args.pcap or args.frames)[0]
    C.write_csv(base + "_cbrvbr.csv", all_rows)
    vs = [v for v in verdicts if v]
    if len(vs) == 2 and (vs[0]["verdict"], vs[0]["signal"]) != (vs[1]["verdict"], vs[1]["signal"]):
        print("\nNOTE: ffprobe and over-the-air results differ; trust ffprobe (exact sizes) and check "
              "the air capture for missed frames (compare_bursts.py).")


if __name__ == "__main__":
    main()
