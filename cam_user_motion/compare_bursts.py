#!/usr/bin/env python3
"""
How well do over-the-air bursts (ESP32 sniffer) reproduce the camera's real video frames (ffprobe)?

Record both at the same time:
  1. sniff_host.py --stages ...           (ESP32-C5, camera uplink on air, stage times)
  2. record_rtsp.py URL --secs ...        (laptop pulls the RTSP stream: exact frame sizes)
The laptop's RTSP stream travels camera -> router over Wi-Fi, so the sniffer sees the very
frames ffprobe logs. Close the camera app on phones meanwhile, so that is the only video stream.

Steps:
  burst sum  camera->router data frames (retransmissions removed) are grouped into bursts:
             a gap > --burst-gap-ms starts a new burst. Burst bytes = sum of 802.11 frame lengths,
             plus an estimate for frames the ESP32 missed (skipped sequence numbers x median length).
             Bursts > --key-k x the median of their neighbours are flagged as key frames (Stage 4).
  align      both clocks are the PC clock, but ffprobe/Wi-Fi add some delay. The offset is found by
             cross-correlating the two byte-vs-time series (10 ms bins) within +-max-lag.
  match      each ffprobe frame is paired with the nearest unused burst within --tol-ms.

Reports:
  - match rate (frames with a burst / bursts with a frame), frames split into several bursts
  - size agreement: air_bytes = a x frame_bytes + b fit, Pearson r, Spearman rho, median error
  - key frame flag: precision / recall of the burst flag vs ffprobe's K flag
  - per stage: P-frame (non-key) median size from ffprobe and from air, and the motion/empty-room ratio
    from each, i.e. whether the Stage 6 movement signal survives the trip through the sniffer

Usage (PowerShell):
  python compare_bursts.py --pcap ..\\esp32c5_sniffer\\host\\datasets\\run6_20261123_101455.pcap `
      --frames datasets\\tplink_20261123_101500_frames.csv --cam 60:15:6f:2e:63:91 --plot
Saves next to the pcap: _compare_frames.csv, _compare_stages.csv, (with --plot) _compare.png
Needs numpy (scipy, matplotlib optional).
"""
import argparse
import os
import statistics as st
import sys

import numpy as np

import common as C


def align(frames, bursts, bin_s=0.010, max_lag=3.0):
    """Offset (s) to add to ffprobe times so they line up with burst times."""
    t0 = max(frames[0]["t"], bursts[0]["t"]) - max_lag
    t1 = min(frames[-1]["t"], bursts[-1]["t"]) + max_lag
    if t1 <= t0:
        sys.exit("the pcap and the frames file do not overlap in time (recorded at the same time?)")
    n = int((t1 - t0) / bin_s) + 1
    a, b = np.zeros(n), np.zeros(n)
    for f in frames:
        i = int((f["t"] - t0) / bin_s)
        if 0 <= i < n:
            a[i] += f["size"]
    for x in bursts:
        i = int((x["t"] - t0) / bin_s)
        if 0 <= i < n:
            b[i] += x["est_bytes"]
    k = np.ones(3) / 3                    # tolerate a bin of jitter
    a, b = np.convolve(a, k, "same"), np.convolve(b, k, "same")
    a, b = a - a.mean(), b - b.mean()
    m = int(max_lag / bin_s)
    best, best_c = 0, -np.inf
    for lag in range(-m, m + 1):          # compare a shifted by lag bins with b
        if lag >= 0:
            c = float(np.dot(a[: n - lag], b[lag:]))
        else:
            c = float(np.dot(a[-lag:], b[: n + lag]))
        if c > best_c:
            best, best_c = lag, c
    norm = float(np.sqrt(np.dot(a, a) * np.dot(b, b))) or 1.0
    return best * bin_s, best_c / norm


def match(frames, bursts, tol):
    """Greedy one-to-one: each frame (in time order) takes the nearest unused burst within tol."""
    times = np.array([b["t"] for b in bursts])
    used = np.zeros(len(bursts), bool)
    pairs = []
    for f in frames:
        lo, hi = np.searchsorted(times, f["ta"] - tol), np.searchsorted(times, f["ta"] + tol, "right")
        cand = [j for j in range(lo, hi) if not used[j]]
        f["n_near"] = hi - lo
        if cand:
            j = min(cand, key=lambda j: abs(times[j] - f["ta"]))
            used[j] = True
            pairs.append((f, bursts[j]))
            f["burst"] = bursts[j]
        else:
            f["burst"] = None
    return pairs, used


def spearman(x, y):
    try:
        from scipy.stats import spearmanr
        return float(spearmanr(x, y).statistic)
    except ImportError:
        rx, ry = np.argsort(np.argsort(x)), np.argsort(np.argsort(y))
        return float(np.corrcoef(rx, ry)[0, 1])


def main():
    ap = argparse.ArgumentParser(description="Compare over-the-air bursts with ffprobe's frame sizes")
    ap.add_argument("--pcap", required=True, help="sniff_host.py capture")
    ap.add_argument("--frames", required=True, help="record_rtsp.py _frames.csv recorded at the same time")
    ap.add_argument("--cam", required=True, help="camera MAC")
    ap.add_argument("--stages", help="_stages.csv (default: next to the pcap, if present)")
    ap.add_argument("--burst-gap-ms", type=float, default=8.0, help="gap that ends a burst (default 8 ms)")
    ap.add_argument("--min-burst", type=int, default=400, help="ignore bursts below this many bytes (default 400)")
    ap.add_argument("--no-fill", action="store_true", help="do not add estimated bytes for missed frames")
    ap.add_argument("--key-k", type=float, default=3.0, help="burst > k x neighbour median = key frame (default 3)")
    ap.add_argument("--tol-ms", type=float, help="max frame-burst time difference (default 40%% of frame interval)")
    ap.add_argument("--max-lag", type=float, default=3.0, help="search the clock offset within +- this (s)")
    C.add_kind_args(ap)
    ap.add_argument("--plot", action="store_true", help="save a PNG (needs matplotlib)")
    ap.add_argument("--tshark", help="path to tshark.exe")
    args = ap.parse_args()
    kind_of = C.kind_from_args(args)

    stages_csv = args.stages or (args.pcap[:-5] + "_stages.csv")
    stages = C.load_stages(stages_csv) if os.path.exists(stages_csv) else []
    frames = C.load_frames(args.frames)
    pk, info = C.read_uplink(args.pcap, args.cam, args.tshark)
    if not pk:
        sys.exit(f"no data frames from {args.cam} in {args.pcap}")
    groups = [C.stage_packets(pk, s) for s in stages] if stages else [pk]
    bursts = []
    for g in groups:                        # sniff_host records only during stages: no burst spans a pause
        bursts += C.flag_key_bursts(C.bursts_from_packets(g, args.burst_gap_ms, not args.no_fill, args.min_burst),
                                    args.key_k)
    bursts.sort(key=lambda b: b["t"])
    print(f"ffprobe: {len(frames)} frames ({sum(f['key'] for f in frames)} key)   "
          f"air: {len(pk)} packets {dict(info)} -> {len(bursts)} bursts", file=sys.stderr)

    # ---- align + match (only frames inside the pcap's time span)
    offset, corr = align(frames, bursts, max_lag=args.max_lag)
    for f in frames:
        f["ta"] = f["t"] + offset
    span = [(g[0]["t"], g[-1]["t"]) for g in groups if g]
    frames = [f for f in frames if any(a - 0.05 <= f["ta"] <= b + 0.05 for a, b in span)]
    if len(frames) < 10:
        sys.exit("fewer than 10 ffprobe frames fall inside the pcap's recorded stages")
    ivl = C.med([b["ta"] - a["ta"] for a, b in zip(frames, frames[1:]) if b["ta"] > a["ta"]])
    tol = (args.tol_ms / 1000) if args.tol_ms else min(0.4 * ivl, 0.030)
    pairs, used = match(frames, bursts, tol)
    print(f"\nclock offset ffprobe -> air: {offset * 1000:+.0f} ms (correlation {corr:.2f})   "
          f"frame interval {ivl * 1000:.0f} ms ({1 / ivl:.1f} fps)   match tolerance {tol * 1000:.0f} ms")
    if corr < 0.3:
        print("WARNING: weak correlation - wrong camera MAC, another stream on air, or many missed frames?")

    nb_in = sum(1 for b in bursts if any(a - 0.05 <= b["t"] <= c + 0.05 for a, c in span))
    split = sum(1 for f in frames if f["n_near"] > 1)
    um_b = [b["est_bytes"] for j, b in enumerate(bursts) if not used[j]]
    print(f"\n== matching")
    print(f"   frames with a burst : {len(pairs)}/{len(frames)} = {len(pairs) / len(frames):.1%}")
    print(f"   bursts with a frame : {len(pairs)}/{nb_in} = {len(pairs) / max(nb_in, 1):.1%}"
          + (f"   (unmatched bursts: median {C.med(um_b):.0f} B - audio, control traffic or split frames)" if um_b else ""))
    print(f"   frames with >1 burst within tolerance: {split} (split frames; try a larger --burst-gap-ms)")
    miss = sum(b["missing"] for _, b in pairs)
    pk_n = sum(b["n_pkts"] for _, b in pairs)
    print(f"   packets missed by the ESP32 inside matched bursts: {miss}/{miss + pk_n} = "
          f"{miss / max(miss + pk_n, 1):.1%}")

    # ---- size agreement
    x = np.array([f["size"] for f, _ in pairs], float)
    y = np.array([b["est_bytes"] for _, b in pairs], float)
    y_raw = np.array([b["bytes"] for _, b in pairs], float)
    print(f"\n== size (matched pairs)")
    for name, yy in (("est (with missed-frame fill)", y), ("captured bytes only", y_raw)):
        a, b = np.polyfit(x, yy, 1)
        r = float(np.corrcoef(x, yy)[0, 1])
        err = np.median(np.abs((yy - b) / a - x) / x)
        print(f"   {name:29s}: air = {a:.3f} x frame + {b:5.0f} B   Pearson r {r:.3f}   "
              f"Spearman {spearman(x, yy):.3f}   median |error| after fit {err:.1%}")
    kx = np.array([f["key"] for f, _ in pairs])
    if kx.any() and (~kx).any():
        print(f"   overhead ratio air/frame: key frames {np.median(y[kx] / x[kx]):.3f}, "
              f"P-frames {np.median(y[~kx] / x[~kx]):.3f}")

    # ---- key frame flag
    kb = np.array([b["key"] for _, b in pairs])
    tp, fp, fn = int((kx & kb).sum()), int((~kx & kb).sum()), int((kx & ~kb).sum())
    print(f"\n== key frame flag (burst > {args.key_k:g} x neighbour median)")
    print(f"   precision {tp / max(tp + fp, 1):.1%}   recall {tp / max(tp + fn, 1):.1%}   "
          f"(true key {int(kx.sum())}, flagged {int(kb.sum())}, both {tp})")

    # ---- per stage: does the motion signal in P-frame sizes survive over the air?
    stage_rows = []
    if stages:
        for s in stages:
            if s["first"] is None:
                continue
            g = C.stage_packets(pk, s)
            if not g:
                continue
            t0, t1 = g[0]["t"], g[-1]["t"]
            fr = [f for f in frames if t0 <= f["ta"] <= t1]
            bu = [b for b in bursts if t0 <= b["t"] <= t1]
            dur = t1 - t0
            fp_ = [f["size"] for f in fr if not f["key"]]
            bp = [b["est_bytes"] for b in bu if not b["key"]]
            stage_rows.append({
                "stage": s["stage"], "name": s["name"], "kind": kind_of(s["name"]),
                "ff_fps": len(fr) / dur if dur else float("nan"), "air_bursts_s": len(bu) / dur if dur else float("nan"),
                "ff_P_med": C.med(fp_), "air_P_med": C.med(bp),
                "ff_P_p90": C.pct(fp_, 90), "air_P_p90": C.pct(bp, 90),
                "matched": f"{sum(1 for f in fr if f['burst'])}/{len(fr)}",
            })
        print("\n== per stage: P-frame (non-key) sizes, bytes")
        C.print_table(stage_rows, [("stage", 5, ""), ("name", 22, ""), ("kind", 8, ""), ("ff_fps", 7, ".1f"),
                                   ("air_bursts_s", 13, ".1f"), ("ff_P_med", 9, ".0f"), ("air_P_med", 10, ".0f"),
                                   ("ff_P_p90", 9, ".0f"), ("air_P_p90", 10, ".0f"), ("matched", 10, "")], left=3)
        def pooled(items, tkey, skey, kind):
            return [x[skey] for s in stages if s["first"] is not None
                    and kind_of(s["name"]) == kind
                    for x in items if not x["key"] and in_span(x[tkey], pk, s)]

        for src, items, tkey, skey in (("ffprobe", frames, "ta", "size"), ("air", bursts, "t", "est_bytes")):
            pk_ = {k: pooled(items, tkey, skey, k) for k in ("empty", "present", "motion", "control")}
            if not (pk_["empty"] and pk_["motion"]):
                continue
            base_med = C.med(pk_["empty"])
            line = f"   {src:8s}: P-frame median vs empty room:"
            for k in ("motion", "present", "control"):
                if pk_[k]:
                    line += f"  {k} {C.med(pk_[k]) / base_med:.2f}x"
            try:
                from scipy.stats import mannwhitneyu
                line += f"   Mann-Whitney motion > empty p = {mannwhitneyu(pk_['motion'], pk_['empty'], alternative='greater').pvalue:.2g}"
            except ImportError:
                pass
            print(line)

    # ---- save
    base = args.pcap[:-5]
    C.write_csv(base + "_compare_frames.csv", [{
        "t_air": f["ta"], "ff_size": f["size"], "ff_key": int(f["key"]),
        "air_t": f["burst"]["t"] if f["burst"] else "", "air_bytes": f["burst"]["bytes"] if f["burst"] else "",
        "air_est_bytes": f["burst"]["est_bytes"] if f["burst"] else "",
        "air_missing": f["burst"]["missing"] if f["burst"] else "",
        "air_key": int(f["burst"]["key"]) if f["burst"] else "", "bursts_near": f["n_near"]} for f in frames])
    C.write_csv(base + "_compare_stages.csv", stage_rows)
    if args.plot:
        plot(base + "_compare.png", frames, bursts, pairs, stages, pk, kind_of)


_span_cache = {}


def in_span(t, pk, s):
    k = s["stage"]
    if k not in _span_cache:
        g = C.stage_packets(pk, s)
        _span_cache[k] = (g[0]["t"], g[-1]["t"]) if g else (1, 0)
    a, b = _span_cache[k]
    return a <= t <= b


def plot(path, frames, bursts, pairs, stages, pk, kind_of):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed: no plot", file=sys.stderr)
        return
    t0 = frames[0]["ta"]
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 8), gridspec_kw={"height_ratios": [2, 1]})
    colors = {"empty": "#dddddd", "present": "#e6dcef", "motion": "#ffd9a8", "control": "#c9dcf5"}
    for s in stages:
        if s["first"] is None:
            continue
        g = C.stage_packets(pk, s)
        if g:
            kind = kind_of(s["name"])
            ax1.axvspan(g[0]["t"] - t0, g[-1]["t"] - t0, color=colors.get(kind, "#f4f4f4"), zorder=0)
            ax1.text(g[0]["t"] - t0, 1.0, s["name"], transform=ax1.get_xaxis_transform(), fontsize=7, va="top")
    ax1.plot([f["ta"] - t0 for f in frames], [f["size"] for f in frames], ".", ms=3, label="ffprobe frame size")
    ax1.plot([b["t"] - t0 for b in bursts], [b["est_bytes"] for b in bursts], ".", ms=2, alpha=.6,
             label="air burst (est. bytes)")
    ax1.set_yscale("log")
    ax1.set_xlabel("time (s)")
    ax1.set_ylabel("bytes")
    ax1.legend(loc="upper right")
    x = [f["size"] for f, _ in pairs]
    y = [b["est_bytes"] for _, b in pairs]
    k = [f["key"] for f, _ in pairs]
    ax2.scatter(x, y, s=4, c=["C3" if v else "C0" for v in k])
    lim = [min(x + y), max(x + y)]
    ax2.plot(lim, lim, "k--", lw=.8)
    ax2.set_xscale("log")
    ax2.set_yscale("log")
    ax2.set_xlabel("ffprobe frame size (B)  [red = key frame]")
    ax2.set_ylabel("matched air burst (B)")
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    print(f"saved {path}", file=sys.stderr)


if __name__ == "__main__":
    main()
