#!/usr/bin/env python3
"""
Per-stage 802.11 header statistics for a sniff_host.py --stages capture.

Inputs : the .pcap and its _stages.csv (written by sniff_host.py --stages)
Needs  : Wireshark installed (uses its tshark.exe to read the pcap). Python standard library only.
Does   : describes the traffic of each stage. It does NOT classify devices.

Usage (PowerShell):
  python analyze_stages.py datasets\\run4_20261121_193606.pcap --mac 60:15:6f:2e:63:91=camera --mac 70:15:fb:08:b2:5e=laptop

  The _stages.csv next to the pcap is found automatically (or pass --stages FILE).
  The router is detected automatically (the most common BSSID) and labelled "router".

Prints two tables and saves them next to the pcap:
  <pcap>_links.csv   one row per stage and link (who -> whom):
      frames, frames/s, kB/s           how much traffic
      len_med, len_p10, len_p90        802.11 frame length in bytes (FCS excluded), median / 10th / 90th percentile
      pct_over_1000B                   share of frames longer than 1000 bytes
      retry, pwr_mgmt, more_data       share of frames with that Frame Control flag set
      gap_med_ms, gap_p90_ms           time between consecutive frames of this link
      rssi_med                         signal strength at the ESP32 (dBm)
      seq_missing                      share of sequence numbers skipped between captured data frames,
                                       i.e. frames sent on air that the ESP32 did not capture
      types, tids                      frame type/subtype counts, QoS TID counts
  <pcap>_timing.csv  one row per stage and data flow between a listed device and the router:
      kB/s, active_s                   bytes per second; seconds (of the stage) with any traffic
      cv_per_s                         std dev / mean of bytes per second (0 = perfectly steady, >1 = bursty)
      bursts_per_s                     groups of frames separated by more than --burst-gap-ms
      burst_kB_med/p90/max             size of those groups
      idle_gap_p90_ms                  90th percentile of the gaps between bursts
      upload_share                     share of the device's data bytes that it sent (vs received)
"""
import argparse
import csv
import os
import shutil
import statistics as st
import subprocess
import sys
from collections import Counter, defaultdict

RADIOTAP_LEN = 14          # sniff_host.py writes a 14-byte radiotap header before each frame
FIELDS = ["frame.number", "frame.time_epoch", "frame.len", "radiotap.dbm_antsignal",
          "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.retry", "wlan.fc.pwrmgt", "wlan.fc.moredata",
          "wlan.ra", "wlan.ta", "wlan.bssid", "wlan.seq", "wlan.qos.tid"]
TYPE_NAMES = {("0", "4"): "probe_req", ("0", "5"): "probe_resp", ("0", "8"): "beacon", ("0", "13"): "action",
              ("2", "0"): "data", ("2", "4"): "null", ("2", "8"): "qos_data", ("2", "12"): "qos_null"}


def find_tshark(explicit):
    for c in (explicit, shutil.which("tshark"), r"C:\Program Files\Wireshark\tshark.exe",
              r"C:\Program Files (x86)\Wireshark\tshark.exe"):
        if c and os.path.exists(c):
            return c
    sys.exit("tshark not found: install Wireshark or pass --tshark PATH")


def read_pcap(tshark, pcap):
    cmd = [tshark, "-r", pcap, "-T", "fields", "-E", "separator=,", "-E", "occurrence=f"]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    rows = []
    for line in out.splitlines():
        v = dict(zip(FIELDS, line.split(",")))
        v["n"] = int(v["frame.number"])
        v["t"] = float(v["frame.time_epoch"])
        v["len"] = int(v["frame.len"]) - RADIOTAP_LEN
        rows.append(v)
    return rows


def pct(values, p):
    v = sorted(values)
    return v[min(len(v) - 1, int(p / 100 * len(v)))] if v else ""


def is_group(mac):
    return bool(mac) and int(mac[:2], 16) & 1


def seq_missing(frames):
    """Share of sequence numbers skipped between consecutive captured data frames (per QoS TID).
    Only QoS/plain data frames are used: Null frames do not number themselves like data does."""
    by_tid = defaultdict(list)
    for r in frames:
        if r["wlan.fc.type"] == "2" and r["wlan.fc.subtype"] in ("0", "8") and r["wlan.seq"]:
            by_tid[r["wlan.qos.tid"]].append(int(r["wlan.seq"]))
    seen = missed = 0
    for seqs in by_tid.values():
        for a, b in zip(seqs, seqs[1:]):
            d = (b - a) % 4096
            if d == 0:
                continue                    # retransmission of the same frame
            if d < 2048:                    # (a huge jump is treated as reordering, not loss)
                missed += d - 1
            seen += 1
    return missed / (missed + seen) if seen else ""


def fmt(v, spec):
    return format(v, spec) if isinstance(v, (int, float)) else str(v)


def main():
    ap = argparse.ArgumentParser(description="Per-stage 802.11 header statistics for a sniff_host.py capture")
    ap.add_argument("pcap")
    ap.add_argument("--stages", help="the _stages.csv (default: next to the pcap)")
    ap.add_argument("--mac", action="append", default=[], metavar="MAC=NAME", help="name a device (repeatable)")
    ap.add_argument("--burst-gap-ms", type=float, default=5.0, help="gap that separates two bursts (default 5 ms)")
    ap.add_argument("--tshark", help="path to tshark.exe")
    args = ap.parse_args()

    stages_csv = args.stages or args.pcap[:-5] + "_stages.csv"
    stages = list(csv.DictReader(open(stages_csv)))
    names = {}
    for m in args.mac:
        mac, _, name = m.partition("=")
        names[mac.lower().replace("-", ":")] = name or mac
    rows = read_pcap(find_tshark(args.tshark), args.pcap)
    bssid = Counter(r["wlan.bssid"] for r in rows if r["wlan.bssid"] and not is_group(r["wlan.bssid"])).most_common(1)
    if bssid and bssid[0][0] not in names:
        names[bssid[0][0]] = "router"
    router = bssid[0][0] if bssid else None
    label = lambda m: names.get(m, "group" if is_group(m) else (m or "?"))
    print(f"{len(rows)} frames, {len(stages)} stages, router = {router}", file=sys.stderr)
    for s in stages:
        if not s["first_frame"]:
            print(f"note: stage {s['stage']} ({s['name']}) has no frames, skipped", file=sys.stderr)

    # ---- table 1: every link (transmitter -> receiver) per stage
    link_rows = []
    for s in stages:
        if not s["first_frame"]:
            continue
        a, b, dur = int(s["first_frame"]), int(s["last_frame"]), float(s["duration_s"])
        groups = defaultdict(list)
        for r in rows:
            if a <= r["n"] <= b:
                groups[(label(r["wlan.ta"]), label(r["wlan.ra"]))].append(r)
        for (ta, ra), fr in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            n = len(fr)
            lens = [r["len"] for r in fr]
            ts = sorted(r["t"] for r in fr)
            gaps = [(y - x) * 1000 for x, y in zip(ts, ts[1:])]
            rssi = [int(r["radiotap.dbm_antsignal"]) for r in fr if r["radiotap.dbm_antsignal"]]
            share = lambda f: sum(r[f] == "True" for r in fr) / n
            types = Counter(TYPE_NAMES.get((r["wlan.fc.type"], r["wlan.fc.subtype"]),
                                           f"{r['wlan.fc.type']}/{r['wlan.fc.subtype']}") for r in fr)
            tids = Counter(r["wlan.qos.tid"] for r in fr if r["wlan.qos.tid"])
            link_rows.append({
                "stage": s["stage"], "stage_name": s["name"], "link": f"{ta}->{ra}", "frames": n,
                "frames_per_s": n / dur, "kB_per_s": sum(lens) / dur / 1000,
                "len_med": st.median(lens), "len_p10": pct(lens, 10), "len_p90": pct(lens, 90),
                "pct_over_1000B": sum(x > 1000 for x in lens) / n,
                "retry": share("wlan.fc.retry"), "pwr_mgmt": share("wlan.fc.pwrmgt"), "more_data": share("wlan.fc.moredata"),
                "gap_med_ms": st.median(gaps) if gaps else "", "gap_p90_ms": pct(gaps, 90),
                "rssi_med": st.median(rssi) if rssi else "", "seq_missing": seq_missing(fr),
                "types": " ".join(f"{k}:{v}" for k, v in types.most_common()),
                "tids": " ".join(f"{k}:{v}" for k, v in sorted(tids.items())),
            })

    # ---- table 2: steadiness / bursts of each listed device's data flows with the router
    timing_rows = []
    gap_s = args.burst_gap_ms / 1000
    for s in stages:
        if not s["first_frame"]:
            continue
        a, b, dur = int(s["first_frame"]), int(s["last_frame"]), float(s["duration_s"])
        data = [r for r in rows if a <= r["n"] <= b and r["wlan.fc.type"] == "2" and r["wlan.fc.subtype"] in ("0", "8")]
        if not data:
            continue
        t0, nsec = min(r["t"] for r in data), max(1, round(dur))
        for dev, name in names.items():
            if dev == router:
                continue
            up = sum(r["len"] for r in data if r["wlan.ta"] == dev)
            down = sum(r["len"] for r in data if r["wlan.ra"] == dev)
            for direction, (ta, ra) in (("upload", (dev, router)), ("download", (router, dev))):
                fr = [(r["t"], r["len"]) for r in data if r["wlan.ta"] == ta and r["wlan.ra"] == ra]
                if not fr:
                    continue
                per = defaultdict(int)
                for t, l in fr:
                    per[min(int(t - t0), nsec - 1)] += l
                secs = [per.get(i, 0) for i in range(nsec)]
                mean = st.mean(secs)
                bursts, cur, idle = [], 0, []
                for i, (t, l) in enumerate(fr):
                    if i and t - fr[i - 1][0] > gap_s:
                        bursts.append(cur)
                        cur = 0
                        idle.append((t - fr[i - 1][0]) * 1000)
                    cur += l
                bursts.append(cur)
                timing_rows.append({
                    "stage": s["stage"], "stage_name": s["name"], "device": name, "flow": direction,
                    "kB_per_s": sum(l for _, l in fr) / dur / 1000, "active_s": f"{sum(x > 0 for x in secs)}/{nsec}",
                    "cv_per_s": st.pstdev(secs) / mean if mean else "", "bursts_per_s": len(bursts) / dur,
                    "burst_kB_med": st.median(bursts) / 1000, "burst_kB_p90": pct(bursts, 90) / 1000,
                    "burst_kB_max": max(bursts) / 1000, "idle_gap_p90_ms": pct(idle, 90),
                    "upload_share": up / (up + down) if up + down else "",
                })

    # ---- print + save
    def show(title, rows_, cols):
        print(f"\n== {title}")
        print(" ".join(f"{h:>{w}}" if i else f"{h:<{w}}" for i, (h, w, _) in enumerate(cols)))
        last = None
        for r in rows_:
            if r["stage"] != last:
                print(f"-- stage {r['stage']}: {r['stage_name']}")
                last = r["stage"]
            print(" ".join(f"{fmt(r[k], spec):>{w}}" if i else f"{fmt(r[k], spec):<{w}}"
                          for i, (k, w, spec) in enumerate(cols)))

    show("links (per stage, transmitter -> receiver)", link_rows, [
        ("link", 22, ""), ("frames", 8, "d"), ("frames_per_s", 13, ".1f"), ("kB_per_s", 9, ".1f"),
        ("len_med", 8, ".0f"), ("len_p10", 8, ""), ("len_p90", 8, ""), ("pct_over_1000B", 15, ".0%"),
        ("retry", 6, ".0%"), ("pwr_mgmt", 9, ".0%"), ("gap_med_ms", 11, ".2f"), ("gap_p90_ms", 11, ".1f"),
        ("rssi_med", 9, ".0f"), ("seq_missing", 12, ".0%"), ("tids", 0, "")])
    show(f"timing (data flows with the router; burst = frames closer than {args.burst_gap_ms:g} ms)", timing_rows, [
        ("device", 10, ""), ("flow", 10, ""), ("kB_per_s", 9, ".1f"), ("active_s", 9, ""), ("cv_per_s", 9, ".2f"),
        ("bursts_per_s", 13, ".1f"), ("burst_kB_med", 13, ".1f"), ("burst_kB_p90", 13, ".1f"),
        ("burst_kB_max", 13, ".0f"), ("idle_gap_p90_ms", 16, ".0f"), ("upload_share", 13, ".0%")])

    base = args.pcap[:-5]
    for path, data in ((base + "_links.csv", link_rows), (base + "_timing.csv", timing_rows)):
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(data[0].keys()))
            w.writeheader()
            for r in data:
                w.writerow({k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()})
        print(f"saved {path}", file=sys.stderr)


if __name__ == "__main__":
    main()
