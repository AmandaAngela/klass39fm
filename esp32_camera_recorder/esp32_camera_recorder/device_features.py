"""Derive per-device behavioural features from one or more session folders.

Derived analysis only: reads session exports, writes nothing back into them.

Features are chosen to be computable for any device whose frames this receiver
decodes at all, including devices whose payload is undecodable (2x2 or HE), since
control frames are sent at legacy rates. Where payload IS visible the same two
headline features are also computed from data frames, which is the higher-
resolution path.

  uplink_share_ctrl  A BlockAck acknowledges received data, so a device appearing
                     as addr1/RA of a BlockAck SENT the data, and as addr2/TA it
                     RECEIVED it. Ratio, so it is not confounded by throughput.
  null_share         Share of a device's frames that are Null/QoS-Null power-save
                     polling. Mains-powered always-on devices sit near zero.
  uplink_share_data  Same direction question from payload frames via the DS bits.
                     Only meaningful when payload is decodable.

Usage:
    python device_features.py <session-folder> [<session-folder> ...]
    python device_features.py --mac <test-device-mac> <folder> [...]
"""
import argparse
import csv
import json
import statistics
from pathlib import Path

BROADCAST = "ff:ff:ff:ff:ff:ff"
SIG_MODE = {"0": "non-HT", "1": "HT", "3": "VHT"}


def is_group(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 1)
    except (ValueError, IndexError):
        return True


def load(folder):
    folder = Path(folder)
    with (folder / "all_wifi_packets.csv").open(newline="") as f:
        rows = list(csv.DictReader(f))
    meta = json.loads((folder / "session.json").read_text(encoding="utf8"))
    return rows, meta


def features(rows, mac, duration):
    mine = [r for r in rows if mac in (r["addr1_ra"], r["addr2_ta"])]
    if not mine:
        return None
    nulls = [r for r in mine if r["frame_type"] == "2" and r["frame_subtype"] in ("4", "12")]
    data = [r for r in mine if r["frame_type"] == "2" and r["frame_subtype"] not in ("4", "12")]
    ctrl = [r for r in mine if r["frame_type"] == "1"]
    ba = [r for r in ctrl if r["frame_subtype"] == "9"]
    ba_sent = sum(1 for r in ba if r["addr1_ra"] == mac)
    ba_recv = sum(1 for r in ba if r["addr2_ta"] == mac)
    up = sum(1 for r in data if r["to_ds"] == "1" and r["from_ds"] == "0" and r["addr2_ta"] == mac)
    down = sum(1 for r in data if r["from_ds"] == "1" and r["to_ds"] == "0" and r["addr1_ra"] == mac)
    lengths = [int(r["frame_length_bytes"]) for r in data]
    # Radio capability, which decides whether the payload path is usable at all.
    # Version-2 archives predate the PHY columns, so these stay empty for them.
    modes = {SIG_MODE.get(r.get("phy_sig_mode"), r.get("phy_sig_mode"))
             for r in mine if r.get("phy_sig_mode")}
    mcs = [int(r["phy_mcs"]) for r in mine if r.get("phy_mcs") not in ("", None)]
    return {
        "frames": len(mine),
        "frames_per_s": round(len(mine) / duration, 2),
        "payload_frames": len(data),
        "control_frames": len(ctrl),
        "null_share": round(len(nulls) / len(mine), 4),
        "uplink_share_ctrl": round(ba_sent / (ba_sent + ba_recv), 4) if ba_sent + ba_recv >= 20 else None,
        "blockack_per_rts": (round(len(ba) / sum(1 for r in ctrl if r["frame_subtype"] == "11"), 2)
                             if sum(1 for r in ctrl if r["frame_subtype"] == "11") else None),
        "plain_acks": sum(1 for r in ctrl if r["frame_subtype"] == "13"),
        "uplink_share_data": round(up / (up + down), 4) if up + down >= 20 else None,
        "median_payload_len": statistics.median(lengths) if lengths else None,
        "payload_ge1000": sum(1 for x in lengths if x >= 1000),
        "payload_mbps": round(sum(lengths) * 8 / duration / 1e6, 3) if lengths else 0.0,
        "phy_modes": sorted(modes),
        "max_mcs": max(mcs) if mcs else None,
        "spatial_streams_hint": ("2 (MCS>=8)" if mcs and max(mcs) >= 8 else
                                 "1 (MCS<=7)" if mcs else "unknown"),
    }


def active_macs(rows, floor):
    counts = {}
    for r in rows:
        for a in (r["addr1_ra"], r["addr2_ta"]):
            if a and a != BROADCAST and not is_group(a):
                counts[a] = counts.get(a, 0) + 1
    return [m for m, n in sorted(counts.items(), key=lambda kv: -kv[1]) if n >= floor]


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("folders", nargs="+", type=Path)
    p.add_argument("--mac", action="append", default=[],
                   help="restrict to these MACs; default is every device with >=200 frames")
    p.add_argument("--floor", type=int, default=200)
    p.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    args = p.parse_args()

    out = []
    for folder in args.folders:
        rows, meta = load(folder)
        duration = meta.get("requested_seconds") or 90.0
        for mac in (args.mac or active_macs(rows, args.floor)):
            f = features(rows, mac, duration)
            if f:
                out.append(dict(session=folder.name[-8:], state=meta.get("camera_state"),
                                mac=mac, **f))

    if args.json:
        print(json.dumps(out, indent=2))
        return

    hdr = ("session", "state", "mac", "frames/s", "nullShr", "upShrC", "upShrD",
           "BA/RTS", "ACKs", "medLen", "Mbps", "phy", "streams")
    print("%-9s %-10s %-18s %8s %8s %7s %7s %7s %6s %7s %7s %-10s %s" % hdr)
    for r in out:
        print("%-9s %-10s %-18s %8.1f %8.4f %7s %7s %7s %6d %7s %7.3f %-10s %s" % (
            r["session"], (r["state"] or "")[:10], r["mac"], r["frames_per_s"], r["null_share"],
            r["uplink_share_ctrl"] if r["uplink_share_ctrl"] is not None else "n/a",
            r["uplink_share_data"] if r["uplink_share_data"] is not None else "n/a",
            r["blockack_per_rts"] if r["blockack_per_rts"] is not None else "n/a",
            r["plain_acks"],
            r["median_payload_len"] if r["median_payload_len"] is not None else "n/a",
            r["payload_mbps"], ",".join(r["phy_modes"])[:10], r["spatial_streams_hint"]))


if __name__ == "__main__":
    main()
