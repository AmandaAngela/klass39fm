"""WFS2 wire decoder. Keep undecodable bytes in the caller's raw archive."""
import struct
import zlib
from collections import Counter

MAGIC = b"WFS2"
HEADER = struct.Struct("<4sBcHII")
# Version 2 is the original 41-byte observation. Version 3 appends four PHY bytes.
# The magic word is unchanged across both so a resync still finds frame starts in
# either archive; the header's version byte selects the record layout.
PACKET_V2 = struct.Struct("<IIHHHbBB6s6s6s6s")
PACKET_V3 = struct.Struct("<IIHHHbBB6s6s6s6sBBBb")
PACKET = PACKET_V2  # original layout, retained for existing callers and fixtures
LAYOUTS = {2: PACKET_V2, 3: PACKET_V3, 4: PACKET_V3}
STATUS = struct.Struct("<10IQbBB32s32s16s")
RADIO = struct.Struct("<Bb")
CRC = struct.Struct("<I")
COUNTERS = ("eligible", "overflow", "malformed", "unsupported", "rx_errors", "high_water",
            "sent", "tx_errors", "tx_lost", "tune_errors")
BASE_FIELDS = ("host_utc", "wire_seq", "observation_id", "esp_timestamp_us", "channel", "rssi_dbm",
               "frame_length_bytes", "frame_control", "sequence_control", "frame_type",
               "frame_subtype", "to_ds", "from_ds", "retry", "sequence", "fragment", "qos_tid",
               "addr1_ra", "addr2_ta", "addr3", "addr4", "source", "destination")
# Raw driver PHY values, undecoded beyond splitting the packed byte. sig_mode is
# 0 non-HT(11bg), 1 HT(11n), 3 VHT(11ac); cwb is 0 for 20 MHz and 1 for 40 MHz;
# legacy_rate is only meaningful when sig_mode is 0, mcs only when it is not.
PHY_FIELDS = ("phy_sig_mode", "phy_mcs", "phy_cwb", "phy_aggregation", "phy_sgi",
              "phy_stbc", "phy_legacy_rate", "noise_floor_dbm")
FIELDS = BASE_FIELDS + PHY_FIELDS
FIELDS_V2 = BASE_FIELDS
KNOWN_FIELD_SETS = (FIELDS, FIELDS_V2)


class Decoder:
    def __init__(self):
        self.buf = bytearray()
        self.errors = Counter()

    def feed(self, chunk, final=False):
        self.buf.extend(chunk)
        while self.buf:
            start = self.buf.find(MAGIC)
            if start < 0:
                # Keep only a possible partial magic word across read boundaries.
                keep = next((n for n in (3, 2, 1) if self.buf.endswith(MAGIC[:n])), 0)
                self.errors["unframed_bytes"] += len(self.buf) - keep
                if keep and final:
                    self.errors["trailing_partial_bytes"] += keep
                    keep = 0
                del self.buf[:len(self.buf)-keep]
                return
            if start:
                self.errors["unframed_bytes"] += start
                del self.buf[:start]
            if len(self.buf) < HEADER.size:
                if final:
                    self.errors["trailing_partial_bytes"] += len(self.buf)
                    self.buf.clear()
                return
            _, version, kind, n, token, seq = HEADER.unpack_from(self.buf)
            layout = LAYOUTS.get(version)
            good_size = layout is not None and (
                kind == b"P" and 0 < n <= 32 * layout.size and n % layout.size == 0
                or kind in (b"B", b"S", b"E") and n == STATUS.size + (RADIO.size if version == 4 else 0))
            if not good_size:
                self.errors["bad_headers"] += 1
                del self.buf[0]
                continue
            size = HEADER.size + n
            if len(self.buf) < size + CRC.size:
                if not final:
                    return
                # A damaged length can mask another complete frame in the tail.
                following = self.buf.find(MAGIC, 1)
                cut = following if following >= 0 else len(self.buf)
                self.errors["trailing_partial_bytes"] += cut
                del self.buf[:cut]
                continue
            if zlib.crc32(self.buf[:size]) != CRC.unpack_from(self.buf, size)[0]:
                self.errors["crc_failures"] += 1
                del self.buf[0]
                continue
            payload = bytes(self.buf[HEADER.size:size])
            del self.buf[:size + CRC.size]
            yield kind, token, seq, payload


def status_fields(payload):
    *nums, sha, idf, target = STATUS.unpack_from(payload)
    names = (*COUNTERS, "uptime_us", "mode", "channel", "locked")
    fields = dict(zip(names, nums), firmware_sha256=sha.hex(),
                idf=idf.split(b"\0")[0].decode("ascii", "replace"),
                target=target.split(b"\0")[0].decode("ascii", "replace"))
    if len(payload) == STATUS.size + RADIO.size:
        primary, offset = RADIO.unpack_from(payload, STATUS.size)
        fields.update(reported_primary=primary, reported_secondary={-1: "below", 0: "none",
                      1: "above"}.get(offset, "unknown"))
    return fields


def layout_for(payload):
    """Resolve the record layout from the body length.

    A batch holds at most 32 records, so a body is at most 1,440 bytes, while the
    smallest length divisible by both 41 and 45 is 1,845. The match is therefore
    unambiguous for any body the decoder accepts.
    """
    options = [s for s in (PACKET_V2, PACKET_V3) if payload and len(payload) % s.size == 0]
    if len(options) != 1:
        raise ValueError(f"packet body of {len(payload)} bytes matches no single record layout")
    return options[0]


def rows(utc, seq, payload):
    layout = layout_for(payload)
    for record in layout.iter_unpack(payload):
        ident, ts, length, fc, sc, rssi, ch, tid = record[:8]
        a1, a2, a3, a4 = (addr.hex(":") for addr in record[8:12])
        if layout is PACKET_V3:
            phy, mcs, rate, noise = record[12:]
            # Blank rather than zero for the modes the value does not describe, so
            # an absent reading is never mistaken for a measured zero.
            sig_mode = phy & 3
            physical = (sig_mode, mcs if sig_mode else "", phy >> 2 & 1, phy >> 3 & 1,
                        phy >> 4 & 1, phy >> 5 & 3, "" if sig_mode else rate, noise)
        else:
            physical = ("",) * len(PHY_FIELDS)
        typ = fc >> 2 & 3
        to_ds, from_ds = fc >> 8 & 1, fc >> 9 & 1
        four = typ == 2 and to_ds and from_ds
        if typ == 1:
            # Control frames have no addr3/addr4, no DS bits and no sequence
            # control, and the short variants (ACK, CTS) carry no transmitter
            # address either. Blank what does not exist rather than reporting a
            # zeroed address or a sequence number the firmware never read.
            a2 = a2 if length >= 16 + 4 else ""
            a3 = a4 = source = dest = ""
            to_ds = from_ds = ""
            seq_control = sequence = fragment = ""
        else:
            source = a4 if four else a3 if from_ds else a2
            dest = a3 if to_ds else a1
            a4 = a4 if four else ""
            seq_control, sequence, fragment = sc, sc >> 4, sc & 15
        yield dict(zip(FIELDS, (utc, seq, ident, ts, ch, rssi, length, fc, seq_control,
            typ, fc >> 4 & 15, to_ds, from_ds, fc >> 11 & 1, sequence, fragment,
            "" if tid == 255 else tid, a1, a2, a3, a4, source, dest,
            *physical)))
