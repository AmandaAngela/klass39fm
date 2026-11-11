"""Regression cases for resynchronization, exact retention and address semantics."""
import argparse
import csv
import json
import tempfile
import unittest
import zlib
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import serial

from audit_recording import audit
from protocol import (CRC, Decoder, FIELDS, HEADER, MAGIC, PACKET, PACKET_V3, PHY_FIELDS,
                      STATUS, rows)
from record_wifi import Session, record, load_labels
from device_features import burst_windows, measured_seconds


def wire(kind, number, payload, version=2):
    block = HEADER.pack(MAGIC, version, kind, len(payload), 123, number) + payload
    return block + CRC.pack(zlib.crc32(block))


def packet(ident, fc):
    addresses = [bytes([n]) * 6 for n in range(1, 5)]
    return PACKET.pack(ident, 578, 76, fc, 0xfff3, -81, 13, 4, *addresses)


def packet_v3(ident, fc, phy=0, mcs=0, rate=11, noise=-96):
    addresses = [bytes([n]) * 6 for n in range(1, 5)]
    return PACKET_V3.pack(ident, 578, 76, fc, 0xfff3, -81, 13, 4, *addresses,
                          phy, mcs, rate, noise)


class ProtocolTests(unittest.TestCase):
    def test_default_and_ht40_session_commands_and_audit(self):
        for secondary, version, verb in ((None, 3, "START"), ("above", 4, "WIDE+"),
                                          ("below", 4, "WIDE-")):
            with self.subTest(secondary=secondary), tempfile.TemporaryDirectory() as tmp, \
                    patch("record_wifi.serial.Serial") as factory, \
                    patch("record_wifi.secrets.randbelow", return_value=122):
                link = factory.return_value.__enter__.return_value
                def status(elapsed, count):
                    body = STATUS.pack(count, 0, 0, 0, 0, count, count, 0, 0, 0,
                                       elapsed, 6, 6, 1, bytes(32), b"test", b"esp32s3")
                    if secondary:
                        body += bytes((6, 1 if secondary == "above" else 255))
                    return body
                link.read.side_effect = [wire(b"B", 0, status(100, 0), version),
                                         wire(b"P", 1, packet_v3(1, 8), version),
                                         wire(b"E", 2, status(1000100, 1), version)]
                link.in_waiting = 500
                args = SimpleNamespace(output=tmp, state="unknown", channel=6, port="test",
                    baud=115200, camera=None, duration=0.1, notes="", secondary=secondary)
                with patch("record_wifi.time.monotonic", side_effect=[0, 0.1, 0.5, 1.1]):
                    self.assertEqual(record(args), 0)
                self.assertEqual(link.write.call_args_list[0].args,
                                 (f"\n{verb} 0000007b 6 000000000000\n".encode(),))
                folder, = Path(tmp).iterdir()
                self.assertEqual(audit(folder)["rows"], 1)
                info = json.loads((folder / "session.json").read_text())
                self.assertEqual(info["latest_firmware_status"].get("reported_secondary"), secondary)
                self.assertEqual(measured_seconds(folder), 1)

    def test_device_label_intervals(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "labels.json"
            label = dict(mac="AA-BB-CC-DD-EE-FF", alias="test", device_class="camera",
                         activity="streaming", start_s=2, end_s=8)
            path.write_text(json.dumps([label]))
            self.assertEqual(load_labels(path)[0]["mac"], "aa:bb:cc:dd:ee:ff")
            label["end_s"] = 1
            path.write_text(json.dumps([label]))
            with self.assertRaisesRegex(argparse.ArgumentTypeError, "end_s"):
                load_labels(path)

    def test_bursts_across_clock_wrap_include_silent_windows(self):
        def row(us, subtype="0", retry="0"):
            return dict(esp_timestamp_us=us % (1 << 32), addr2_ta="device", frame_type="2",
                        frame_subtype=subtype, retry=retry, frame_length_bytes="100")
        start = (1 << 32) - 1000
        sample = [row(start), row(start + 2000, retry="1"), row(start + 150000, "12"),
                  row(start + 202000)]
        windows = list(burst_windows(sample, "device", 100, 10))
        self.assertEqual([w["tx_frame_bytes"] for w in windows], [200, 0, 100])
        self.assertEqual(windows[0]["retry_frames"], 1)
        self.assertEqual(windows[0]["median_tx_gap_us"], 2000)
        self.assertEqual(windows[-1]["median_burst_period_us"], 202000)

    def test_fragmentation_corruption_and_recovery(self):
        good = wire(b"P", 1, packet(1, 0x888))
        damaged = bytearray(good)
        damaged[-1] ^= 4
        decoder = Decoder()
        data = b"boot\r\n" + damaged + good + good[:24]
        decoded = []
        for byte in data:
            decoded.extend(decoder.feed(bytes([byte])))
        decoded.extend(decoder.feed(b"", final=True))
        self.assertEqual([f[2] for f in decoded], [1])
        self.assertEqual(decoder.errors["crc_failures"], 1)
        self.assertEqual(decoder.errors["trailing_partial_bytes"], 24)

    def test_directions(self):
        for ds, expected in enumerate(((2, 1), (2, 3), (3, 1), (4, 3))):
            r, = rows("utc", 0, packet(1, 0x888 | ds << 8))
            self.assertEqual(tuple(int(r[k][:2], 16) for k in ("source", "destination")), expected)
            self.assertEqual((r["retry"], r["sequence"], r["fragment"], r["qos_tid"]), (1, 4095, 3, 4))
            self.assertEqual(bool(r["addr4"]), ds == 3)

    def test_session_preserves_duplicate_times_and_raw_bytes(self):
        p = packet(1, 0x888) + packet(3, 0x888)
        s = STATUS.pack(3, 1, 0, 0, 0, 2, 2, 0, 0, 0, 1234, 13, 13, 1,
                        bytes(32), b"test", b"esp32s3")
        raw = b"\xffBOOT" + wire(b"B", 0, s) + wire(b"P", 2, p) + wire(b"E", 3, s)
        with tempfile.TemporaryDirectory() as folder, ExitStack() as files:
            folder = Path(folder)
            session = Session({"token": 123, "camera_mac": "01:01:01:01:01:01"}, folder, files)
            session.consume(raw)
            info = session.checkpoint()
            self.assertEqual((folder / "raw_serial.bin").read_bytes(), raw)
            with (folder / "all_wifi_packets.csv").open() as f:
                data = list(csv.DictReader(f))
            self.assertEqual([r["esp_timestamp_us"] for r in data], ["578", "578"])
            self.assertEqual([r["observation_id"] for r in data], ["1", "3"])
            for key in ("equal_adjacent_timestamps", "wire_gaps", "observation_gaps"):
                self.assertEqual(session.count[key], 1)
            self.assertEqual(session.count["camera_rows"], 2)
            self.assertEqual(info["sent_minus_rows"], 0)
            self.assertEqual(info["eligible_minus_accounted"], 0)

    def test_version3_phy_fields_and_version2_blanks(self):
        # HT, 40 MHz, aggregated, short GI, STBC 1 -> phy = 1 | 1<<2 | 1<<3 | 1<<4 | 1<<5
        r, = rows("utc", 0, packet_v3(1, 0x888, phy=0b0111101, mcs=7, rate=11, noise=-98))
        self.assertEqual((r["phy_sig_mode"], r["phy_mcs"], r["phy_cwb"]), (1, 7, 1))
        self.assertEqual((r["phy_aggregation"], r["phy_sgi"], r["phy_stbc"]), (1, 1, 1))
        self.assertEqual(r["noise_floor_dbm"], -98)
        # legacy_rate describes non-HT frames only, so it stays blank for an HT frame
        self.assertEqual(r["phy_legacy_rate"], "")
        # A non-HT frame reports its legacy rate and leaves mcs blank.
        legacy, = rows("utc", 0, packet_v3(2, 0x888, phy=0, mcs=0, rate=11))
        self.assertEqual((legacy["phy_sig_mode"], legacy["phy_legacy_rate"], legacy["phy_mcs"]),
                         (0, 11, ""))
        # Version-2 records still decode, with every PHY column blank rather than zero.
        old, = rows("utc", 0, packet(3, 0x888))
        self.assertEqual([old[k] for k in PHY_FIELDS], [""] * len(PHY_FIELDS))
        self.assertEqual(tuple(old), FIELDS)

    def test_version3_frames_decode_over_the_wire(self):
        decoder = Decoder()
        body = packet_v3(1, 0x888) + packet_v3(2, 0x888)
        decoded = list(decoder.feed(wire(b"P", 1, body, version=3), final=True))
        self.assertEqual(len(decoded), 1)
        self.assertEqual([r["observation_id"] for r in rows("", 1, decoded[0][3])], [1, 2])
        self.assertFalse(decoder.errors)

    def test_control_frames_blank_absent_fields(self):
        # BlockAck (type 1, subtype 9) is long enough to carry a transmitter address.
        ba = packet_v3(1, (1 << 2) | (9 << 4))
        r, = rows("utc", 0, ba)
        self.assertEqual((r["frame_type"], r["frame_subtype"]), (1, 9))
        self.assertEqual(r["addr1_ra"][:2], "01")
        self.assertEqual(r["addr2_ta"][:2], "02")  # length 76 >= 20, so TA present
        for key in ("addr3", "addr4", "source", "destination", "to_ds", "from_ds",
                    "sequence_control", "sequence", "fragment"):
            self.assertEqual(r[key], "", key)

    def test_short_control_frame_has_no_transmitter_address(self):
        addresses = [bytes([n]) * 6 for n in range(1, 5)]
        # An ACK is 14 bytes including FCS, so addr2 must be reported as absent.
        ack = PACKET_V3.pack(1, 578, 14, (1 << 2) | (13 << 4), 0, -81, 13, 255,
                             *addresses, 0, 0, 11, -96)
        r, = rows("utc", 0, ack)
        self.assertEqual(r["addr1_ra"][:2], "01")
        self.assertEqual(r["addr2_ta"], "")

    def test_unknown_version_is_rejected(self):
        decoder = Decoder()
        self.assertEqual(list(decoder.feed(wire(b"P", 1, packet(1, 0x888), version=9),
                                           final=True)), [])
        self.assertEqual(decoder.errors["bad_headers"], 1)

    def test_invalid_header_and_partial_magic(self):
        decoder = Decoder()
        bad = HEADER.pack(MAGIC, 2, b"P", 65535, 1, 0)
        good = wire(b"P", 4, packet(1, 0x8))
        result = list(decoder.feed(bad + good + MAGIC[:3], final=True))
        self.assertEqual(len(result), 1)
        self.assertEqual(decoder.errors["bad_headers"], 1)
        self.assertEqual(decoder.errors["trailing_partial_bytes"], 3)

    def test_disconnect_preserves_partial_session(self):
        status = STATUS.pack(*([0] * 10), 200, 13, 13, 1, bytes(32), b"test", b"esp32s3")
        raw = wire(b"B", 0, status) + wire(b"P", 1, packet(1, 0x888))[:24]
        with tempfile.TemporaryDirectory() as tmp, patch("record_wifi.serial.Serial") as serial_factory:
            link = serial_factory.return_value.__enter__.return_value
            link.in_waiting = len(raw)
            link.read.side_effect = [raw, serial.SerialException("test disconnect")]
            args = SimpleNamespace(output=tmp, state="unknown", channel=13, port="test", baud=115200,
                                   camera="01:01:01:01:01:01", duration=60, notes="synthetic")
            with patch("record_wifi.secrets.randbelow", return_value=122):
                self.assertEqual(record(args), 1)
            folder, = Path(tmp).iterdir()
            info = json.loads((folder / "session.json").read_text())
            self.assertEqual(info["result"], "incomplete")
            self.assertTrue(info["begin_received"])
            self.assertFalse(info["end_received"])
            self.assertEqual(info["decoder"]["trailing_partial_bytes"], 24)
            self.assertEqual((folder / "raw_serial.bin").read_bytes(), raw)
            with self.assertRaisesRegex(ValueError, "boundaries incomplete"):
                audit(folder)


if __name__ == "__main__":
    unittest.main()
