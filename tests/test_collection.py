"""Workflow regressions: attribution, unsafe promotion and lossless organisation."""
import csv
import hashlib
import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'recorder'))
from collection import automatic_candidate, check_capture, discover, discovery_candidates, explain_candidate, organise, session_decision, select_port
from record_wifi import record
from width_survey import target_measurements
from audit_recording import audit
from protocol import STATUS, PACKET_V3
from test_protocol import wire, packet_v3


class CollectionTests(unittest.TestCase):
    def test_auto_port_ignores_bluetooth_and_requires_unique_receiver(self):
        bluetooth=SimpleNamespace(device='COM3',description='Serial over Bluetooth',hwid='BTHENUM')
        usb=SimpleNamespace(device='COM42',description='USB CH343',vid=0x1a86,pid=0x55d3,serial_number='synthetic')
        other=SimpleNamespace(device='COM43',description='USB serial',vid=1,pid=2,serial_number='other')
        self.assertIs(select_port([bluetooth,usb]),usb)
        self.assertIs(select_port([bluetooth,usb,other],saved=dict(vid=usb.vid,pid=usb.pid,serial_number=usb.serial_number)),usb)
        with self.assertRaisesRegex(ValueError,'More than one'):
            select_port([usb,other])
        with self.assertRaisesRegex(ValueError,'No ESP'):
            select_port([bluetooth])
        self.assertIs(select_port([usb,other],requested='COM43'),other)

    def test_discovery_distinguishes_power_match_from_busiest_new_address(self):
        before=Counter(stable=50,weak=1)
        after=Counter(stable=50,new=1000,weak=1)
        data=[Counter(stable=30),Counter(),Counter(stable=30,new=900)]
        candidates=discovery_candidates(before,Counter(),after,set(),data)
        self.assertEqual(candidates[0]['mac'],'stable')
        self.assertTrue(candidates[0]['power_test_match'])
        new=next(c for c in candidates if c['mac']=='new')
        self.assertFalse(new['power_test_match'])
        self.assertIn('UNCONFIRMED',explain_candidate(new))
        self.assertIn('before power-off 30',explain_candidate(candidates[0]))

    def test_guided_find_does_not_confirm_a_reboot_only_candidate(self):
        for changed in (False,True):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                def capture(args,folder):
                    folder.mkdir(parents=True)
                    (folder/'session.json').write_text(json.dumps(dict(quality_findings={})))
                    return 0
                def counts(folder):
                    phase=folder.parent.name
                    mac='old' if changed and phase=='before' else 'candidate'
                    return (Counter(),Counter(),set()) if phase=='off' else (Counter({mac:10}),Counter({mac:10}),set())
                answers=['yes']*3
                args=SimpleNamespace(probe_seconds=2)
                with patch('collection.settings',return_value=[None]), patch('collection.audit'), \
                     patch('collection.transmitters',side_effect=counts), patch('collection.choice',side_effect=answers):
                    result=discover(args,root,capture)
                self.assertEqual(result,'candidate')
                self.assertEqual(args.discovery_selection['identity_confirmed'],not changed)
                self.assertTrue((root/'identity/automatic_selection.json').exists())

    def test_automatic_selection_keeps_competing_candidates_provisional(self):
        c=lambda mac,n:dict(mac=mac,before_data=n,after_data=n,power_test_match=True)
        chosen=automatic_candidate([c('second',25),c('first',100)])
        self.assertEqual(chosen['mac'],'first')
        self.assertFalse(chosen['identity_confirmed'])
        self.assertIsNone(automatic_candidate([c('weak',1)]))

    def test_off_on_evidence_excludes_persistent_and_beacon_transmitters(self):
        before = Counter({'same':10, 'persistent':20, 'ap':100})
        off = Counter({'persistent':3})
        after = Counter({'same':9, 'persistent':5, 'ap':100, 'new':30})
        result = discovery_candidates(before, off, after, {'ap'})
        self.assertEqual([x['mac'] for x in result], ['same','new'])
        self.assertFalse(result[0]['changed_address_possible'])
        self.assertTrue(result[1]['changed_address_possible'])
        self.assertNotIn('device_class', result[0])

    def test_visibility_and_interruption_block_automatic_promotion(self):
        meta = dict(result='completed', end_received=True, requested_mode=6,
                    latest_firmware_status=dict(target='esp32c5', channel=6, locked=1))
        metrics = dict(target_tx_frames=1, target_tx_data_frames=0)
        self.assertIn('active_workload_data_not_decoded', session_decision(meta,metrics,'esp32c5','streaming',True))
        self.assertEqual(session_decision(meta,metrics,'esp32c5','idle',True), [])
        meta.update(operator_stopped=True, requested_secondary='above')
        findings = session_decision(meta,metrics,'esp32s3','idle',False)
        for expected in ('operator_stopped','receiver_target_mismatch','secondary_not_confirmed','identity_unconfirmed'):
            self.assertIn(expected, findings)

    def capture(self, root, expected='esp32s3', count=20, secondary=None, leaf='compare'):
        source = root/'runs'/'survey'/leaf
        source.parent.mkdir(parents=True,exist_ok=True)
        with patch('record_wifi.serial.Serial') as factory, patch('record_wifi.secrets.randbelow',return_value=122):
            link = factory.return_value.__enter__.return_value
            def status(ts, count):
                return STATUS.pack(count,0,0,0,0,count,count,0,0,0,ts,6,6,1,bytes(32),b'test',b'esp32s3') + (bytes((6,1)) if secondary else b'')
            observation = list(PACKET_V3.unpack(packet_v3(1,8)))
            observation[6] = 6
            packets = []
            for ident in range(1, count+1):
                observation[0] = ident
                packets.append(PACKET_V3.pack(*observation))
            version=4 if secondary else 3
            link.read.side_effect = [wire(b'B',0,status(100,0),version), wire(b'P',1,b''.join(packets),version),
                                     wire(b'E',2,status(1000100,count),version)]
            link.in_waiting = 500
            args = SimpleNamespace(output=str(source.parent),state='streaming',channel=6,port='test',
                    baud=921600,camera='02:02:02:02:02:02',duration=.1,notes='synthetic',secondary=secondary,
                    expected_target=expected)
            with patch('record_wifi.time.monotonic',side_effect=[0,.1,.5,1.1]):
                result = record(args,folder=source)
            return result, source, link

    def test_wrong_receiver_stops_and_preserves_failed_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, source, link = self.capture(Path(tmp), 'esp32c5')
            self.assertEqual(result,1)
            self.assertIn('STOP',link.write.call_args_list[-1].args[0].decode())
            meta = json.loads((source/'session.json').read_text())
            self.assertEqual(meta['result'],'incomplete')
            self.assertIn('Expected esp32c5',meta['error'])
            self.assertIn('incomplete',(source/'README.md').read_text())

    def test_organisation_keeps_bytes_paths_reports_and_repeat_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            result, source, _ = self.capture(root)
            self.assertEqual(result,0)
            original = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in source.iterdir() if p.name!='README.md'}
            metrics = target_measurements(source,'02:02:02:02:02:02',6)
            report = dict(runs=[dict(phase='compare',folder='compare',**metrics)])
            survey_root=source.parent
            (survey_root/'survey.json').write_text(json.dumps(report))
            profile=dict(receiver='s3',activity='streaming',device_class='camera',device='synthetic_camera',
                         setup='Synthetic test setup',identity_basis='Synthetic known identity',identity_confirmed=True)
            outcome, = organise(root,survey_root,profile,'test_run')
            dest=Path(outcome['session_folder'])
            self.assertTrue(dest.is_relative_to(root/'dataset'))
            self.assertFalse(source.exists())
            for name,digest in original.items():
                self.assertEqual(hashlib.sha256((dest/name).read_bytes()).hexdigest(),digest)
            self.assertEqual(audit(dest)['rows'],20)
            self.assertEqual(dest.parent.parent, root/'dataset')
            self.assertEqual(dest.name,'20mhz')
            self.assertEqual(dest.parent.name,'synthetic_camera_test_streaming_positive_run')
            text=(dest/'README.md').read_text()
            self.assertIn('Synthetic test setup',text)
            self.assertIn('## 5.',text)
            self.assertNotIn('esp32_camera_recorder/',text)
            self.assertEqual((survey_root/json.loads((survey_root/'survey.json').read_text())['runs'][0]['folder']).resolve(),dest.resolve())
            organise(root,survey_root,profile,'test_run')
            with (root/'manifest.csv').open(newline='') as stream:
                self.assertEqual(len(list(csv.DictReader(stream))),1)

    def test_sparse_full_capture_is_kept_for_review_and_negative_is_named_explicitly(self):
        for count in (1,20):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                _,source,_=self.capture(root,count=count)
                raw=(source/'raw_serial.bin').read_bytes()
                metrics=target_measurements(source,'02:02:02:02:02:02',6)
                (source.parent/'survey.json').write_text(json.dumps(dict(runs=[
                    dict(phase='compare',folder='compare',**metrics)])))
                profile=dict(receiver='s3',activity='scrolling',device_class='non-camera',device='test_phone',
                             setup='Synthetic',identity_basis='Synthetic',identity_confirmed=True)
                row,=organise(root,source.parent,profile,'20260101T010203Z_random')
                self.assertEqual(row['sample_label'],'negative')
                if count==1:
                    self.assertEqual(row['status'],'review_required')
                    self.assertTrue(Path(row['session_folder']).is_relative_to(root/'runs'))
                    self.assertFalse((root/'dataset').exists())
                    self.assertIn('insufficient_target_outgoing_data',row['quality_findings'])
                else:
                    self.assertEqual(row['status'],'acquisition_checked')
                    self.assertEqual(Path(row['session_folder']).parent.name,'test_phone_20260101T010203Z_scrolling_negative_random')
                self.assertEqual((Path(row['session_folder'])/'raw_serial.bin').read_bytes(),raw)

    def test_both_widths_share_one_collection_and_provisional_stays_in_review(self):
        for confirmed in (True,False):
            with self.subTest(confirmed=confirmed), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                _,narrow,_=self.capture(root)
                _,wide,_=self.capture(root,secondary='above',leaf='wide')
                report=dict(runs=[dict(phase='compare',folder=src.name,
                    **target_measurements(src,'02:02:02:02:02:02',6)) for src in (narrow,wide)])
                (narrow.parent/'survey.json').write_text(json.dumps(report))
                profile=dict(receiver='s3',device='test_device',device_class='camera',activity='streaming',
                             identity_confirmed=confirmed,identity_basis='Synthetic',setup='Synthetic')
                preflight_check=check_capture(narrow,dict(profile,mac='02:02:02:02:02:02'),require_identity=False)
                self.assertEqual(preflight_check['findings'],[])
                result=organise(root,narrow.parent,profile,'20260101T000000Z_123')
                parents={Path(row['session_folder']).parent for row in result}
                self.assertEqual(len(parents),1)
                batch=parents.pop()
                self.assertEqual({Path(row['session_folder']).name for row in result},{'20mhz','40mhz_above'})
                self.assertTrue((batch/'README.md').exists())
                self.assertEqual(batch.is_relative_to(root/'dataset'),confirmed)
                for row in result:
                    self.assertEqual(audit(Path(row['session_folder']))['rows'],20)
                    self.assertEqual(row['training_eligible'],confirmed)


if __name__=='__main__':
    unittest.main()
