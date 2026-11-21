"""Traffic screening must tolerate inapplicable fields and reject invisible workloads."""
import csv
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'recorder'))
from traffic_check import inspect_traffic
from collection import main, preflight
from protocol import FIELDS, FIELDS_V3, PACKET_V5, rows
from test_protocol import packet_v3

MAC = '02:02:02:02:02:02'


class TrafficTests(unittest.TestCase):
    def sample(self, root, receiver='s3', fmt=0, count=20, seconds=10, edit=None, columns=FIELDS):
        if receiver=='s3':
            body=packet_v3(1,8)
        else:
            body=PACKET_V5.pack(1,578,100,8,0,-50,6,255,
                bytes([1])*6,bytes([2])*6,bytes(6),bytes(6),255,255,255,-95,
                7,0,96,fmt,0,11,0,0,1,0)
        row,=rows('2026-01-01T00:00:00Z',0,body)
        if edit:
            row.update(edit)
        with (root/'all_wifi_packets.csv').open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=columns,extrasaction='ignore')
            writer.writeheader()
            writer.writerows([row]*count)
        (root/'status.jsonl').write_text(json.dumps(dict(kind='B',uptime_us=0))+'\n'+
            json.dumps(dict(kind='E',uptime_us=seconds*1000000))+'\n')
        return inspect_traffic(root, MAC, receiver)

    def test_applicable_fields_pass_without_all_47_populated(self):
        for receiver,fmt in [('s3',0),('c5',0),('c5',2),('c5',4)]:
            with self.subTest(receiver=receiver,fmt=fmt), tempfile.TemporaryDirectory() as tmp:
                result=self.sample(Path(tmp),receiver,fmt)
                self.assertEqual(result['findings'],[])
                self.assertEqual(len(result['field_nonempty_target_rows']),47)
                self.assertTrue(result['fields_not_observed'])

    def test_missing_c5_metadata_fails_even_when_schema_has_47_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=self.sample(Path(tmp),'c5',2,edit={'phy_sig_a1':''})
            self.assertIn('missing_applicable_measurements',result['findings'])
            self.assertEqual(result['missing_applicable_data_fields']['phy_sig_a1'],20)

    def test_sparse_slow_control_only_and_receive_only_do_not_pass(self):
        for args in [dict(count=1),dict(seconds=30),
                     dict(edit={'frame_type':'1'}),dict(edit={'addr2_ta':'04:04:04:04:04:04','addr1_ra':MAC})]:
            with self.subTest(args=args), tempfile.TemporaryDirectory() as tmp:
                self.assertIn('insufficient_target_outgoing_data',self.sample(Path(tmp),**args)['findings'])

    def test_legacy_schema_is_replayable_but_not_current_collection_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIn('expected_47_column_schema_not_present',
                          self.sample(Path(tmp),columns=FIELDS_V3)['findings'])

    def test_preflight_requires_every_width_and_stops_on_any_bad_setting(self):
        for bad in (False,True):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as tmp:
                run=Path(tmp)
                report=run/'preflight/test_width_survey_123/survey.json'
                report.parent.mkdir(parents=True)
                report.write_text(json.dumps(dict(result='completed',primary=1,runs=[
                    dict(phase='compare',primary=1,secondary='none',folder='narrow'),
                    dict(phase='compare',primary=1,secondary='above',folder='wide')])))
                args=SimpleNamespace(output=str(run),channel=0,secondary='auto')
                with patch('collection.survey',return_value=0), patch('collection.check_capture',side_effect=[
                    {'findings':[]},{'findings':['insufficient_target_outgoing_data'] if bad else []}]) as check:
                    self.assertEqual(preflight(args,run,{}),not bad)
                    self.assertEqual(check.call_count,2)
                self.assertEqual(json.loads((run/'traffic_check.json').read_text())['passed'],not bad)

    def test_failed_preflight_never_asks_class_name_or_starts_full_survey(self):
        cwd=Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            prompts=[]
            answers=iter(['s3',MAC,'device-settings','yes','yes'])
            def answer(prompt):
                prompts.append(prompt)
                return next(answers)
            try:
                with patch('sys.argv',['collect.py']), patch('builtins.input',side_effect=answer), \
                     patch('collection.list_ports.comports',return_value=[SimpleNamespace(device='test',description='test')]), \
                     patch('collection.preflight',return_value=False), patch('collection.survey') as full:
                    self.assertEqual(main(Path(tmp)),2)
                    full.assert_not_called()
                self.assertFalse(any('name/model' in p or 'camera or non-camera' in p for p in prompts))
                self.assertFalse((Path(tmp)/'recordings/s3/dataset').exists())
            finally:
                os.chdir(cwd)

    def test_manual_traffic_guess_stops_before_capture(self):
        cwd=Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                with patch('sys.argv',['collect.py']), patch('builtins.input',side_effect=['c5',MAC,'traffic-guess']), \
                     patch('collection.list_ports.comports',return_value=[SimpleNamespace(device='test',description='USB test')]), \
                     patch('collection.preflight') as check:
                    self.assertEqual(main(Path(tmp)),2)
                    check.assert_not_called()
                result,=Path(tmp).rglob('result.json')
                self.assertEqual(json.loads(result.read_text())['result'],'identity_unresolved')
            finally:
                os.chdir(cwd)


if __name__=='__main__':
    unittest.main()
