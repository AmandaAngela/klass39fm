"""Conservative acquisition screening, not a classifier or RF completeness test."""
import csv
from collections import Counter
from pathlib import Path

from protocol import FIELDS, EXTRA_FIELDS
from device_features import measured_seconds

DEFAULT_MIN_FRAMES = 20
DEFAULT_MIN_RATE = 1.0
REVIEW_MESSAGE = (
    'CHECK WITH AI: this target traffic may be incomplete or unsuitable for training. '
    'Review the saved traffic check, raw capture and status before collecting a labelled dataset. '
    'Check active MAC, band, channel, workload and receiver visibility. Sparse/control-only '
    'traffic does not prove a 2x2 limitation; a passing check cannot prove complete RF reception.'
)


def inspect_traffic(folder, mac, receiver, min_frames=DEFAULT_MIN_FRAMES, min_rate=DEFAULT_MIN_RATE):
    folder = Path(folder)
    populated = Counter({key: 0 for key in FIELDS})
    missing_required = Counter()
    tx = data = 0
    with (folder/'all_wifi_packets.csv').open(newline='', encoding='utf-8-sig') as stream:
        reader = csv.DictReader(stream)
        columns = reader.fieldnames or []
        for row in reader:
            if row.get('addr2_ta') != mac:
                continue
            tx += 1
            populated.update(key for key in FIELDS if row.get(key, '') != '')
            if row.get('frame_type') != '2' or int(row['frame_subtype']) & 4:
                continue
            data += 1
            required = set(FIELDS[:16]) | {'addr1_ra', 'addr2_ta', 'addr3', 'source', 'destination',
                                         'phy_sig_mode', 'noise_floor_dbm'}
            if int(row['frame_subtype']) & 8:
                required.add('qos_tid')
            if row.get('to_ds') == row.get('from_ds') == '1':
                required.add('addr4')
            if receiver == 'c5':
                required.update(EXTRA_FIELDS[:10])
                fmt = row.get('phy_rx_format')
                if fmt == '2':
                    required.update(('phy_mcs', 'phy_cwb', 'phy_aggregation', 'phy_sgi',
                                     'phy_stbc', 'phy_fec_coding'))
                elif fmt == '4':
                    required.update(('phy_mcs', 'phy_cwb', 'phy_stbc', 'phy_fec_coding', *EXTRA_FIELDS[11:]))
            else:
                required.update(('phy_cwb', 'phy_aggregation', 'phy_sgi', 'phy_stbc'))
                required.add('phy_legacy_rate' if row.get('phy_sig_mode') == '0' else 'phy_mcs')
            missing_required.update(key for key in required if row.get(key, '') == '')
    seconds = measured_seconds(folder)
    rate = data / seconds if seconds > 0 else 0
    findings = []
    if tuple(columns) != FIELDS:
        findings.append('expected_47_column_schema_not_present')
    if data < min_frames or rate < min_rate:
        findings.append('insufficient_target_outgoing_data')
    if seconds <= 0:
        findings.append('invalid_measured_duration')
    if missing_required:
        findings.append('missing_applicable_measurements')
    return dict(findings=findings, target_tx_frames=tx, target_tx_data_frames=data,
                measured_seconds=seconds, target_tx_data_frames_per_s=rate,
                thresholds=dict(min_data_frames=min_frames, min_data_frames_per_s=min_rate),
                schema_columns=len(columns), field_nonempty_target_rows=dict(populated),
                missing_applicable_data_fields=dict(missing_required),
                fields_not_observed=[key for key in FIELDS if not populated[key]],
                interpretation='Conditional PHY/header blanks are expected; this checks applicable measurements and minimum observed traffic, not all 47 values on every frame or RF completeness.')
