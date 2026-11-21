"""Operator-guided collection, device discovery and canonical dataset organisation."""
import argparse
import csv
import hashlib
import json
import math
import os
import re
import secrets
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from serial.tools import list_ports
from record_wifi import record, camera_mac
from width_survey import survey, settings
from audit_recording import audit
from session_report import write_session_readme
from traffic_check import inspect_traffic, REVIEW_MESSAGE, DEFAULT_MIN_FRAMES, DEFAULT_MIN_RATE


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2) + "\n", encoding="utf8")
    temp.replace(path)


def ask(label, default=""):
    value = input(f"{label}" + (f" [{default}]" if default != "" else "") + ": ").strip()
    return value or default


def choice(label, options, default):
    while True:
        value = ask(label + " (" + "/".join(options) + ")", default).lower()
        if value in options:
            return value
        print("Choose one of the listed values.")


def positive(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise ValueError("Duration must be positive and finite")
    return number


def slug(value):
    result = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    if not result:
        raise ValueError("Device/activity name needs letters or digits")
    return result


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "_" + secrets.token_hex(4)


def select_port(ports, requested=None, saved=None):
    """Prefer a unique USB receiver; bridge identity alone never proves the chip."""
    if requested:
        matches = [p for p in ports if p.device == requested]
        if not matches:
            raise ValueError('Requested serial port is not currently connected')
        return matches[0]
    candidates = [p for p in ports if 'bluetooth' not in str(p.description).lower()
                  and 'bthenum' not in str(getattr(p,'hwid','')).lower()]
    if saved and saved.get('serial_number'):
        matches = [p for p in candidates if all(getattr(p,k,None)==saved.get(k)
                   for k in ('vid','pid','serial_number'))]
        if len(matches)==1:
            return matches[0]
    usb = [p for p in candidates if getattr(p,'vid',None) is not None
           or any(word in str(p.description).lower() for word in ('usb','espressif','esp32','cp210','ch34'))]
    pool = usb or candidates
    if len(pool)==1:
        return pool[0]
    if not pool:
        raise ValueError('No ESP serial connection found. Connect the ESP with a data-capable USB cable and retry.')
    raise ValueError('More than one possible receiver is connected. Unplug the other serial devices and retry, '
                     'or specify --port explicitly. Connections: '+', '.join(p.device for p in pool))


def transmitters(folder):
    counts, data, beacons = Counter(), Counter(), set()
    with (Path(folder) / "all_wifi_packets.csv").open(newline="", encoding="utf8") as stream:
        for row in csv.DictReader(stream):
            mac = row["addr2_ta"]
            if not mac or mac == '00:00:00:00:00:00' or int(mac[:2], 16) & 1:
                continue
            counts[mac] += 1
            if row["frame_type"] == "0" and row["frame_subtype"] == "8":
                beacons.add(mac)
            if row["frame_type"] == "2" and not int(row["frame_subtype"]) & 4:
                data[mac] += 1
    return counts, data, beacons


def discovery_candidates(before, off, after, beacons, data_inventories=None):
    # Descriptive temporal association only. Never assigns a device class.
    candidates = [dict(mac=mac, before=before[mac], off=off[mac], after=after[mac],
                        changed_address_possible=not before[mac])
                  for mac in after if after[mac] and not off[mac] and mac not in beacons]
    for item in candidates:
        counts = data_inventories or [Counter(),Counter(),Counter()]
        item.update(before_data=counts[0][item['mac']], after_data=counts[2][item['mac']])
        item['power_test_match'] = (not item['changed_address_possible'] and
            item['before_data'] >= DEFAULT_MIN_FRAMES and item['after_data'] >= DEFAULT_MIN_FRAMES)
    return sorted(candidates, key=lambda item: (item['power_test_match'], item['after_data'],
                  bool(item['before']), item['after']), reverse=True)


def explain_candidate(item):
    if item['power_test_match']:
        verdict = 'POWER-TEST MATCH: this same address was active, disappeared when power was removed, and returned.'
    elif item['changed_address_possible']:
        verdict = 'UNCONFIRMED: appeared after restart only. The device may have changed address, or this may be another device.'
    else:
        verdict = 'WEAK EVIDENCE: too little actual data to associate this address reliably.'
    return (f"{item['mac']} — {verdict}\n"
            f"   Actual data frames sent: before power-off {item['before_data']}; after power-on {item['after_data']}. "
            f"Any frames while powered off: {item['off']}.")


def automatic_candidate(candidates):
    eligible = [c for c in candidates if c['after_data'] >= DEFAULT_MIN_FRAMES]
    if not eligible:
        return None
    ranked = sorted(eligible, key=lambda c: (-int(c['power_test_match']),
                    -c['after_data'], -c['before_data'], c['mac']))
    selected = dict(ranked[0])
    supported = selected['power_test_match'] and sum(c['power_test_match'] for c in eligible)==1
    selected.update(identity_confirmed=supported,
        identity_status='power_test_supported' if supported else 'provisional',
        selection_basis=('Automatically selected the unique same-address ON/OFF/ON data match.' if supported else
            'Automatically selected the strongest available candidate; changed-address or competing-candidate evidence leaves identity provisional.'))
    return selected


def discover(args, run, capture=record):
    inventories = []
    data_inventories = []
    all_beacons = set()
    print('Find your device: I will compare traffic while you turn ONLY that device off and on. '
          'Leave the router, ESP and other devices running. A bigger traffic count does not prove identity. '
          'Each scan takes about a minute at the default settings.')
    for phase, instruction in (
            ("before", "Step 1/3: Turn the device ON. For a camera, open live view and wait until video plays"),
            ("off", "Step 2/3: Unplug ONLY that device's power (closing the app is not enough). Leave it off"),
            ("after", "Step 3/3: Power the device ON again. Wait for Wi-Fi and restart the same activity/live view")):
        if choice(instruction + '. Ready?', ("yes", "cancel"), "cancel") != "yes":
            return None
        counts, data = Counter(), Counter()
        for primary in range(1, 14):
            for secondary in settings(primary):
                sample = SimpleNamespace(**vars(args))
                sample.camera, sample.labels, sample.state = None, None, "unknown"
                sample.channel, sample.secondary, sample.duration = primary, secondary, args.probe_seconds
                sample.notes = f"Identity discovery {phase}; operator-controlled physical state. Not a class prediction."
                folder = run / "identity" / phase / f"ch{primary}_{secondary or '20mhz'}"
                code = capture(sample, folder=folder)
                if code == 1:
                    raise RuntimeError(f"Discovery interrupted/incomplete: {folder}")
                meta = json.loads((folder / "session.json").read_text())
                if meta.get("operator_stopped"):
                    raise KeyboardInterrupt
                if any(k != "empty_capture" for k in meta.get("quality_findings", {})):
                    raise RuntimeError(f"Discovery has acquisition findings; inspect {folder}")
                audit(folder)
                c, d, b = transmitters(folder)
                counts.update(c); data.update(d); all_beacons.update(b)
        inventories.append(counts)
        data_inventories.append(data)
        save(run / "identity" / f"{phase}.json", dict(tx=dict(counts), data=dict(data)))
    candidates = discovery_candidates(*inventories, all_beacons, data_inventories)
    save(run / "identity" / "candidates.json", candidates)
    print('Results: a MAC is a Wi-Fi address, not a device name. Counts mean received frames, not confidence scores.')
    for i, item in enumerate(candidates[:20], 1):
        print(f'{i}. '+explain_candidate(item))
    print("This is observation evidence, not proof of identity. Scan gaps and other changing devices can mislead.")
    if not candidates:
        print("No supported association found. Evidence saved for manual/AI investigation.")
        return None
    result = automatic_candidate(candidates)
    if result is None:
        print('No candidate has enough outgoing data to select. Evidence saved for AI review.')
        return None
    print(f"Automatically selected {result['mac']}: {result['selection_basis']}")
    if not result['identity_confirmed']:
        print('I will check and record this candidate, but keep the collection marked PROVISIONAL for identity review, outside confirmed training data.')
    args.discovery_selection = result
    save(run / "identity" / "automatic_selection.json", result)
    return result["mac"]


def session_decision(meta, metrics, expected_target, activity, confirmed):
    reasons = []
    if meta.get("result") != "completed" or not meta.get("end_received"):
        reasons.append("incomplete")
    if meta.get("operator_stopped"):
        reasons.append("operator_stopped")
    status = meta.get("latest_firmware_status") or {}
    if status.get("target") != expected_target:
        reasons.append("receiver_target_mismatch")
    if not status.get("locked") or status.get("channel") != meta.get("requested_mode"):
        reasons.append("channel_not_locked")
    if meta.get("requested_secondary") and (
            status.get("reported_secondary") != meta['requested_secondary'] or
            status.get("reported_primary") != meta['requested_mode']):
        reasons.append("secondary_not_confirmed")
    if meta.get("quality_findings"):
        reasons.append("acquisition_findings")
    if not confirmed:
        reasons.append("identity_unconfirmed")
    if not metrics.get("target_tx_frames"):
        reasons.append("target_not_transmitting_in_capture")
    if activity not in ("idle", "off", "background") and not metrics.get("target_tx_data_frames"):
        reasons.append("active_workload_data_not_decoded")
    return reasons


def append_manifest(root, row):
    path = root / "manifest.csv"
    entries = []
    if path.exists():
        with path.open(newline="", encoding="utf8") as stream:
            entries = list(csv.DictReader(stream))
    if any(e.get("raw_sha256") == row["raw_sha256"] for e in entries):
        return
    fields = list(dict.fromkeys([k for e in entries + [row] for k in e]))
    temp = path.with_suffix(".tmp")
    with temp.open("w", newline="", encoding="utf8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader(); writer.writerows(entries + [row])
    temp.replace(path)


def check_capture(folder, profile, require_identity=True):
    meta = json.loads((folder/'session.json').read_text())
    capture_quality = meta.get('quality_findings', {})
    try:
        checks = inspect_traffic(folder, profile['mac'], profile['receiver'],
                                 profile.get('min_data_frames', DEFAULT_MIN_FRAMES),
                                 profile.get('min_data_rate', DEFAULT_MIN_RATE))
    except (ValueError, OSError, KeyError) as exc:
        checks = dict(findings=['traffic_inspection_failed: '+str(exc)])
    checks['findings'].extend(session_decision(meta, checks, 'esp32'+profile['receiver'],
                                              profile.get('activity', 'unknown'), profile['identity_confirmed']))
    try:
        audit(folder)
    except (ValueError, OSError, KeyError) as exc:
        checks['findings'].append('replay_failed: '+str(exc))
    checks['findings'] = list(dict.fromkeys(checks['findings']))
    checks['capture_quality_findings'] = capture_quality
    if not require_identity:
        checks['findings'] = [f for f in checks['findings'] if f != 'identity_unconfirmed']
        checks['identity_status'] = 'supported' if profile['identity_confirmed'] else 'provisional'
    save(folder/'traffic_check.json', checks)
    write_session_readme(folder, dict(review=(REVIEW_MESSAGE if checks['findings'] else
        'Traffic screening passed; this is not proof of model suitability or complete RF reception.')+
        ' Per-field availability, thresholds and findings: traffic_check.json.'))
    return checks


def preflight(args, run, profile):
    print('Traffic check: automatic 20/40 MHz survey, then short fixed captures. No dataset labels yet.')
    sample = SimpleNamespace(**vars(args))
    sample.output = str(run/'preflight')
    code = survey(sample, record)
    report_path = next((run/'preflight').glob('*_width_survey_*/survey.json'), None)
    report = json.loads(report_path.read_text()) if report_path else {}
    if report.get('result') == 'interrupted':
        raise KeyboardInterrupt
    findings, checks = [], []
    if code or report.get('result') != 'completed':
        findings.append('preflight_survey_not_clean: '+report.get('result', 'missing_report'))
    comparisons = [r for r in report.get('runs', []) if r['phase']=='compare']
    expected = set(settings(report['primary'])) if report.get('primary') else set()
    actual = {None if r['secondary']=='none' else r['secondary'] for r in comparisons}
    if not comparisons or actual != expected:
        findings.append('missing_receiver_setting_checks')
    for item in comparisons:
        folder = report_path.parent/item['folder']
        try:
            check = check_capture(folder, profile, require_identity=False)
        except (ValueError, OSError, KeyError) as exc:
            check = dict(findings=['check_failed: '+str(exc)])
        checks.append(dict(folder=str(folder), **check))
        if check['findings']:
            findings.append('traffic_review_required: '+item['folder'])
        print(f"{item['secondary']} / ch{item['primary']}: {check.get('target_tx_data_frames', 0)} outgoing data frames; "
              f"{check.get('target_tx_data_frames_per_s', 0):.2f}/s; findings={check['findings'] or 'none'}")
        quality = check.get('capture_quality_findings', {})
        if quality:
            print('  Receiver capture loss/errors: ' + ', '.join(f'{key}={value}' for key, value in quality.items()))
        print(f"Fields observed in target transmissions: {sum(bool(n) for n in check.get('field_nonempty_target_rows', {}).values())}/47. "
              'See traffic_check.json for conditional blanks and missing applicable fields.')
    result = dict(passed=not findings, findings=findings, sessions=checks,
                  limitation='47 columns are verified with per-field availability; conditional blanks are normal. No guarantee of complete RF reception.')
    save(run/'traffic_check.json', result)
    (run/'README.md').write_text('# Traffic check\n\nUnlabelled preflight before dataset collection. '
        'See traffic_check.json for field availability, minimum-traffic thresholds and results. '
        'Each capture has its own five-section README.\n\n'+
        ('Passed; full collection can proceed.' if result['passed'] else REVIEW_MESSAGE)+'\n', encoding='utf8')
    if not result['passed']:
        print(REVIEW_MESSAGE)
        print(f'No full dataset recording started. Evidence: {(run/"traffic_check.json").resolve()}')
    else:
        print('Traffic check passed at all requested receiver settings. Some of the 47 fields are PHY-dependent and may remain blank.')
    return result['passed']


def organise(root, survey_root, profile, run_id):
    report_path = survey_root / "survey.json"
    report = json.loads(report_path.read_text())
    outcomes = []
    comparisons = [item for item in report['runs'] if item['phase']=='compare']
    checks = {}
    for item in comparisons:
        source = survey_root/item['folder']
        if (source/'session.json').exists():
            meta = json.loads((source/'session.json').read_text())
            checks[item['folder']] = check_capture(source, dict(profile, mac=meta['camera_mac']))
        else:
            checks[item['folder']] = dict(findings=['session_metadata_missing'])
    batch_review = any(check['findings'] for check in checks.values())
    sample_label = 'positive' if profile['device_class']=='camera' else 'negative'
    batch_name = f"{slug(profile['device'])}_{run_id.split('_')[0]}_{slug(profile['activity'])}_{sample_label}_{run_id.split('_')[-1]}"
    batch = (root/'runs'/run_id/'review' if batch_review else root/'dataset')/batch_name
    for item in comparisons:
        source = survey_root / item['folder']
        if not (source / 'session.json').exists():
            outcomes.append(dict(status='review_required', session_folder=str(source),
                                 quality_findings=['session_metadata_missing']))
            continue
        meta = json.loads((source / "session.json").read_text())
        metrics = item
        reasons = session_decision(meta, metrics, "esp32" + profile['receiver'],
                                   profile['activity'], profile['identity_confirmed'])
        traffic = checks[item['folder']]
        reasons = list(dict.fromkeys(reasons + traffic['findings']))
        if batch_review and not reasons:
            reasons.append('another_setting_in_collection_requires_review')
        width = meta.get('requested_width_mhz', 20)
        secondary = meta.get('requested_secondary', 'none')
        sample_label = 'positive' if profile['device_class']=='camera' else 'negative'
        state = 'review_required' if reasons else 'acquisition_checked'
        dest = batch / (f'{width}mhz' + (f'_{secondary}' if width==40 else ''))
        if source.resolve() != dest.resolve():
            if dest.exists():
                raise FileExistsError(dest)
            dest.parent.mkdir(parents=True, exist_ok=True)
            original_hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in source.iterdir() if p.is_file()}
            shutil.move(str(source), str(dest))
            assert all(hashlib.sha256((dest / n).read_bytes()).hexdigest() == h
                       for n, h in original_hashes.items()), 'Migration checksum mismatch'
            item['folder'] = os.path.relpath(dest, survey_root)
            # Update the inventory immediately so a later reporting failure cannot orphan data.
            save(report_path, report)
        context = dict(setup=profile['setup'], identity_basis=profile['identity_basis'],
                       capture_scope=profile.get('capture_scope', 'all'),
                       review=f"Collection status: {state}. Findings: {reasons or 'none'}. See traffic_check.json for field availability and screening thresholds. This is an acquisition check, not proof of model suitability." + (' '+REVIEW_MESSAGE if reasons else ''),
                       additional_findings=f"Physical device alias: {profile['device']}. Activity: {profile['activity']}. Experiment: {run_id}. Keep its widths and repeat windows in the same evaluation partition.",
                       recording_output_root=str(root / 'runs'))
        write_session_readme(dest, context)
        if reasons:
            print(REVIEW_MESSAGE)
            print(f'Review-only capture (not promoted): {dest}; findings: {reasons}')
        schema_csv = 'camera_packets.csv' if meta.get('capture_scope') == 'target' else 'all_wifi_packets.csv'
        row = dict(session_id=f"{meta['token']:08x}", run_id=run_id,
                   session_folder=str(dest), target_packets_csv=str(dest/'camera_packets.csv'),
                   device_class=profile['device_class'], activity=profile['activity'],
                   sample_label=sample_label,
                   collection_folder=str(batch), training_eligible=not bool(reasons),
                   capture_scope=meta.get('capture_scope', 'all'),
                   identity_status=profile.get('identity_status', 'confirmed' if profile['identity_confirmed'] else 'provisional'),
                   traffic_check_json=str(dest/'traffic_check.json'),
                   physical_device_alias=profile['device'], target_mac=meta['camera_mac'],
                   primary=meta['requested_mode'], receiver_width_mhz=width, secondary=secondary,
                   measured_seconds=metrics.get('measured_seconds', ''), status=state,
                   quality_findings=json.dumps(reasons),
                   schema_columns=len(next(csv.reader((dest/schema_csv).read_text().splitlines()))),
                   receiver_target=(meta.get('latest_firmware_status') or {}).get('target',''),
                   firmware_sha256=(meta.get('latest_firmware_status') or {}).get('firmware_sha256',''),
                   raw_sha256=hashlib.sha256((dest/'raw_serial.bin').read_bytes()).hexdigest())
        append_manifest(root, row)
        outcomes.append(row)
    if outcomes:
        batch.mkdir(parents=True, exist_ok=True)
        (batch/'README.md').write_text('# '+profile['device']+' — '+profile['activity']+'\n\n'
            'One collection, with separate receiver settings below. 20 MHz and 40 MHz are sequential listening tests, not duplicate files. '
            'A 40 MHz receiver setting can still receive only 20 MHz frames. Each child has its own data and five-section README.\n\n'
            f"Requested class: {profile['device_class']} ({sample_label}). Identity: {profile.get('identity_status', 'confirmed' if profile['identity_confirmed'] else 'provisional')}. "
            f"Collection status: {'REVIEW REQUIRED — not confirmed training data' if batch_review else 'acquisition checked'}.\n\n"
            +'\n'.join(f"- [{Path(row['session_folder']).name}/README.md]({os.path.relpath(Path(row['session_folder'])/'README.md',batch).replace(chr(92),'/')}): {row['status']}" for row in outcomes)+'\n',encoding='utf8')
    return outcomes


def main(repo):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, help='Reuse a local JSON profile; MAC and workload are reconfirmed')
    parser.add_argument('--port', help='Optional serial override; normally auto-selects the unique USB receiver')
    parser.add_argument('--check', action='store_true', help='Check Python/dependencies and list ports, without recording')
    parser.add_argument('--seconds', type=positive, help='Seconds per receiver setting')
    parser.add_argument('--probe-seconds', type=positive, default=2, help='Dwell per discovery setting; increase for quiet devices')
    parser.add_argument('--preflight-seconds', type=positive, default=10, help='Traffic check seconds per fixed receiver setting')
    parser.add_argument('--min-data-frames', type=positive, default=DEFAULT_MIN_FRAMES, help='Minimum outgoing payload-carrying frames per checked session')
    parser.add_argument('--min-data-rate', type=positive, default=DEFAULT_MIN_RATE, help='Minimum outgoing payload-carrying frames/s (screening heuristic)')
    parser.add_argument('--capture-scope', choices=('target','all'), help='target MAC only (default) or all decoded channel traffic')
    opts = parser.parse_args()
    os.chdir(repo)
    ports = list(list_ports.comports())
    if opts.check:
        for port in ports:
            print(f"{port.device}: {port.description}")
        selected = select_port(ports, opts.port)
        print(f'Automatic receiver connection: {selected.device} ({selected.description})')
        print('Python and pyserial available. Firmware/receiver reception is checked on the first capture.')
        return 0
    profile = json.loads(opts.profile.read_text(encoding='utf-8-sig')) if opts.profile else {}
    profile['receiver'] = choice('Receiver', ('c5','s3'), profile.get('receiver','c5'))
    profile.update(min_data_frames=opts.min_data_frames, min_data_rate=opts.min_data_rate,
                   preflight_seconds=opts.preflight_seconds)
    connection = select_port(ports, opts.port, profile.get('receiver_connection'))
    port = connection.device
    profile['receiver_connection'] = {k:getattr(connection,k,None) for k in ('vid','pid','serial_number')}
    print(f'Using receiver connection {port}: {connection.description}. Firmware chip is verified when capture starts.')
    root = Path('recordings') / profile['receiver']
    run_id = stamp(); run = root / 'runs' / run_id
    run.mkdir(parents=True)
    args = SimpleNamespace(port=port, baud=921600, state='unknown', camera=None,
                           output=str(run), channel=0, secondary='auto', probe_seconds=opts.probe_seconds,
                           duration=opts.preflight_seconds, labels=None, notes='Unlabelled traffic/field availability check before dataset collection.',
                           expected_target='esp32'+profile['receiver'], capture_scope='all')
    print('This workflow uses 2.4 GHz and automatically surveys 20/40 MHz settings.')
    current = ask('Current MAC (or find for guided power-off/on discovery)', profile.get('mac','find'))
    save(run/'profile.json', profile)
    try:
        if current.lower() == 'find':
            mac = discover(args, run)
            if not mac:
                save(run/'result.json', dict(result='identity_unresolved'))
                print(f'Identity unresolved; evidence: {run.resolve()}')
                return 2
            selection = args.discovery_selection
            basis = selection['selection_basis']
            profile.update(identity_confirmed=selection['identity_confirmed'], identity_status=selection['identity_status'])
        else:
            mac = camera_mac(current)
            source = choice('Where did this MAC come from?', ('device-settings','verified-power-test','traffic-guess'), 'device-settings')
            if source == 'traffic-guess':
                save(run/'result.json', dict(result='identity_unresolved', candidate_mac=mac,
                     reason='Address selected by traffic volume only; no identity confirmation.'))
                print('Traffic volume alone does not identify the device. Use find for a guided power test, '
                      'or check with AI/router settings. No labelled dataset started.')
                return 2
            basis = ('Operator checked the current MAC in device/router settings.' if source=='device-settings' else
                     'Operator reports a separately verified controlled power test.')
            profile.update(identity_confirmed=choice('Confirm current MAC belongs to this device', ('yes','no'),'yes')=='yes',
                           identity_status='operator_confirmed')
            if not profile['identity_confirmed']:
                save(run/'result.json', dict(result='identity_unconfirmed'))
                print('Device identity unresolved. No labelled recording started.')
                return 2
        profile.update(mac=mac, identity_basis=basis)
        args.camera = mac
        profile['capture_scope'] = opts.capture_scope or choice(
            'Capture scope', ('target','all'), profile.get('capture_scope','target'))
        args.capture_scope = profile['capture_scope']
        print('Target scope queues only frames addressed to or sent by this MAC. All scope keeps every decoded channel observation.')
        save(run/'profile.json', profile)
        if choice('Run the intended device activity for the traffic check. Ready?', ('yes','cancel'),'yes')!='yes':
            save(run/'result.json', dict(result='cancelled_before_capture'))
            return 1
        if not preflight(args, run, profile):
            save(run/'profile.json', profile)
            save(run/'result.json', dict(result='traffic_review_required', exit_code=2))
            print('Traffic check finished; you may stop the workload.')
            return 2
        profile['device_class'] = choice('Is the physical device a camera or non-camera?', ('camera','non-camera'), profile.get('device_class','camera'))
        profile['device'] = ask('Device name/model (reuse this name for the same physical device)', profile.get('device',''))
        slug(profile['device'])
        profile['activity'] = ask('Activity (streaming, idle, tiktok, upload, etc.)', profile.get('activity','streaming'))
        slug(profile['activity'])
        profile['duration'] = opts.seconds or positive(ask('Seconds per full receiver setting', str(profile.get('duration',90))))
        print('Setup can be unknown. Record connected band, AP/topology, distance, obstacles and workload settings.')
        profile['setup'] = ask('Experiment setup', profile.get('setup','Unknown; not supplied by operator.'))
        if choice('Keep the stated activity stable for the full 20/40 MHz recordings. Ready?', ('yes','cancel'),'yes')!='yes':
            save(run/'result.json', dict(result='cancelled_after_preflight'))
            return 1
        save(run/'profile.json', profile)
        profile_path = Path('profiles')/(slug(profile['device'])+'.json')
        save(profile_path, profile)
        args.camera = mac
        args.duration, args.notes = profile['duration'], profile['setup']
        args.state = profile['activity'] if profile['device_class']=='camera' and profile['activity'] in (
            'streaming','idle','off','motion','motion-triggered','background','unknown') else 'unknown'
        args.labels = [dict(mac=mac, alias=profile['device'], device_class=profile['device_class'],
                            activity=profile['activity'], start_s=0, end_s=None, identity_basis=basis)]
        args.report_context = dict(setup=profile['setup'], identity_basis=basis)
        result = survey(args, record)
        print('Activity-dependent capture finished; you may stop the workload.')
        survey_path = next(run.glob('*_width_survey_*/survey.json'), None)
        outcomes = organise(root, survey_path.parent, profile, run_id) if survey_path else []
        result = 1 if result==1 else 2 if result==2 or any(e['status']=='review_required' for e in outcomes) else 0
        save(run/'result.json', dict(exit_code=result, sessions=outcomes))
        (run/'README.md').write_text('# Collection run\n\nProfile and operator setup: profile.json. Outcome: result.json. '
            'Preflight results: traffic_check.json. Survey evidence and per-probe reports are in the survey folder. Measurements listed below each have their own five-section README.\n\n'
            +'\n'.join(f"- {e['status']}: {e['session_folder']}" for e in outcomes)+'\n', encoding='utf8')
        if not (root/'README.md').exists():
            (root/'README.md').write_text('# Recorder output\n\nOpen manifest.csv for session labels, quality and paths. '
            'Acquisition-checked collections are in dataset/<device>_<UTC-date-time>_<activity>_<positive-or-negative>_<run-id>/, with 20mhz/ and legal 40mhz_above/below children. '
            'Each session has a README. Runs contain discovery evidence and attempts needing review. '
            'Profiles are at repository-root profiles/. Acquisition checks do not establish general model suitability.\n', encoding='utf8')
        print(f'Run report: {(run/"README.md").resolve()}\nManifest: {(root/"manifest.csv").resolve()}\nProfile: {profile_path}')
        return 1 if result==1 else 2 if result==2 or any(e['status']=='review_required' for e in outcomes) else 0
    except KeyboardInterrupt:
        save(run/'result.json', dict(result='operator_interrupted'))
        print(f'Interrupted; evidence preserved in {run}')
        return 1
    except (OSError, ValueError, RuntimeError, KeyError, argparse.ArgumentTypeError) as exc:
        save(run/'result.json', dict(result='failed', error=str(exc)))
        print(f'Collection stopped: {exc}. Evidence preserved in {run}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main(Path(__file__).resolve().parents[1]))
