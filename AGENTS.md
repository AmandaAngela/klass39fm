# Wi-Fi recorder working guide

Read README.md, CAPSTONE_CONTEXT.md and docs/measurements.md before changing the collection workflow. Read docs/firmware.md before building/flashing. This is Stage 1 collection and verification; automated camera/non-camera classification belongs to Stage 5.

## Normal collection

- Use `python collect.py` from the root, or reuse an ignored profile with `--profile`. The maintained implementation is in recorder/. Do not recreate one-off collection/curation scripts for routine runs.
- Auto-select a unique USB receiver connection, ignoring Bluetooth; use saved USB identity when unambiguous. Never hardcode a COM number or treat a bridge name as chip proof. Multiple possible receivers require disconnecting extras or an explicit --port. Capture still verifies the firmware target.
- Explain find as physical ON/OFF/ON steps. After those steps automatically select the strongest eligible candidate without a MAC-selection/identity-confirmation prompt. Rank same-address matches first, then after/before outgoing data counts; require at least 20 after-restart data frames and absence during OFF. Only a unique same-address match with sufficient before/after data gets power_test_supported status. Changed-address or competing matches remain provisional but may proceed through traffic checks and record into review storage. No candidate probability or camera class is inferred. Manual MAC entry must state its source, with traffic guesses unresolved rather than invented device-settings evidence.
- The normal collector asks for receiver/MAC, then performs an unlabelled preflight before asking class/name. Require all requested settings to pass replay, schema/applicable-field and traffic checks. Defaults: 10 seconds per fixed preflight setting, at least 20 outgoing payload-carrying frames and 1 frame/s. These are documented screening heuristics, not evidence of full RF visibility. Conditional blanks among 47 fields are normal. Save per-field counts in traffic_check.json.
- On insufficient traffic or missing applicable measurements, print CHECK WITH AI, preserve diagnostic evidence, and stop before the full dataset capture. Reapply the gate to completed full captures so a workload stopping after preflight is quarantined. Legitimate idle/low-rate data can need review; do not erase it or infer a 2x2 cause. Change thresholds only with a documented experimental rationale.
- Reuse operator-supplied identity, active MAC, connected band, activity and duration. Ask only for missing facts. Never hardcode experimental MACs, channels or device allowlists in tracked files.
- Every normal repeat must begin with automatic primary AND secondary discovery. The helper surveys 20 MHz and legal 40 MHz pairs, then holds the selected primary during sequential comparisons. Do not silently substitute a 20 MHz-only run or an earlier channel. Increase probe dwell for quiet targets.
- Ground truth comes from confirmed physical identity. Activity is separate: an idle camera remains a camera. Unknown-MAC controlled on/off/on observations provide candidates, not proof or classifier labels. Recheck private/reboot MAC changes. Keep ambiguity in run evidence.
- Keep workload and placement consistent. Monitor authorised capture until it completes, fails with a diagnosed cause or the operator stops it. Tell the operator when workload-dependent recording ends. Do not silently continue after an interruption.
- Receiver settings do not describe every frame's bandwidth. Review driver readback for wide requests and actual per-frame PHY width/mode. A wide capture can contain only 20 MHz data.
- Incomplete, acquisition-flagged or unsupported active-device captures require review. Sparse confirmed idle observations may be useful; do not equate sparse with invalid. An entirely unobserved target stays review-required. The earlier largely undecoded PC YouTube samples remain excluded from the current training selection, not a permanent ban on PCs.

## Outputs and explanation

One run creates one collection: recordings/<receiver>/dataset/<device>_<UTCdate-time>_<activity>_<positive-or-negative>_<run-id>/ with child 20mhz/, 40mhz_above/ and/or 40mhz_below/. The parent README indexes these sequential receiver tests; each child has its own README and capture files. If any setting needs review or identity is provisional, keep the whole collection together under runs/<run_id>/review/<same-collection-name>/ with training_eligible=false. Preflight checks acquisition independently of identity; full collection promotion requires both. Ask physical class and device name after preflight passes, keeping operator class distinct from MAC-association confidence. Preserve historical paths unless the operator requests regrouping, and verify hashes/update active references when regrouping. Profiles remain private. Do not create duplicate raw finaliser copies or mix S3 into C5.

**Every session needs its own README**, including incomplete attempts where files exist:
1. Summary of that recording.
2. Files/code used and their roles.
3. Reproduction commands, parameters and purpose.
4. Actual setup, labels/identity basis, frame types, extracted fields, processing, duration/counts and quality results.
5. Evidence-based Stage 2 suggestions, distinguished from processing actually performed.

The recorder/report generator supplies measured facts. Complete operator-known context without inventing setup details. Preserve context and correction history when updating reports/labels. A batch/root README is only an index and cannot replace individual reports.

Replay with `python recorder/audit_recording.py $sessionFolder`. Review boundaries, tuning, target attribution, queue/transport/parser findings and schema. Replay consistency does not prove complete RF visibility. Keep source raw rows, timestamps, retries and identifiers unchanged. Review status means not automatically selected for training.

Future training selections should reference canonical paths/hashes rather than duplicate raw sessions. Keep device/experiment groups together across widths and windows; hold out physical devices for generalisation. Use a common named feature schema and identical preprocessing at training/inference. Do not use identity or collection conditions as unexplained shortcuts.

## Changes, cleanup and Git

- Update README/file descriptions and reproduction instructions with Stage 1 source changes. Acquisition/schema changes need compatible decoding and replay. Add regression coverage for real failure cases.
- Identify the connected chip before flashing; separate build/configuration per target. Carry authorised builds through boot verification and recoverable failures. See docs/firmware.md.
- Preserve unrelated changes. Do not overwrite curated labels or remove existing reviewed sessions when appending.
- Keep old recordings, one-off analyses and provenance in ignored archive/. Before removing a historical source, create an archive, verify every archived file's SHA-256 against the source and write an inventory/path map. On Windows verify absolute removal targets stay beneath the intended repo, using native PowerShell file operations.
- Commit source, public instructions, generic configs and synthetic tests only. Keep real MACs, SSIDs, serials, personal paths, experiment results, profiles and data in ignored local storage. Existing tracked files are not protected by ignore rules.
- Inspect untracked files and diffs before any requested commit/push. Do not force-add outputs.

```powershell
python -m unittest discover -s tests -v
git diff --check
git status --short --untracked-files=normal
git diff --cached --stat
git diff --cached
```

No class model or cleaning transform should be added during collection without a new task. Full bytes/CSI or other fields may merit later experiments; propose them with schema compatibility and measured throughput/memory loss checks, not claims that omitted information has no value.
