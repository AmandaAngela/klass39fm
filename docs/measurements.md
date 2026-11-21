# Measurements, rationale and limits

The research question is whether observable traffic and signal patterns generalise across unseen camera models. Collection preserves candidates for later feature discovery; it does not establish which features are predictive.

## Exported fields

The current host writes these 47 columns. Firmware wire versions 2, 3/4 and 5/6 carry 41, 45 and 61-byte records respectively. Historical CSVs have 23 or 31 columns; replay supports all three schemas. S3 leaves C5 extensions blank.

| Fields | Origin and meaning | Research purpose / caution |
| --- | --- | --- |
| host_utc, wire_seq, observation_id | Host batch receipt time, serial batch sequence, firmware eligible observation ID | Bookkeeping and loss/replay checks; host time is not individual RF arrival time |
| esp_timestamp_us | Raw 32-bit driver receive timestamp, microseconds | Timing, bursts and inter-arrival candidates; wraps about every 71.6 minutes |
| channel, rssi_dbm | Driver channel and transmitter RSSI in dBm | Channel coverage/signal variation; RSSI reflects placement and environment |
| frame_length_bytes | Whole-frame length including Wi-Fi overhead/FCS | Length distribution and observed byte rates; includes retries, not application bitrate |
| frame_control, sequence_control | Raw MAC-header controls | Preserve future header interpretations; absent controls stay blank |
| frame_type, frame_subtype | Derived from frame control; management=0, control=1, data=2 | Frame mix; beacons are management subtype8; not all data subtypes carry payload |
| to_ds, from_ds, retry | Header flags | Direction and retry context |
| sequence, fragment | Sequence-control decomposition | Repetition/fragment context; do not blindly deduplicate |
| qos_tid | Available QoS traffic identifier | Traffic priority context; missing is not zero |
| addr1_ra, addr2_ta, addr3, addr4 | Available header addresses | Immediate receiver/transmitter and forwarding context; short ACK/CTS have no TA |
| source, destination | Derived from DS/address fields | Original endpoint context; not necessarily the radio transmitter |
| phy_sig_mode | Normalised legacy/HT/HE/VHT indication (0/1/2/3) | Distinguish interpretation of rate/width fields |
| phy_mcs, phy_cwb | Applicable MCS and actual decoded width (0=20,1=40) | Rate/width context; interpretation depends on PHY mode |
| phy_aggregation, phy_sgi, phy_stbc | Applicable aggregation, short-GI and STBC indications | PHY effects on observed timing and reliability |
| phy_legacy_rate, noise_floor_dbm | Applicable raw legacy rate index and driver noise estimate (dBm) | Rate and signal-environment context; rate index is not Mbps |
| phy_rx_format, phy_sig_a1, phy_sig_a2 | C5 raw receive-format and signal words | Preserve information for future validated interpretations |
| driver_dump_length_bytes | C5 original driver dump length | Length-convention validation and traceability |
| rx_secondary_channel, phy_l_sig_rate | C5 raw secondary indication and L-SIG rate | Receiver/PHY context; not a MAC header or decoded payload |
| phy_rx_end_state, phy_sigb_length | C5 RX end state and SIG-B length | Reception/format diagnostics |
| phy_channel_estimate_valid, phy_group_addressed | C5 driver flags | Diagnostics; channel-estimate-valid is not CSI |
| phy_fec_coding | Derived applicable coding indication | PHY reliability context |
| phy_he_gi_ltf, phy_he_bss_color, phy_he_ul_dl, phy_he_dcm, phy_he_beamformed | Selected HE SU signal-field interpretations | HE context; absent/unsupported interpretations stay blank |

C5 HT fields are derived from raw HT-SIG. Selected HE SU fields are decoded separately; HE MU/TB interpretations are not assumed. HE MCS does not imply the same spatial-stream count as HT MCS. Current C5 bring-up recordings did not establish HE or HT40 reception simply by exposing these columns.

C5 length handling bounds header access by the smaller driver length and exports the larger as FCS-inclusive frame length, preserving the dump length. This addresses the tested SDK convention; revalidate on SDK/target changes. Earlier bring-up files used a different convention and should retain firmware/schema provenance.

## Capture and processing

The passive receiver does not join the target network. Firmware accepts supported management, data and control callbacks, checks header lengths/RX state, queues eligible measurements and exports CRC-protected serial batches of up to 32 observations. The bounded ring can still overflow during bursts or sustained receiver/transport load; inspect END counters and retain flagged sessions for review. Host code saves the raw stream and decodes valid batches. All-scope sessions write all channel observations to all_wifi_packets.csv and target matches to camera_packets.csv. Target-scope sessions write only camera_packets.csv because firmware has already limited the observations to the selected address. That filename also applies to non-camera devices.

The collector offers two capture scopes. `all` stores all decoded observations on the receiver channel; other devices must not inherit the selected target's class. `target` filters in firmware before queueing and stores frames where the selected MAC is the immediate receiver or transmitter, including AP-to-target replies. Target scope reduces unrelated queue traffic, but omits beacons and devices that do not address the selected MAC. Identity discovery without a known MAC uses all-channel scope. In either scope, use addr2_ta for attributable outgoing traffic. RSSI belongs to that transmitter, not an original source forwarded by an AP. camera_packets.csv matches addr1 or addr2 and therefore contains both directions, including AP-originated frames.

The exporter does **not** save frame-body bytes, FCS bytes, CSI or length-only multi-stream callbacks without a readable address header. This is the present design, not proof those observations lack value. Full bytes could preserve more header/body choices; protected bodies may remain encrypted. Adding them needs a versioned format, bounded memory/transport measurements and compatible replay. The serial CRC validates transport, not the radio frame FCS.

Both receivers use one spatial stream. A two-stream-capable phone/PC can send readable single-stream traffic; actual multi-stream data can remain inaccessible. Missing decoded data can also result from band, hopping, channel, distance, PHY, driver or parser limitations. C5's current firmware enables 2.4 GHz only; its other-band hardware capability is not enabled here.

## Quality and interpretation

The interactive collector first takes unlabelled fixed preflight captures after automatic 20/40 MHz discovery. traffic_check.json reports all 47 columns' nonempty counts for target-transmitted rows and missing applicable fields in outgoing payload-carrying data. Expected fields depend on receiver, PHY and MAC subtype: absent HE fields on HT frames, absent addr4 without four-address forwarding, absent QoS TID on non-QoS frames and absent C5 extensions on S3 do not fail screening. Raw C5 metadata is required for C5 data; HT and HE SU derived fields are checked where implemented. Unsupported PHY interpretations remain unproven even when raw fields exist.

By default every setting needs 20 outgoing payload-carrying frames and a measured rate of at least 1/s. These configurable thresholds are operational review gates, not validated completeness/model-quality criteria. Sparse legitimate idle devices may fail; preserve them for human/AI review. The gate cannot measure frames never delivered by the driver or diagnose spatial-stream count. It repeats on full recordings; failures stay outside the canonical dataset. Preflight and full-capture reports preserve the thresholds and evidence.

At END, eligible = sent + overflow + tx_lost; sent should match decoded rows. Inspect malformed/unsupported/RX errors, tune errors, CRC/sequence gaps and ring high-water. Some counters overlap; do not sum them into an invented RF-loss estimate. Raw replay proves consistency of saved exports, not reception of transmissions the driver never delivered.

Receiver 40 MHz settings and per-frame width are different. Confirm wide driver readback, then examine target data with mode HT and cwb=1 for HT40 evidence. A wide receiver can hear only 20 MHz frames. Sequential width differences can also reflect changing workload, not bandwidth.

## Stage 2 proposals

Keep originals intact. Derive separately documented views for lengths/rates, timing/bursts, direction, retries, PHY and RSSI variation. Preserve missing-value meaning, unwrap timestamps explicitly and examine gaps before choosing valid windows. Quiet confirmed idle data can be useful; an invisible active device cannot be treated as a quiet negative.

device_features.py --measured-duration uses BEGIN-to-END time. Burst windows begin at the first observation and end at the last observation's window, so silent leading/trailing coverage differs from full session coverage. Decide and document a common convention before training.

Use named common features across schemas, consistent feature order/window lengths and training-fitted transforms. Keep all widths/windows of a physical device/experiment together when splitting; hold out whole devices for generalisation. MAC, peer, channel, width and RSSI can expose collection conditions. They require evaluation rather than assuming a high score means camera detection.

Generated session READMEs provide concrete counts and rule-based suggestions. Broader feature discovery, data cleaning choices and classification are separate stages.
