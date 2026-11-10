# Capstone context — Portable Hidden Wi-Fi Camera Detector

## 1. Project objective

Develop a **small, portable, traveller-friendly device** that helps people discover and investigate **potentially hidden, actively transmitting Wi-Fi cameras** in unfamiliar environments such as accommodation or private rooms.

The device should identify **suspicious camera-like wireless activity** and, where feasible, help the user narrow down the transmitter's location. It is an investigation aid, **not proof** that a camera is present, hidden or unauthorised.

## 2. Core research question

Can patterns observable from Wi-Fi transmissions be used to distinguish actively transmitting cameras from ordinary Wi-Fi devices, **including camera brands and models that the system has never encountered during training**?

Explore traffic features such as packet/frame lengths, rates, inter-arrival timing, bursts, traffic direction and signal-strength behaviour, depending on what the selected receiver can capture. The approach should not depend primarily on a database of known camera MAC addresses, manufacturer identifiers or device signatures.

## 3. Detection concept

- **Discover:** Observe nearby Wi-Fi transmissions across channels and frequency bands supported by the selected hardware and permitted by local rules.
- **Measure:** Group observations by candidate transmitter or communication flow, and capture sufficient time-series information to analyse behaviour.
- **Assess:** Investigate whether the observed behaviour is consistent with active camera traffic, while reporting uncertainty and false-positive risks.
- **Locate (if feasible):** Explore relative signal-strength trends, antenna directionality or other practical methods to help find a suspicious transmitter.

The final architecture remains open; scanning, measurement and classification may require different hardware, software or processing strategies.

## 4. Hardware and product constraints

- Keep the solution **hardware-agnostic** during prototyping. Microcontrollers, ESP variants, wireless interfaces, RF receivers, antennas and other components may be changed based on experimental results.
- Prefer a **compact, portable design** suitable for travel, with a target hardware cost **under S$100** where practical.
- A smartphone may provide power, processing, controls or a user interface, but this is a possible design choice rather than a fixed requirement.
- Validate the capture capabilities and limits of each candidate receiver. A device that only supports 2.4 GHz Wi-Fi cannot detect 5 GHz-only Wi-Fi traffic; no passive Wi-Fi traffic method can reliably detect an inactive or wired-only camera.
- The project scope is **Wi-Fi camera detection**. No analog-camera receiver pathway is currently included.

## 5. Data collection and experimental method

Prioritise real, reproducible measurements **before committing to a particular ML model**.

- Collect recordings from **different Wi-Fi camera models** and **non-camera devices** under comparable conditions.
- Record multiple camera states where available: powered off (background baseline), connected/idle, active livestreaming, motion-triggered transmission and other relevant operating modes.
- Vary realistic conditions such as distance, obstacles, channel congestion, camera settings and network topology.
- Preserve **original receiver-observed packet/frame metadata** and session information (device identity for ground truth, state, channel, environment, time, firmware version, receiver configuration and capture-quality indicators).
- Keep raw records unchanged. Create separate derived data for filtering, cleaning or feature extraction, documenting each transformation.
- Explicitly measure and report known limitations such as dropped records, missing observation periods, channel-hopping gaps, repeated timestamps and uncertain frame reception.
- Use MAC addresses to associate records with known experimental devices, **not** as the main model input for camera classification.

## 6. Machine-learning direction (future stage)

- Investigate whether signal and traffic patterns can support **camera-like versus non-camera-like** classification.
- Prioritise **generalisability to unseen camera manufacturers and models**, rather than memorising known devices or sessions.
- Use appropriate independent evaluation, including holding out entire camera models/devices and recording sessions where feasible.
- Study class imbalance, false positives and false negatives; include non-camera devices with superficially similar traffic (e.g., uploads, video calls and streaming devices).
- Treat synthetic augmentation, smoothing, resampling and feature selection as hypotheses to validate—not assumptions to bake into raw collection.
- A high score separating one known camera's idle and streaming states does **not** establish general hidden-camera detection performance.

## 7. Real-world expectations and limits

A useful system must operate amid ordinary nearby Wi-Fi traffic without access to the network's router or credentials. However, capture coverage and channel timing depend on the radio hardware. Encryption can conceal content even where frame metadata is observable. Other activities can resemble video transmissions, and some cameras may be silent when nobody is viewing or uploading video.

Outputs should describe **candidate camera-like activity** and signal evidence, not claim certain identification without independent verification. Localisation should acknowledge multipath and measurement uncertainty.

## 8. Project development principles

- Treat component selections and model architecture as **experimental and revisable**.
- Make incremental prototypes and test claims against real recordings.
- Retain working implementations and avoid losing previous datasets.
- Document the reasoning behind design choices, measured trade-offs and remaining limitations.
- Keep detailed implementation notes, version-specific settings, known test-device identifiers and experiment results in separate logs rather than turning them into permanent project assumptions.

## Current phase

The project is currently focused on **prototyping Wi-Fi sensing and collecting dependable recordings**, not training or deploying the final classifier. Previous experiments with an ESP-family Wi-Fi sniffer demonstrate that over-the-air metadata collection is possible, but the final sensing hardware and software pipeline remain open to change.
