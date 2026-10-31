# System Overhead (Section 7.3) V2 — Work Report

**Date:** 2026-10-31 (full measured campaign; pilot was 2026-10-30)
**Scope:** Re-implement the Section 7.3 system-overhead experiment for the
requirement/method taxonomy, with per-requirement and single-device
instrumentation, and produce the verification-latency table and the
integrated-plan stage-latency graph. `main.tex` was **not** modified.

**Status:** The full measured campaign (warmup 5 + measured 100 per config, 10
configs, `v2pilot` experiment dir) is complete. **Six configs produced clean
measured data** and are reported here as final. **Four configs failed on
hardware** (pi43 USB microphone hard-wedge for all acoustic configs; UWB
positioning intermittent) and are deferred for re-run after the microphone is
physically re-seated — see §8.

## 1. Changed code and scripts

- **C instrumentation** (`entity/c/examples/physical_presence/`, committed):
  `benchmark.h` now records a `check_timings[]` array — one entry per
  verification with `{check, method, kind (cooperative|single_device),
  start/end/duration_us, completed, accepted}` — replacing the single
  CO_LOCATION span. `verify_cooperative`/`verify_requirement` time each
  cooperative requirement; `locker.c` times `TEMPERATURE_CHECK` and
  `HUMIDITY_CHECK`; `robot.c` times `HUMAN_PRESENCE`. CO_LOCATION lookups were
  de-hardcoded to the cooperative-requirement set.
- **Harness** (`examples/system_overhead/bench.py`, untracked): new taxonomy
  config model. 11 configs — `s0` (single-device only) plus one cooperative
  requirement each (`prox_ir/lifi/acoustic/ble/wifi_rssi/wifi_timing/uwb`,
  `position_uwb`, `ambient_audio`) and `multi_prox_ambient`. Every config also
  runs the S0 single-device checks. Each config generates its own policy and
  catalog (only its selected methods, so Auth's choice is deterministic);
  results go to a new experiment directory, preserving prior data. The robot's
  camera detector is provided via `HUMAN_PRESENCE_CMD`/`PYTHONPATH`, correct
  under sudo. BLE connection-timing is **not** a config (amendment 1).
- **Analyzer** (`examples/system_overhead/analyze_v2.py`, new): reads the
  trials and emits `verification_latency_summary.csv`,
  `verification_latency.tex`, `stage_latency.csv`,
  `figures/baseline_stage_latency.{pdf,png}`, and
  `analysis_v2_metadata.json`.
- **Config fixes:** `examples/configs/physical_presence_remote.graph` grants
  robot1/locker1 `Microphone` and `Humidity`; the DB-regen SSH command adds
  `mvn` to `PATH`; the endpoint configs' Auth IP was corrected.

## 2. Instrumentation definitions

- Timestamps are each device's own `CLOCK_MONOTONIC`; the analyzer never
  subtracts across devices.
- **Procedure latency** (verification table): the `duration_us` of a check's
  own execution interval from `check_timings[]` — preparation, measurement,
  processing, and any required exchange/cleanup; excludes operation
  authorization and peer handshake. Camera timing includes capture, detector
  process start, model load, and inference.
- **Stage latency** (graph): `authorization`, `peer_handshake`,
  `single_device` (per-trial sum of that device's single-device check
  durations), `cooperative` (the cooperative span), and the directly measured
  `total` (robot: authorization start → ALLOW callback; locker: accept return →
  ALLOW callback).

## 3. Table columns (amendment 2 & 3)

`verification_latency.tex` columns: **Requirement | Method | Fixed parameters |
Successes/attempts | Median (ms) | p95 (ms) | p99 (ms)** — no Role/mode column
(measuring role is kept in the CSV/metadata). Median, p95 and p99 are computed
over the same joint-success trial set per row; unmeasured rows are `---`, never
0. The stage graph keeps its design: robot/locker panels, stacked stage
medians, measured total as a separate black marker (amendment 4).

## 4. Hardware

Auth on ada6000; robot (pi42) and locker (pi43), both Raspberry Pi 4B. ESP32
(thermistor + DHT11) on the locker's USB serial; Pi camera + MobileNet-SSD on
the robot; three Qorvo DWM3001CDK UWB anchors on the locker and one tag on the
robot. A CH340 USB instability was resolved by moving the ESP32 to a different
USB port; it then streamed stably (`TEMP=23.6 HUM=53`).

**USB microphone fault (campaign):** the locker's USB microphone (pi43,
`1-1.1.4`, JMTek `0c76:6013`, ALSA `CARD=MICROPHONE`) went into a hard-wedge
during the campaign. The SST acoustic path fails to switch the capture
alternate setting: ALSA `snd_pcm_set_params ... Connection timed out (errno
110)`, kernel `usb 1-1.1.4: 1:1: usb_set_interface failed (-110)`. A bare
`arecord` on the pre-existing altsetting still worked, which masked the fault.
A software USB reset (`usbreset`, sysfs unbind/rebind) did **not** recover it
(the device then reported `can't set config #1, error -110`); a physical
re-plug (or powered-hub power-cycle) is required. This blocked all acoustic
configs (prox_acoustic, ambient_audio, multi_prox_ambient).

## 5. Per-setting attempts/successes (measured campaign)

Warmup 5 + measured 100 per config; "joint successes" = both robot and locker
exit 0 (ALLOW). 1000 measured trials, **594 joint successes** total.

| Config | Attempts | Joint successes | Status |
|---|---|---|---|
| s0 (single-device only) | 100 | 100 | ✅ final |
| prox_ble | 100 | 100 | ✅ final |
| prox_lifi | 100 | 99 | ✅ final |
| prox_uwb (ranging) | 100 | 99 | ✅ final |
| prox_wifi_rssi | 100 | 98 | ✅ final |
| prox_wifi_timing | 100 | 96 | ✅ final |
| position_uwb | 100 | 2 | ❌ UWB positioning intermittent (control message not received, errno 11) |
| prox_acoustic | 100 | 0 | ❌ pi43 mic hard-wedge (§4) |
| ambient_audio | 100 | 0 | ❌ pi43 mic hard-wedge (§4) |
| multi_prox_ambient | 100 | 0 | ❌ pi43 mic hard-wedge + UWB |

`prox_ir` was excluded from the campaign (IR hardware marginal; it was not in
the 10-config run).

## 6. Results — final measured data (six clean configs)

Verification procedure latency (median / p95 / p99, ms), from
`verification_latency_summary.csv` / `verification_latency.tex`. Rows with no
usable data are the hardware-blocked configs (§8).

| Requirement / Method | Fixed parameters | Successes/attempts | Median | p95 | p99 |
|---|---|---|---|---|---|
| Temperature / THERMOMETER | min_temp=18 | 100/100 | 5.7 | 8.1 | 8.4 |
| Humidity / HUMIDITY | min_hum=30 | 100/100 | 683.6 | 1166.8 | 1271.9 |
| Human absence / CAMERA_PERSON | min_conf=0.5 | 100/100 | 3334.5 | 3360.2 | 3366.3 |
| Proximity / LIFI | 128 rounds, frac 0.8, deadline 2000 µs | 99/100 | 18235.1 | 18252.0 | 18254.9 |
| Proximity / BLE_RSSI | min −60 dBm, 20 samples, 10 s | 100/100 | 5899.0 | 7020.2 | 7121.7 |
| Proximity / WIFI_RSSI (rssi-only) | min −60 dBm, 20 samples, 100 ms | 98/100 | 2533.7 | 2839.7 | 3768.9 |
| Proximity / WIFI_RSSI (+ timing) | min −60 dBm, 20 samples, 100 ms | 96/100 | 2374.5 | 2896.6 | 3691.9 |
| Proximity / UWB (ranging) | max 150 cm, 20 samples, 10 s | 99/100 | 10532.4 | 10930.0 | 11117.8 |
| Proximity / IR | — | 0/0 | --- | --- | --- |
| Proximity / ULTRASOUND | — | 0/100 | --- | --- | --- |
| Position / UWB_POSITION | tol 50 cm, 15 samples, 3 anchors | 2/100 | --- | --- | --- |
| Shared acoustic env / AMBIENT_AUDIO | — | 0/100 | --- | --- | --- |

(UWB_POSITION has 2 successes — too few for a reliable percentile; treated as
not-measured pending re-run.)

Integrated-plan stage graph (`figures/baseline_stage_latency.{pdf,png}`): robot
and locker panels, stacked stage medians, measured total as a black diamond.
Robot end-to-end medians (directly measured total, incl. the 3.3 s camera
single-device check every config runs): s0 ≈ 3.70 s; prox_ble ≈ 10.19 s;
prox_wifi_rssi ≈ 12.41 s; prox_wifi_timing ≈ 12.40 s; prox_uwb ≈ 14.28 s;
prox_lifi ≈ 21.95 s (128-round optical exchange dominates). The figure will be
**regenerated** once the four blocked configs are re-run, so it fills the
currently-empty rows. (Note: the robot y-axis config labels render faint in the
current PNG — verify/adjust on the final regeneration.)

## 7. Freshness-integration scope

Single-device temperature/humidity/human-absence checks are enforced
fail-closed at their owning endpoint and are now individually timed, but their
integration into the gate's uniform per-requirement freshness validation
remains incomplete (as `main.tex` §Implementation states). The benchmark
retains the prototype's implemented gate behavior and does not assume uniform
freshness enforcement for these checks.

## 8. Blocked / deferred (re-run after hardware fix)

All blocked by hardware, **not** by the code or pipeline:

- **prox_acoustic, ambient_audio, multi_prox_ambient** (0/100 each) — pi43 USB
  microphone hard-wedge (§4). Needs a physical re-plug of the mic, then re-run
  (warmup 5 + measured 100 each).
- **position_uwb** (2/100) — UWB positioning aborts with "control message not
  received" (errno 11); the anchor/serial path is intermittent. It occasionally
  succeeds, so it is marginal rather than dead; re-run after a UWB check.
- **prox_ir** — excluded from the campaign (IR hardware marginal, 64/128 in an
  earlier pilot). Re-measure if IR is to appear in the final table.
- **Not faked / unimplemented** (deny if required): camera path-clearance,
  IR/LiFi receiving-alignment, dynamic QR. BLE connection-timing is excluded
  from this experiment per amendment 1.

Re-run plan: once the pi43 mic is re-seated and verified (`arecord -D
plughw:CARD=MICROPHONE,DEV=0 -d 1` plus one `prox_acoustic` smoke trial), run
the four configs into the same `v2pilot` dir and re-run `analyze_v2.py`; the
table rows and graph fill in automatically.

## 9. Key numbers directly from the data (six measured configs)

- Camera human-absence detection costs ≈ 3.33 s per check (capture + model load
  + inference), the dominant single-device cost; temperature ≈ 5.7 ms, humidity
  ≈ 684 ms (DHT11 read wait).
- Cooperative proximity procedure latency: Wi-Fi RSSI ≈ 2.4–2.5 s, BLE RSSI
  ≈ 5.9 s, UWB ranging ≈ 10.5 s (20 samples), LiFi ≈ 18.2 s (128 rounds).
- Robot end-to-end medians range 3.70 s (s0) to 21.95 s (prox_lifi); cooperative
  verification dominates every non-baseline plan.

Cross-check vs `main.tex` abstract (report only — not edited): the abstract
states end-to-end "3.04 to 32.86 seconds" and authorization "0.24 to 0.44 s".
Measured here: end-to-end 3.70–21.95 s (the upper 32.86 s likely came from a
config not yet successfully measured, e.g. acoustic/multi); authorization stage
median ≈ 0.16 s. These abstract numbers may be stale and should be re-derived
from the final dataset.

No claim is made here about verification accuracy, safety, or relay
resistance — this experiment measures execution cost only.
