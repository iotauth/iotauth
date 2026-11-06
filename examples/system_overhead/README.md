# System overhead benchmark

Latency of one protected operation (robot `RETRIEVE_ITEM`, locker
`LOCKER_OPEN`) for the six CO_LOCATION mechanisms: IR, LiFi, acoustic,
Bluetooth, Wi-Fi and UWB. Real sensors, a real Auth request and a real
authenticated peer session are used. After ALLOW the only "action" is a
software callback, so every number is software latency up to the action
decision. No motor or item transfer is included.

## What is measured

All times are on the measuring endpoint's own `CLOCK_MONOTONIC`, in
microseconds. Timestamps from different Pis are never subtracted from each
other. SSH, process start-up, builds and log copying are outside every
interval.

| Metric (requester) | Start | End |
|---|---|---|
| Authorization | right before `get_session_key_with_purpose()` for RETRIEVE_ITEM | right after it returns the key and plan |
| Peer handshake | right before the transport's connect call (TCP: `secure_connect_to_server()`; Wi-Fi: `connect_as_client()` on the direct link; BLE: `secure_connect_to_server_via_bt()`) | session ready |
| Cooperative verification | right before `verify_co_location()` | right after it returns |
| End-to-end | authorization start | first statement of the benchmark action callback, run by `action_gate_run()` after ALLOW |
| Local verification | — | always null (the policy requires CO_LOCATION only) |

- The peer handshake includes the locker's own Auth lookup.
- Cooperative verification includes waiting for the peer's direction and the report exchange.
- End-to-end is measured directly from its two timestamps. It is never computed as a sum of the stages.

The locker records the following:
- cooperative verification, the gate report and its callback time;
- for TCP and Wi-Fi only, its handshake from `accept()` returning to session ready (null for the other transports, whose accept is inside the handshake call);
- authorization and end-to-end are null, because the locker runs no operation authorization.

The benchmark callback reads the clock before anything else, and the gate
logs only after the callback returns. A DENY never runs the callback; that
trial has no end-to-end value and is not in any latency summary.

Code:
- `entity/c/examples/physical_presence/benchmark.h`, used by `robot.c` and `locker.c` through `--benchmark`;
- `bench.py` (runner);
- `analyze.py` (collector, tables, figures).

## Setup once

```bash
cd examples/system_overhead
python3 -m venv .venv && .venv/bin/pip install numpy matplotlib   # for analyze.py
cp placement.example.json my_placement.json   # fill in what was actually set up
```

Hosts default to `pi41@pi41` (Auth), `pi42@pi42` (robot) and `pi43@pi43`
(locker). Override them with `init --auth-host/--robot-host/--locker-host`
or `SYSOH_*_HOST`. The same requirements as
`../test_physical_presence_multihost.sh` apply: passwordless SSH and sudo,
`~/project/iotauth` on every host, and the sensors and radios connected.

## Commands

```bash
# 1. Experiment directory, 22 settings, manifest (no hosts needed)
python3 bench.py init --experiment sysoh-2026xxxx --placement my_placement.json

# 2. Copy this checkout to the hosts, check the sources match, build, record versions
python3 bench.py prepare --experiment sysoh-2026xxxx --sync

# 3. Pilot (10 attempts) of one baseline, e.g. Bluetooth first
python3 bench.py run --experiment sysoh-2026xxxx --setting ble_base --pilot 10

# 4. Formal block: 5 warmup + 100 measured attempts (fixed; failures kept)
python3 bench.py run --experiment sysoh-2026xxxx --setting ble_base --warmup 5 --attempts 100

# 5. Sweeps, same way, one setting per block, e.g.
python3 bench.py run --experiment sysoh-2026xxxx --setting ble_s40 --warmup 5 --attempts 100

# An interrupted block: finish only its not-yet-run trials
python3 bench.py resume --experiment sysoh-2026xxxx --block b003

# 6. Tables and figures (rerunnable at any time)
.venv/bin/python analyze.py ../../artifacts/system_overhead/sysoh-2026xxxx

# Stop anything this experiment started (its endpoints, Auth, Wi-Fi link)
python3 bench.py cleanup --experiment sysoh-2026xxxx

# Self-test of the analysis on synthetic data (temporary directory)
python3 test_analyze.py
```

Settings, from `bench.py init` (`settings.json` holds the full parameters):

| Mechanism | Baseline | Sweep settings |
|---|---|---|
| IR | `ir_base` (128 rounds) | `ir_r32`, `ir_r64` |
| LiFi | `lifi_base` (128 rounds) | `lifi_r32`, `lifi_r64` |
| Acoustic | `acoustic_base` | — |
| Bluetooth | `ble_base` (20 samples) | `ble_s5`, `ble_s10`, `ble_s40` |
| Wi-Fi | `wifi_base` (20 samples, 100 ms) | `wifi_s5`, `wifi_s10`, `wifi_s40`, `wifi_i25`, `wifi_i50`, `wifi_i200` |
| UWB | `uwb_base` (20 samples) | `uwb_s5`, `uwb_s10`, `uwb_s40` |

Each baseline also stands for the matching sweep value (for example,
Bluetooth samples=20), so it is measured once.

## What a block does

1. Uploads the setting's catalog and the policy snapshot to the Auth host and regenerates the Auth DB.
2. Copies the new credentials to both Pis.
3. Starts Auth (aborting if its ports are already in use) and, for Wi-Fi, the direct AP/station link. For Bluetooth, it unblocks the radio and reads the locker's address.

Then, for each trial:
1. A new locker process starts.
2. The runner waits until the locker is listening or advertising.
3. A new robot process starts with a timeout.
4. The runner waits for the locker to finish.
5. It stops only this run's processes, matched by the unique run ID.
6. It copies `robot/locker.{json,log,exit}` and writes `status.json`.

At the end, the block stops its Auth and the Wi-Fi link and copies the Auth log.

`schedule.json` lists every planned run ID before the block runs. A run is
never repeated under the same ID, and a resumed block runs only the IDs that
have no `status.json`.

## Output (`artifacts/system_overhead/<experiment_id>/`)

- `manifest.json`: commits, hashes of changed sources, binary hashes and build flags, host software and hardware, placement, policy, catalog and config hashes, key-state and attempt rules.
- `settings.json`, `schedule.json`, `config/` (policy and per-setting catalogs), `commands.log`.
- `trials/<run_id>/`: `robot.json`, `locker.json`, `robot.log`, `locker.log`, `*.exit`, `status.json` (raw, never modified).
- `auth_logs/<block>.log`.
- From `analyze.py`:
  - `endpoint_results.csv`, `trial_status.csv`, `latency_summary.csv`
  - `baseline_configuration.csv`, `sweep_configuration.csv`
  - `baseline_latency.csv`, `trial_accounting.csv`, `parameter_sweep_latency.csv`
  - `figures/baseline_stage_latency`, `baseline_end_to_end_latency`, `parameter_latency`, `endpoint_cooperative_latency` (`.png` and `.pdf`, captions in `figures/captions.json`), drawn by `plot_figures.py` from the CSVs alone; redraw one with `plot_figures.py <experiment_dir> --only <name>`
  - `analysis_metadata.json` (classification rules, percentile method, captions)

Trial status uses the first matching rule:
1. `infrastructure_failure`
2. `measurement_error`
3. `joint_success`
4. `protocol_or_action_failure`

The exact rules are in `analysis_metadata.json`. Latency summaries use only
`measured` runs that are `joint_success`. Median and p95 come from
`numpy.percentile(method="linear")`.

## Known limits

- The Bluetooth, Wi-Fi and UWB sample arrays are not kept, only their medians and counts. IR and LiFi keep per-round RTTs and correctness.
- The locker's Auth key lookup is not timed separately (`auth_key_lookup_latency_us` is not recorded). It is inside the requester's peer handshake.
- Placement is whatever `--placement` provides. The runner cannot measure it.
