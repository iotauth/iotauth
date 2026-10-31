# BLE Connection-Based Timing Integration — Work Report

**Date:** 2026-10-31
**Scope:** Integrate the existing BLE L2CAP authenticated response-time check
(`bluetooth_com/ble_timing.c`) into the robot/locker `BLE_RSSI` verification
path, as a timing enhancement of the existing RSSI mechanism (no new physical
requirement). Mirrors the existing Wi-Fi RSSI+timing integration. `main.tex`
was **not** modified.

## 1. Starting state (confirmed, not duplicated)

- `bluetooth_com/ble_timing.c` / `.h`: L2CAP authenticated nonce→HMAC
  challenge–response with per-round deadline, modes disabled/measure/enforce,
  and `ble_timing_request_interval()`. Already present; **reused as-is**.
- `bluetooth_com/ble_timing_test.c`: standalone two-Pi test with a **fixed test
  key**, independent of SST. Left unchanged.
- `examples/physical_presence/hk_check.h` `verify_ble_rssi()`: previously called
  **only** advertising-RSSI (`ble_adv_rssi_run`).
- The UWB positioning re-implementation done earlier this session is preserved
  (independent files).

## 2. Design decisions

- **Enhancement, not a new requirement:** timing is added under the existing
  `BLE_RSSI` method, exactly like `WIFI_RSSI` + Wi-Fi timing.
- **Separate channels:** the SST handshake/control runs over TCP
  (`--comm_type tcp`); the timing challenge–response runs over a **dedicated BLE
  LE L2CAP link** (`bt_link.c`), established separately. A relay bridging the
  BLE link therefore adds its forwarding delay to the measured RTT.
- **Real session auth:** `ble_timing_run()` is keyed with the **current SST
  session MAC key** (`session->s_key`), not the standalone test's fixed key.
  Fresh nonce, direction/round binding, and response authentication are kept
  from the existing implementation.
- **Parameters via CLI**, consistent with the existing Wi-Fi timing path
  (mode/rounds/deadline/recv-timeout are command-line options, not yet plan
  fields — see §7). Rounds and the receive timeout are validated by
  `ble_timing_run()`/`ble_timing.c` as before.
- **No silent fallback:** if timing is required but the BLE measurement link was
  not established, `verify_ble_rssi` returns abort (DENY), not RSSI-only.
- **BLE connection ≠ proximity:** establishing the L2CAP link is not treated as
  peer authentication or proximity; only the authenticated, timely exchange
  counts.
- **Freshness preserved:** the RSSI observation window (`observed_not_before` /
  `collection_completed` from the advertising sampling) is kept as the
  evidence's observation time; running timing afterward does **not** overwrite it
  to look more recent.
- **BLE deadline is separate from Wi-Fi's:** default deadline is 0 (measure); the
  Wi-Fi 5 ms deadline is **not** applied to BLE. The enforce deadline must be
  chosen from measured BLE RTTs.

## 3. Modes (`--ble-timing-mode`)

- `disabled` (default): unchanged RSSI-only behavior; no BLE measurement link.
- `measure`: establish the link, run the authenticated timing, record RTTs and
  validity, but the verdict is RSSI-only (timing not ANDed).
- `enforce`: verdict = RSSI pass **AND** every timing round authenticated and
  within the deadline. Any auth failure, receive timeout, or deadline overrun
  makes the check fail/abort.

## 4. Changed files

| File | Change |
|---|---|
| `examples/physical_presence/hk_check.h` | Include `ble_timing.h`/`bt_link.h`; add `ble_timing_*` + `ble_measure_sock` + `ble_timing_psm`/`interval_units`/`negotiated_units` to `co_location_options`; add the timing block to `verify_ble_rssi` (enforce ANDs, measure records; evidence/obs extended with timing fields). |
| `examples/physical_presence/physical_options.h` | Defaults; CLI flags `--ble-timing-mode/-rounds/-deadline-us/-recv-timeout-us/-psm/-interval-units`; `physical_requires_ble_timing()`; BLE-ready control-session handshake; `physical_ble_measure_setup_locker/robot()` (L2CAP accept/connect + interval request) and `physical_ble_measure_cleanup()` (guarded by `HAVE_BT_TRANSPORT`). |
| `examples/physical_presence/robot.c` | After the handshake, set up the BLE measurement link (connect to `--bt-peer`) when BLE timing is required; cleanup after cooperative verification. |
| `examples/physical_presence/locker.c` | Advertise/accept the BLE measurement link and signal the robot when BLE timing is required; cleanup after. |
| `examples/physical_presence/CMakeLists.txt` | Compile `ble_timing.c` into robot/locker (BlueZ branch). |

## 5. Plan / config and run commands

Auth selects `BLE_RSSI` as the PROXIMITY method as before (bench config
`prox_ble`); timing is turned on by the endpoints' command line. Example direct
integrated run (TCP control, BLE L2CAP measurement):

```
# Locker (pi43): advertises the BLE L2CAP link, measures/enforces timing
sudo ./locker locker_pi43.config --comm_type tcp --require-ble-rssi \
     --ble-timing-mode measure --ble-timing-rounds 20

# Robot (pi42): connects the BLE L2CAP link to the locker's LE address
sudo ./robot robot_pi42.config --comm_type tcp --require-ble-rssi \
     --bt-peer <LOCKER_BDADDR> --ble-timing-mode measure --ble-timing-rounds 20
```

Enforce adds `--ble-timing-mode enforce --ble-timing-deadline-us <US>` on both
sides, where `<US>` is chosen from the measured BLE direct-link RTTs.

## 6. Measurement and freshness notes

- **Timing boundary** (from `ble_timing.c`): per round, the verifier's RTT is
  `(response received + verified) − (just before sending the nonce)`, on its own
  clock. It is an application-level response time (crypto + host stack + BLE
  controller + connection-event scheduling + peer processing), **not** RF
  airtime; it rejects relays slower than the deadline, not a distance bound.
- Per round: response time, authentication validity, and deadline status are
  recorded (`valid`, `within_deadline`, `rtt_us[]`, medians).
- **Connection interval:** the robot (central) requests
  `--ble-timing-interval-units` (default 6 = 7.5 ms) and logs **both** the
  requested and the negotiated value read back from the LE Connection Update
  Complete event; `7.5 ms` is not assumed.
- Evidence and its observation time feed the existing action gate; enforce makes
  the combined RSSI∧timing verdict the gate evidence.

## 7. Build verification

- **macOS (no BlueZ):** `robot` and `locker` build cleanly — portable path and
  the `HAVE_BT_TRANSPORT`-off stubs compile and link; no warnings/errors.
- **pi43 (BlueZ):** clean build; `ble_timing.c` compiled into both `robot` and
  `locker`; `ble_timing_test` still builds; no warnings/errors.
- UWB `uwb_locate_test` / `uwb_range_test` still pass (earlier change intact).

## 8. Results to distinguish

- **Standalone BLE timing test** (`ble_timing_test`, fixed key): validates the
  L2CAP connect/accept + interval negotiation + timing exchange on real boards.
  Reported separately; **not** the integrated path.
- **Integrated path** (Auth → robot/locker `BLE_RSSI` → action gate with the
  current SST session key): software integration complete and build-verified; a
  **direct hardware pilot has not yet been run** (see §9).

## 9. Remaining work

- **Direct integrated pilot** on pi42/pi43: boards are currently free (the UWB /
  acoustic experiments are stopped). Needs the locker's LE address for
  `--bt-peer` and an Auth DB with the `BLE_RSSI` plan (bench `prox_ble`). To be
  run for correctness confirmation only, kept separate from the formal
  Direct/Relay repetitions.
- **BLE enforce deadline:** calibrate from measured BLE direct RTTs before any
  enforce run.
- **Plan-driven provisioning (optional):** move timing mode/rounds/deadline from
  CLI into the Auth plan, consistent with however the Wi-Fi timing path is
  eventually moved (both are CLI-driven today).
- **Checks to confirm on hardware:** RSSI-only path unchanged; real-session auth
  in the integrated path; enforce fails on auth failure/timeout/deadline
  overrun; RSSI pass + timing fail ⇒ action denied; BLE link failure ⇒ refused
  even with the TCP control session alive.

`main.tex` was not modified.
