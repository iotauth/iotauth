#!/usr/bin/env python3
"""Synthetic checks of analyze.py: trial classification, what is and is not
aggregated, attempt counting and percentiles. The fixture experiment is
generated in a temporary directory, never under artifacts/.

  python3 test_analyze.py
"""
import csv
import json
import os
import tempfile
import unittest

import numpy as np

import analyze


def requester(run_id, t0=1_000_000, auth=100_000, hs=50_000, coop=3_000_000,
              allow=True, mech="PASS", gate_gap=500):
    a1 = t0 + auth
    h0, h1 = a1 + 1000, a1 + 1000 + hs
    c0, c1 = h1 + 1000, h1 + 1000 + coop
    gate = c1 + gate_gap
    cb = gate + 20 if allow else None
    return dict(
        run_id=run_id, endpoint_role="requester", action="RETRIEVE_ITEM",
        selected_method="UWB", handshake_transport="tcp",
        parameters={"samples": 20}, freshness_bound_us=15_000_000,
        session_key_id="00", authorization_start_us=t0,
        authorization_end_us=a1, peer_handshake_start_us=h0,
        peer_handshake_end_us=h1, cooperative_start_us=c0,
        cooperative_end_us=c1, gate_time_us=gate,
        action_callback_start_us=cb, authorization_latency_us=auth,
        peer_handshake_latency_us=hs, local_verification_latency_us=None,
        cooperative_verification_latency_us=coop,
        end_to_end_latency_us=(cb - t0) if allow else None,
        observed_not_before_us=c0 + 10, collection_completed_us=c1 - 10,
        observation_time_known=True, evidence_age_us_at_gate=gate - c0 - 10,
        mechanism_outcome=mech,
        verification_result="PASS" if allow else "FAIL",
        action_decision="ALLOW" if allow else "DENY",
        denial_reason=None if allow else "STALE_EVIDENCE",
        callback_started=allow, observations=None, error_stage=None,
        measurement_status="ok")


def locker(run_id, coop=2_000_000, allow=True):
    c0, c1 = 5_000_000, 5_000_000 + coop
    rec = dict(
        run_id=run_id, endpoint_role="locker", action="LOCKER_OPEN",
        selected_method="UWB", handshake_transport="tcp",
        authorization_start_us=None, authorization_end_us=None,
        peer_handshake_start_us=4_000_000, peer_handshake_end_us=4_100_000,
        cooperative_start_us=c0, cooperative_end_us=c1,
        gate_time_us=c1 + 100, action_callback_start_us=c1 + 120
        if allow else None, authorization_latency_us=None,
        peer_handshake_latency_us=100_000,
        local_verification_latency_us=None,
        cooperative_verification_latency_us=coop,
        end_to_end_latency_us=None, observed_not_before_us=c0 + 5,
        collection_completed_us=c1 - 5, observation_time_known=True,
        mechanism_outcome="PASS",
        verification_result="PASS" if allow else "FAIL",
        action_decision="ALLOW" if allow else "DENY",
        callback_started=allow, error_stage=None, measurement_status="ok")
    return rec


class Fixture:
    def __init__(self, root):
        self.dir = os.path.join(root, "fixture-exp")
        os.makedirs(os.path.join(self.dir, "trials"))
        self.runs = []
        settings = dict(order=["uwb_base", "uwb_s5"], settings=dict(
            uwb_base=dict(setting_id="uwb_base", mechanism="UWB",
                          method="UWB", kind="baseline",
                          varied_parameter=None, value=None,
                          parameters={"samples": 20, "max_distance_cm": 150,
                                      "timeout_ms": 10000},
                          handshake_transport="tcp", freshness_bound_ms=15000,
                          sweeps=["samples"]),
            uwb_s5=dict(setting_id="uwb_s5", mechanism="UWB", method="UWB",
                        kind="sweep", varied_parameter="samples", value=5,
                        parameters={"samples": 5, "max_distance_cm": 150,
                                    "timeout_ms": 10000},
                        handshake_transport="tcp", freshness_bound_ms=15000,
                        sweeps=["samples"])))
        self.write("settings.json", settings)
        self.write("manifest.json", dict(placement="fixture",
                                         auth_network="fixture"))

    def write(self, name, obj):
        with open(os.path.join(self.dir, name), "w") as f:
            json.dump(obj, f)

    def add(self, run_id, phase, robot=None, locker_rec=None, status=None,
            run=True, setting="uwb_base"):
        self.runs.append(dict(run_id=run_id, setting_id=setting, phase=phase,
                              attempt_index=len(self.runs) + 1))
        if not run:
            return
        tdir = os.path.join(self.dir, "trials", run_id)
        os.makedirs(tdir)
        st = dict(run_id=run_id, infrastructure_errors=[], robot_exit_code=0,
                  locker_exit_code=0)
        st.update(status or {})
        for name, obj in (("status.json", st), ("robot.json", robot),
                          ("locker.json", locker_rec)):
            if obj is not None:
                with open(os.path.join(tdir, name), "w") as f:
                    json.dump(obj, f)

    def finish(self, duplicate_block=False):
        blocks = [dict(block_id="b001", setting_id="uwb_base",
                       runs=self.runs)]
        if duplicate_block:  # a resumed block lists the same runs again
            blocks.append(dict(block_id="b002", setting_id="uwb_base",
                               runs=self.runs[:2]))
        self.write("schedule.json", dict(blocks=blocks))


class AnalyzeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        f = self.f = Fixture(self.tmp.name)
        # Warmup success: never aggregated.
        f.add("w1", "warmup", requester("w1", coop=99_000_000),
              locker("w1"))
        # Five joint successes with known cooperative latencies.
        self.coops = [1_000_000, 2_000_000, 3_000_000, 4_000_000, 5_000_000]
        for i, c in enumerate(self.coops):
            rid = "ok%d" % i
            f.add(rid, "measured", requester(rid, coop=c), locker(rid))
        # Mechanism PASS but stale: DENY, no callback.
        f.add("stale", "measured", requester("stale", allow=False),
              locker("stale"))
        # Only one side allows.
        f.add("oneside", "measured", requester("oneside"),
              locker("oneside", allow=False))
        # Locker exited (e.g. timeout) without a record: ran, so protocol.
        f.add("nolocker", "measured", requester("nolocker"), None,
              status=dict(locker_exit_code=124))
        # Locker record never collected and no exit code: infrastructure.
        f.add("lost", "measured", requester("lost"), None,
              status=dict(locker_exit_code=None))
        # The peer failed; the runner stopped the still-waiting locker.
        f.add("stopped", "measured", requester("stopped", allow=False), None,
              status=dict(locker_exit_code=None,
                          locker_stopped_by_runner=True))
        # Runner-reported infrastructure error, even with both ALLOW.
        f.add("infra", "measured", requester("infra"), locker("infra"),
              status=dict(infrastructure_errors=["cannot collect"]))
        # A record from another run.
        f.add("wrongid", "measured", requester("other-run"),
              locker("wrongid"))
        # Out-of-order timestamps on the requester's own clock.
        bad = requester("badorder")
        bad["gate_time_us"] = bad["cooperative_start_us"] - 1
        f.add("badorder", "measured", bad, locker("badorder"))
        # Scheduled, not run yet: not an attempt.
        f.add("pending", "measured", run=False)
        f.finish(duplicate_block=True)
        analyze.analyze(f.dir, figures=False)

    def tearDown(self):
        self.tmp.cleanup()

    def csv_rows(self, name):
        with open(os.path.join(self.f.dir, name)) as fh:
            return list(csv.DictReader(fh))

    def test_classification(self):
        st = {r["run_id"]: r["trial_status"]
              for r in self.csv_rows("trial_status.csv")}
        for i in range(5):
            self.assertEqual(st["ok%d" % i], "joint_success")
        self.assertEqual(st["stale"], "protocol_or_action_failure")
        self.assertEqual(st["oneside"], "protocol_or_action_failure")
        self.assertEqual(st["nolocker"], "protocol_or_action_failure")
        self.assertEqual(st["lost"], "infrastructure_failure")
        self.assertEqual(st["stopped"], "protocol_or_action_failure")
        self.assertEqual(st["infra"], "infrastructure_failure")
        self.assertEqual(st["wrongid"], "measurement_error")
        self.assertEqual(st["badorder"], "measurement_error")
        self.assertNotIn("pending", st)
        # 1 warmup + 13 measured; the resumed block repeats w1/ok0, which
        # are still counted once.
        self.assertEqual(len(st), 14)

    def test_accounting(self):
        row = next(r for r in self.csv_rows("trial_accounting.csv")
                   if r["setting_id"] == "uwb_base")
        self.assertEqual(row["measured_attempts"], "13")
        self.assertEqual(row["joint_successes"], "5")
        self.assertEqual(row["protocol_or_action_failures"], "4")
        self.assertEqual(row["infrastructure_failures"], "2")
        self.assertEqual(row["measurement_errors"], "2")
        self.assertEqual(row["warmup_or_pilot_runs"], "1")
        self.assertEqual(sum(int(row[k]) for k in (
            "joint_successes", "protocol_or_action_failures",
            "infrastructure_failures", "measurement_errors")), 13)

    def summary(self, role, metric, setting="uwb_base"):
        return next(r for r in self.csv_rows("latency_summary.csv")
                    if r["setting_id"] == setting and r["endpoint_role"] ==
                    role and r["metric"] == metric)

    def test_percentiles_use_only_joint_successes(self):
        s = self.summary("requester", "cooperative_verification_latency_us")
        self.assertEqual(s["n"], "5")  # not the warmup, not the failures
        self.assertAlmostEqual(float(s["median_us"]), 3_000_000)
        self.assertAlmostEqual(float(s["p95_us"]), float(
            np.percentile(self.coops, 95, method="linear")))
        self.assertAlmostEqual(float(s["p95_us"]), 4_800_000)
        self.assertEqual(s["small_sample"], "True")

    def test_null_metrics_are_not_zero_samples(self):
        for role, metric in (("locker", "authorization_latency_us"),
                             ("locker", "end_to_end_latency_us"),
                             ("requester", "local_verification_latency_us"),
                             ("locker", "local_verification_latency_us")):
            s = self.summary(role, metric)
            self.assertEqual(s["n"], "0", (role, metric))
            self.assertEqual(s["median_us"], "")
        e2e = self.summary("requester", "end_to_end_latency_us")
        self.assertEqual(e2e["n"], "5")

    def test_unrun_setting_has_no_samples(self):
        row = next(r for r in self.csv_rows("parameter_sweep_latency.csv")
                   if r["setting_id"] == "uwb_s5")
        self.assertEqual(row["measured_attempts"], "0")
        self.assertEqual(row["end_to_end_median_ms"], "")

    def test_endpoint_rows_keep_raw_paths(self):
        rows = self.csv_rows("endpoint_results.csv")
        self.assertEqual(len(rows), 28)  # 14 runs x 2 endpoints
        r = next(x for x in rows if x["run_id"] == "stale" and
                 x["endpoint_role"] == "requester")
        self.assertEqual(r["action_decision"], "DENY")
        self.assertEqual(r["action_callback_start_us"], "")
        self.assertTrue(r["raw_log_path"].endswith("stale/robot.log"))


if __name__ == "__main__":
    unittest.main()
