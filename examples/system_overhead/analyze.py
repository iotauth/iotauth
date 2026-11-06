#!/usr/bin/env python3
"""Collects, classifies and summarizes one system-overhead experiment.

Reads only what the runner kept (schedule.json, settings.json and each
trials/<run_id>/{robot,locker}.json, status.json), writes CSV tables,
figures and analysis_metadata.json into the experiment directory, and
never changes the raw records.

  python3 analyze.py artifacts/system_overhead/<experiment_id> [--no-figures]
"""
import argparse
import csv
import datetime
import json
import os
import sys

import numpy as np

import plot_figures

PERCENTILE_METHOD = "linear"
SMALL_SAMPLE = 20  # fewer successful trials than this is flagged
METRICS = ["authorization_latency_us", "peer_handshake_latency_us",
           "local_verification_latency_us",
           "cooperative_verification_latency_us", "end_to_end_latency_us"]
ENDPOINT_FIELDS = [
    "experiment_id", "setting_id", "block_id", "run_id", "attempt_index",
    "phase", "endpoint_role", "action", "mechanism", "selected_method",
    "handshake_transport", "parameters", "freshness_bound_us",
    "session_key_id", "authorization_start_us", "authorization_end_us",
    "peer_handshake_start_us", "peer_handshake_end_us",
    "cooperative_start_us", "cooperative_end_us", "gate_time_us",
    "action_callback_start_us"] + METRICS + [
    "observed_not_before_us", "collection_completed_us",
    "observation_time_known", "evidence_age_us_at_gate",
    "mechanism_outcome", "verification_result", "action_decision",
    "denial_reason", "callback_started", "process_exit_code",
    "measurement_status", "error_stage", "raw_log_path", "observations"]

CLASSIFICATION_RULES = [
    "infrastructure_failure: the runner reported an infrastructure error "
    "(host/SSH/start/collection), or an endpoint has neither a result file "
    "nor an exit code and was not stopped by the runner (it never ran or "
    "could not be collected).",
    "measurement_error: a result file names another run_id, reports "
    "measurement_status other than ok, or a run that claims success lacks a "
    "required timestamp or has them out of order on its own clock.",
    "joint_success: both endpoints report mechanism_outcome PASS, "
    "verification_result PASS, action_decision ALLOW and a callback start, "
    "with all required timestamps valid.",
    "protocol_or_action_failure: everything else that ran: FAIL, ABORT, "
    "DENY, an error stage, or an endpoint that exited (including by the "
    "runner's timeout) or was stopped by the runner after its peer ended, "
    "without a result file.",
    "The first matching rule, in this order, decides; each run has exactly "
    "one status. Only phase 'measured' counts as formal attempts; warmup and "
    "pilot runs are reported separately and never aggregated with them.",
]


def read_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (ValueError, OSError):
        return "unparsable"


def requester_order_ok(r):
    """Same-clock checks of a successful requester record."""
    keys = ["authorization_start_us", "authorization_end_us",
            "peer_handshake_start_us", "peer_handshake_end_us",
            "cooperative_start_us", "cooperative_end_us", "gate_time_us",
            "action_callback_start_us"]
    vals = [r.get(k) for k in keys]
    if any(v is None for v in vals):
        return "missing timestamp"
    if any(b < a for a, b in zip(vals, vals[1:])):
        return "timestamps out of order"
    onb, done = r.get("observed_not_before_us"), r.get(
        "collection_completed_us")
    if onb is None or done is None or not (
            r["cooperative_start_us"] <= onb <= done
            <= r["cooperative_end_us"]):
        return "observation interval outside cooperative verification"
    for start, end, dur in (
            ("authorization_start_us", "authorization_end_us",
             "authorization_latency_us"),
            ("peer_handshake_start_us", "peer_handshake_end_us",
             "peer_handshake_latency_us"),
            ("cooperative_start_us", "cooperative_end_us",
             "cooperative_verification_latency_us"),
            ("authorization_start_us", "action_callback_start_us",
             "end_to_end_latency_us")):
        if r.get(dur) != r[end] - r[start]:
            return "duration does not match its timestamps"
    if r.get("local_verification_latency_us") is not None:
        return "local verification should be null"
    return None


def locker_order_ok(r):
    keys = ["cooperative_start_us", "cooperative_end_us", "gate_time_us",
            "action_callback_start_us"]
    vals = [r.get(k) for k in keys]
    if any(v is None for v in vals):
        return "missing timestamp"
    if any(b < a for a, b in zip(vals, vals[1:])):
        return "timestamps out of order"
    onb, done = r.get("observed_not_before_us"), r.get(
        "collection_completed_us")
    if onb is None or done is None or not (
            r["cooperative_start_us"] <= onb <= done
            <= r["cooperative_end_us"]):
        return "observation interval outside cooperative verification"
    if r.get("cooperative_verification_latency_us") != (
            r["cooperative_end_us"] - r["cooperative_start_us"]):
        return "duration does not match its timestamps"
    for k in ("authorization_latency_us", "end_to_end_latency_us",
              "local_verification_latency_us"):
        if r.get(k) is not None:
            return "%s should be null for the locker" % k
    return None


def claims_success(r):
    return (r.get("mechanism_outcome") == "PASS"
            and r.get("verification_result") == "PASS"
            and r.get("action_decision") == "ALLOW"
            and r.get("callback_started") is True)


def classify(run_id, status, robot, locker):
    """@return (status name, reason)."""
    if status is None or status == "unparsable":
        return "infrastructure_failure", "no runner status"
    if status.get("infrastructure_errors"):
        return "infrastructure_failure", "; ".join(
            status["infrastructure_errors"])
    records = {"robot": robot, "locker": locker}
    for role, rec in records.items():
        # An endpoint the runner had to stop (still waiting after its peer
        # ended) did run; it is not an infrastructure problem.
        if rec in (None, "unparsable") and status.get(
                "%s_exit_code" % role) is None and not status.get(
                "%s_stopped_by_runner" % role):
            return ("infrastructure_failure",
                    "%s: no result file and no exit code" % role)
    for role, rec in records.items():
        if isinstance(rec, dict):
            if rec.get("run_id") != run_id:
                return "measurement_error", "%s: run_id mismatch" % role
            if rec.get("measurement_status") != "ok":
                return "measurement_error", "%s: %s" % (
                    role, rec.get("measurement_status"))
        elif rec == "unparsable":
            return "measurement_error", "%s: unparsable result" % role
    if all(isinstance(r, dict) and claims_success(r)
           for r in records.values()):
        why = requester_order_ok(robot) or locker_order_ok(locker)
        if why:
            return "measurement_error", why
        return "joint_success", ""
    reasons = []
    for role, rec in records.items():
        if not isinstance(rec, dict):
            reasons.append("%s: %s without a result" % (
                role, "stopped by the runner" if status.get(
                    "%s_stopped_by_runner" % role) else "exited %s" %
                status.get("%s_exit_code" % role)))
        elif not claims_success(rec):
            reasons.append("%s: %s/%s/%s%s" % (
                role, rec.get("mechanism_outcome"),
                rec.get("verification_result"), rec.get("action_decision"),
                " at %s" % rec["error_stage"] if rec.get("error_stage")
                else ""))
    return "protocol_or_action_failure", "; ".join(reasons)


def percentile(values, q):
    return float(np.percentile(np.asarray(values, dtype=float), q,
                               method=PERCENTILE_METHOD))


def summarize(values):
    if not values:
        return dict(n=0, median_us=None, p95_us=None)
    return dict(n=len(values), median_us=percentile(values, 50),
                p95_us=percentile(values, 95))


def load(exp_dir):
    with open(os.path.join(exp_dir, "schedule.json")) as f:
        schedule = json.load(f)
    with open(os.path.join(exp_dir, "settings.json")) as f:
        settings = json.load(f)
    exp_id = os.path.basename(os.path.normpath(exp_dir))
    runs, seen = [], set()
    for block in schedule["blocks"]:
        for r in block["runs"]:
            if r["run_id"] in seen:  # never count a run twice
                continue
            seen.add(r["run_id"])
            tdir = os.path.join(exp_dir, "trials", r["run_id"])
            status = read_json(os.path.join(tdir, "status.json"))
            if status is None:
                continue  # scheduled but not run (yet): not an attempt
            robot = read_json(os.path.join(tdir, "robot.json"))
            locker = read_json(os.path.join(tdir, "locker.json"))
            name, reason = classify(r["run_id"], status, robot, locker)
            runs.append(dict(experiment_id=exp_id, block_id=block["block_id"],
                             tdir=tdir, status=status, robot=robot,
                             locker=locker, trial_status=name, reason=reason,
                             **r))
    return exp_id, settings, runs


def endpoint_rows(settings, runs):
    rows = []
    for run in runs:
        st = settings["settings"][run["setting_id"]]
        for role in ("robot", "locker"):
            rec = run[role] if isinstance(run[role], dict) else {}
            row = {k: rec.get(k) for k in ENDPOINT_FIELDS}
            row.update(experiment_id=run["experiment_id"],
                       setting_id=run["setting_id"],
                       block_id=run["block_id"], run_id=run["run_id"],
                       attempt_index=run["attempt_index"], phase=run["phase"],
                       mechanism=st["mechanism"],
                       endpoint_role=rec.get("endpoint_role",
                                             "requester" if role == "robot"
                                             else "locker"),
                       process_exit_code=run["status"].get(
                           "%s_exit_code" % role),
                       raw_log_path=os.path.join(run["tdir"], "%s.log" % role))
            for k in ("parameters", "observations"):
                row[k] = json.dumps(rec.get(k)) if rec.get(k) is not None \
                    else None
            rows.append(row)
    return rows


def write_csv(path, rows, fields):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: ("" if r.get(k) is None else r.get(k))
                        for k in fields})


def ms(us):
    return None if us is None else us / 1000.0


def analyze(exp_dir, figures=True):
    exp_id, settings, runs = load(exp_dir)
    order, sdefs = settings["order"], settings["settings"]
    rows = endpoint_rows(settings, runs)
    write_csv(os.path.join(exp_dir, "endpoint_results.csv"), rows,
              ENDPOINT_FIELDS)
    write_csv(os.path.join(exp_dir, "trial_status.csv"), [
        dict(run_id=r["run_id"], setting_id=r["setting_id"],
             block_id=r["block_id"], phase=r["phase"],
             attempt_index=r["attempt_index"], trial_status=r["trial_status"],
             reason=r["reason"]) for r in runs],
        ["run_id", "setting_id", "block_id", "phase", "attempt_index",
         "trial_status", "reason"])

    measured = [r for r in runs if r["phase"] == "measured"]
    ok = [r for r in measured if r["trial_status"] == "joint_success"]

    # Per setting, role and metric, from joint successes only.
    summary = {}
    lat_rows = []
    for sid in order:
        for role, key in (("requester", "robot"), ("locker", "locker")):
            for metric in METRICS:
                vals = [r[key][metric] for r in ok if r["setting_id"] == sid
                        and r[key].get(metric) is not None]
                s = summarize(vals)
                summary[(sid, role, metric)] = (s, vals)
                lat_rows.append(dict(
                    setting_id=sid, mechanism=sdefs[sid]["mechanism"],
                    endpoint_role=role, metric=metric, n=s["n"],
                    median_us=s["median_us"], p95_us=s["p95_us"],
                    small_sample=0 < s["n"] < SMALL_SAMPLE))
    write_csv(os.path.join(exp_dir, "latency_summary.csv"), lat_rows,
              ["setting_id", "mechanism", "endpoint_role", "metric", "n",
               "median_us", "p95_us", "small_sample"])

    def counts(sid):
        rs = [r for r in measured if r["setting_id"] == sid]
        c = {k: sum(r["trial_status"] == k for r in rs) for k in (
            "joint_success", "protocol_or_action_failure",
            "infrastructure_failure", "measurement_error")}
        return len(rs), c

    baselines = [sid for sid in order if sdefs[sid]["kind"] == "baseline"]
    # Baseline configuration.
    with open(os.path.join(exp_dir, "manifest.json")) as f:
        manifest = json.load(f)
    t1 = []
    for sid in baselines:
        d = sdefs[sid]
        t1.append(dict(mechanism=d["mechanism"],
                       handshake_transport=d["handshake_transport"],
                       parameters=json.dumps(d["parameters"]),
                       freshness_bound_ms=d["freshness_bound_ms"],
                       placement=json.dumps(manifest.get("placement")),
                       auth_network=manifest.get("auth_network")))
    write_csv(os.path.join(exp_dir, "baseline_configuration.csv"), t1,
              list(t1[0].keys()) if t1 else ["mechanism"])
    sweep_rows = []
    for sid in order:
        d = sdefs[sid]
        for name in d.get("sweeps", []):
            sweep_rows.append(dict(
                mechanism=d["mechanism"], varied_parameter=name,
                value=d["parameters"][name], setting_id=sid,
                fixed_parameters=json.dumps({k: v for k, v in
                                             d["parameters"].items()
                                             if k != name})))
    write_csv(os.path.join(exp_dir, "sweep_configuration.csv"), sweep_rows,
              ["mechanism", "varied_parameter", "value", "setting_id",
               "fixed_parameters"])

    # Requester baseline latency.
    t2 = []
    for sid in baselines:
        attempts, c = counts(sid)
        row = dict(mechanism=sdefs[sid]["mechanism"], setting_id=sid,
                   successful_trials=c["joint_success"],
                   measured_attempts=attempts)
        for metric in ("authorization_latency_us",
                       "peer_handshake_latency_us",
                       "cooperative_verification_latency_us",
                       "end_to_end_latency_us"):
            s, _ = summary[(sid, "requester", metric)]
            short = metric.replace("_latency_us", "")
            row[short + "_median_ms"] = ms(s["median_us"])
            row[short + "_p95_ms"] = ms(s["p95_us"])
        t2.append(row)
    write_csv(os.path.join(exp_dir, "baseline_latency.csv"), t2,
              list(t2[0].keys()) if t2 else ["mechanism"])

    # Trial accounting (formal attempts only).
    t3 = []
    for sid in order:
        attempts, c = counts(sid)
        other = [r for r in runs if r["setting_id"] == sid and
                 r["phase"] != "measured"]
        t3.append(dict(setting_id=sid, measured_attempts=attempts,
                       joint_successes=c["joint_success"],
                       protocol_or_action_failures=c[
                           "protocol_or_action_failure"],
                       infrastructure_failures=c["infrastructure_failure"],
                       measurement_errors=c["measurement_error"],
                       warmup_or_pilot_runs=len(other)))
    write_csv(os.path.join(exp_dir, "trial_accounting.csv"), t3,
              list(t3[0].keys()))

    # Parameter sweep latency.
    t4 = []
    for r in sweep_rows:
        sid = r["setting_id"]
        attempts, c = counts(sid)
        co, _ = summary[(sid, "requester",
                         "cooperative_verification_latency_us")]
        e2e, _ = summary[(sid, "requester", "end_to_end_latency_us")]
        t4.append(dict(mechanism=r["mechanism"],
                       varied_parameter=r["varied_parameter"],
                       value=r["value"], setting_id=sid,
                       successful_trials=c["joint_success"],
                       measured_attempts=attempts,
                       cooperative_median_ms=ms(co["median_us"]),
                       cooperative_p95_ms=ms(co["p95_us"]),
                       end_to_end_median_ms=ms(e2e["median_us"]),
                       end_to_end_p95_ms=ms(e2e["p95_us"])))
    write_csv(os.path.join(exp_dir, "parameter_sweep_latency.csv"), t4,
              list(t4[0].keys()) if t4 else ["mechanism"])

    meta = dict(
        experiment_id=exp_id,
        generated_at_utc=datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        percentile_method="numpy.percentile(values, q, method='%s')"
                          % PERCENTILE_METHOD,
        summary_statistics="median (q=50) and p95 (q=95) of successful "
                           "trials; not confidence intervals",
        inclusion="latency summaries use phase 'measured' runs whose trial "
                  "status is joint_success; warmup and pilot are excluded",
        classification_rules=CLASSIFICATION_RULES,
        small_sample_threshold=SMALL_SAMPLE,
        requester_metrics="requester (robot) timestamps; end-to-end measured "
                          "directly from authorization start to action "
                          "callback entry, never summed from stages",
        locker_metrics="locker: authorization and end-to-end are null by "
                       "design; its handshake is measured from accept() "
                       "returning only for TCP/Wi-Fi",
        local_verification="null for every run (no local check required)",
        counts=dict(runs=len(runs), measured=len(measured),
                    joint_success=len(ok)),
        figures=plot_figures.CAPTIONS,
    )
    with open(os.path.join(exp_dir, "analysis_metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")
    if figures:  # drawn from the CSVs above; see plot_figures.py
        plot_figures.plot_all(exp_dir)
    return meta


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("experiment_dir")
    ap.add_argument("--no-figures", action="store_true")
    args = ap.parse_args()
    meta = analyze(args.experiment_dir, figures=not args.no_figures)
    print(json.dumps(meta["counts"]))


if __name__ == "__main__":
    sys.exit(main())
