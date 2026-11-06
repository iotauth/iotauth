#!/usr/bin/env python3
"""Analyze a V2 system-overhead experiment (requirement/method taxonomy).

Reads schedule.json, settings.json and each trials/<run_id>/{robot,locker,
status}.json, and writes, into the experiment directory:
  trial_status_v2.csv          every measured trial's classification
  verification_latency_summary.csv / .tex   per requirement/method procedure
                                            latency (median/p95/p99)
  stage_latency.csv            per config, per-device stage latencies
  figures/baseline_stage_latency.{pdf,png}  the integrated-plan stage graph
  analysis_v2_metadata.json    percentile method, counts, provenance

Only the 'measured' phase counts as formal attempts. Timings come from each
device's own CLOCK_MONOTONIC; the analyzer never subtracts across devices.

  python3 analyze_v2.py artifacts/system_overhead/<experiment_id> [--no-figures]
"""
import argparse
import csv
import json
import os
import sys

import numpy as np

PERCENTILE_METHOD = "linear"

# Where each verification-latency table row comes from: the single-device
# checks from S0, each cooperative requirement from the config whose only
# cooperative check it is. (requirement, method) -> (setting_id, role).
LATENCY_SOURCES = [
    ("Temperature", "TEMPERATURE_CHECK", "THERMOMETER", "s0", "locker"),
    ("Humidity", "HUMIDITY_CHECK", "HUMIDITY", "s0", "locker"),
    ("Human absence", "HUMAN_PRESENCE", "CAMERA_PERSON", "s0", "robot"),
    ("Proximity", "PROXIMITY", "IR", "prox_ir", "robot"),
    ("Proximity", "PROXIMITY", "LIFI", "prox_lifi", "robot"),
    ("Proximity", "PROXIMITY", "ULTRASOUND", "prox_acoustic", "robot"),
    ("Proximity", "PROXIMITY", "BLE_RSSI", "prox_ble_timing", "robot"),
    ("Proximity", "PROXIMITY", "WIFI_RSSI", "prox_wifi_timing", "robot"),
    ("Proximity", "PROXIMITY", "UWB", "prox_uwb", "robot"),
    ("Receiving position", "POSITION_IN_REGION", "UWB_POSITION", "position_uwb",
     "robot"),
    ("Shared acoustic environment", "SHARED_ACOUSTIC_ENVIRONMENT",
     "AMBIENT_AUDIO", "ambient_audio", "robot"),
]
STAGE_ORDER = ["authorization", "peer_handshake", "single_device",
               "cooperative", "total"]


def read_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (ValueError, OSError):
        return "unparsable"


def pct(values, q):
    return float(np.percentile(np.asarray(values, float), q,
                               method=PERCENTILE_METHOD))


def summary(values):
    """n plus median/p95/p99 over the same value set, or None when empty."""
    if not values:
        return dict(n=0, median_us=None, p95_us=None, p99_us=None)
    return dict(n=len(values), median_us=pct(values, 50),
                p95_us=pct(values, 95), p99_us=pct(values, 99))


def joint_success(robot, locker):
    """Both devices reached ALLOW with a callback and a clean record."""
    for rec in (robot, locker):
        if not isinstance(rec, dict):
            return False
        if rec.get("measurement_status") != "ok":
            return False
        if rec.get("action_decision") != "ALLOW":
            return False
        if rec.get("callback_started") is not True:
            return False
    return True


def load(exp_dir):
    schedule = read_json(os.path.join(exp_dir, "schedule.json"))
    settings = read_json(os.path.join(exp_dir, "settings.json"))
    exp_id = os.path.basename(os.path.normpath(exp_dir))
    runs, seen = [], set()
    for block in schedule["blocks"]:
        for r in block["runs"]:
            if r["run_id"] in seen:
                continue
            seen.add(r["run_id"])
            tdir = os.path.join(exp_dir, "trials", r["run_id"])
            status = read_json(os.path.join(tdir, "status.json"))
            if status is None:
                continue  # scheduled but not run
            robot = read_json(os.path.join(tdir, "robot.json"))
            locker = read_json(os.path.join(tdir, "locker.json"))
            ok = (not status.get("infrastructure_errors")
                  and joint_success(robot, locker))
            runs.append(dict(run_id=r["run_id"], setting_id=r["setting_id"],
                             block_id=block["block_id"], phase=r["phase"],
                             attempt_index=r["attempt_index"], status=status,
                             robot=robot, locker=locker, ok=ok))
    return exp_id, settings, runs


def check_duration(rec, check, kind=None):
    """The duration_us of `check` in a record's check_timings, or None."""
    if not isinstance(rec, dict):
        return None
    for t in rec.get("check_timings", []):
        if t.get("check") == check and (kind is None or t.get("kind") == kind) \
                and t.get("accepted") and t.get("duration_us") is not None:
            return t["duration_us"]
    return None


def write_csv(path, rows, fields):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: ("" if r.get(k) is None else r.get(k))
                        for k in fields})


def fixed_params(sdefs, setting_id, check):
    st = sdefs.get(setting_id, {})
    rm = st.get("resolved_methods", {}).get(check, {})
    p = rm.get("parameters", {})
    # Compact, stable rendering of the key numeric parameters.
    keep = {k: v for k, v in p.items()
            if k not in ("anchors", "expected") and not isinstance(v, (dict, list))}
    parts = ["%s=%s" % (k, keep[k]) for k in keep]
    if "anchors" in p:
        parts.append("anchors=%d" % len(p["anchors"]))
    return "; ".join(parts)


def ms(us):
    return None if us is None else round(us / 1000.0, 1)


def analyze(exp_dir, figures=True):
    exp_id, settings, runs = load(exp_dir)
    sdefs = settings["settings"]
    measured = [r for r in runs if r["phase"] == "measured"]
    # Pilot data (no measured phase yet) is still summarized, flagged below.
    phase_used = "measured" if measured else "pilot"
    pool = measured or runs

    # Trial status CSV.
    write_csv(os.path.join(exp_dir, "trial_status_v2.csv"),
              [dict(run_id=r["run_id"], setting_id=r["setting_id"],
                    block_id=r["block_id"], phase=r["phase"],
                    joint_success=r["ok"],
                    infra_error="; ".join(r["status"].get(
                        "infrastructure_errors", []))) for r in runs],
              ["run_id", "setting_id", "block_id", "phase", "joint_success",
               "infra_error"])

    def attempts(sid):
        return [r for r in pool if r["setting_id"] == sid]

    def successes(sid):
        return [r for r in attempts(sid) if r["ok"]]

    # --- Table 1: verification procedure latency (per requirement/method).
    lat_rows = []
    for label, req, method, sid, role in LATENCY_SOURCES:
        succ = successes(sid)
        att = attempts(sid)
        key = "robot" if role == "robot" else "locker"
        check = "HUMAN_PRESENCE" if method == "CAMERA_PERSON" else req.replace(
            "+timing", "")
        vals = [d for d in (check_duration(r[key], check) for r in succ)
                if d is not None]
        s = summary(vals)
        method_label = method + (" + timing" if "+timing" in req else "")
        lat_rows.append(dict(
            requirement=label, method=method_label,
            fixed_parameters=fixed_params(sdefs, sid, check),
            successes=len(succ), attempts=len(att),
            n_timed=s["n"], median_ms=ms(s["median_us"]),
            p95_ms=ms(s["p95_us"]), p99_ms=ms(s["p99_us"]),
            source_setting=sid, measuring_role=role))
    write_csv(os.path.join(exp_dir, "verification_latency_summary.csv"),
              lat_rows, ["requirement", "method", "fixed_parameters",
                         "successes", "attempts", "n_timed", "median_ms",
                         "p95_ms", "p99_ms", "source_setting",
                         "measuring_role"])
    write_latency_tex(os.path.join(exp_dir, "verification_latency.tex"),
                      lat_rows)

    # --- Stage latency per config (robot and locker), joint-success trials.
    stage_rows = []
    for sid in settings["order"]:
        succ = successes(sid)
        for role, key in (("robot", "robot"), ("locker", "locker")):
            for stage in STAGE_ORDER:
                vals = [v for v in (stage_value(r[key], role, stage)
                                    for r in succ) if v is not None]
                s = summary(vals)
                stage_rows.append(dict(
                    setting_id=sid, device=role, stage=stage, n=s["n"],
                    median_ms=ms(s["median_us"]), p95_ms=ms(s["p95_us"]),
                    p99_ms=ms(s["p99_us"])))
    write_csv(os.path.join(exp_dir, "stage_latency.csv"), stage_rows,
              ["setting_id", "device", "stage", "n", "median_ms", "p95_ms",
               "p99_ms"])

    meta = dict(experiment_id=exp_id, percentile_method=PERCENTILE_METHOD,
                phase_used=phase_used,
                note="median/p95/p99 computed over the same joint-success "
                     "trial set per row; pilot phase used only if no measured "
                     "phase exists; unmeasured entries are null, not zero.",
                per_setting={sid: dict(attempts=len(attempts(sid)),
                                       successes=len(successes(sid)))
                             for sid in settings["order"]})
    with open(os.path.join(exp_dir, "analysis_v2_metadata.json"), "w") as f:
        json.dump(meta, f, indent=2)

    if figures:
        try:
            plot_stage_latency(exp_dir, settings, stage_rows)
        except Exception as e:  # a missing display/font must not lose the CSVs
            print("figure skipped:", e)
    print("analyzed %s (%s phase): %d trials, %d joint successes" % (
        exp_id, phase_used, len(pool), sum(r["ok"] for r in pool)))


def stage_value(rec, role, stage):
    """One stage's latency (us) for a device record, or None."""
    if not isinstance(rec, dict):
        return None
    if stage == "authorization":
        return rec.get("authorization_latency_us")
    if stage == "peer_handshake":
        return rec.get("peer_handshake_latency_us")
    if stage == "cooperative":
        return rec.get("cooperative_verification_latency_us")
    if stage == "total":
        # Robot: authorization start -> its own action callback (pre-computed).
        # Locker: accept return (= peer-handshake start) -> its own action
        # callback. The locker has no authorization start, so its
        # end_to_end_latency_us is null; its directly-measured decision interval
        # comes from these two same-clock timestamps (NOT a stage sum).
        if role == "locker":
            a = rec.get("action_callback_start_us")
            b = rec.get("peer_handshake_start_us")
            return (a - b) if (a is not None and b is not None) else None
        return rec.get("end_to_end_latency_us")
    if stage == "single_device":
        # Sum of this device's single-device check durations in the trial.
        total = 0
        found = False
        for t in rec.get("check_timings", []):
            if t.get("kind") == "single_device" and t.get("duration_us") \
                    is not None:
                total += t["duration_us"]
                found = True
        return total if found else None
    return None


def write_latency_tex(path, rows):
    """The paper table: Requirement | Method | Fixed parameters |
    Successes/attempts | Median | p95 | p99 (no role/mode column)."""
    def cell(v):
        return "---" if v is None else ("%.1f" % v if isinstance(v, float)
                                        else str(v))
    lines = [
        "% Auto-generated by analyze_v2.py; do not edit by hand.",
        "\\begin{tabular}{@{}lllcccc@{}}", "\\toprule",
        "Requirement & Method & Fixed parameters & Successes/attempts & "
        "Median (ms) & p95 (ms) & p99 (ms) \\\\", "\\midrule"]
    for r in rows:
        params = r["fixed_parameters"].replace("_", "\\_") or "---"
        lines.append("%s & %s & %s & %d/%d & %s & %s & %s \\\\" % (
            r["requirement"], r["method"].replace("_", "\\_"), params,
            r["successes"], r["attempts"], cell(r["median_ms"]),
            cell(r["p95_ms"]), cell(r["p99_ms"])))
    lines += ["\\bottomrule", "\\end{tabular}"]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def plot_stage_latency(exp_dir, settings, stage_rows):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    from matplotlib.lines import Line2D
    import matplotlib.transforms as mtransforms
    from matplotlib.ticker import FuncFormatter
    # Broken y-axis: top panel = full seconds range (whole stacked bars + measured
    # total dots); bottom panel = ms zoom so authorization and peer-handshake
    # (invisible on a seconds scale) are legible per configuration. Chosen over an
    # inset: an inset with 18 R/L bars would be unreadable, whereas the broken axis
    # keeps per-config values and shared x labels for only a small height increase
    # (~3.2 in). Per config a Robot (R) and Locker (L) stacked bar; black dot =
    # directly-measured total decision latency median (robot: authorization start
    # -> its callback; locker: accept return = peer-handshake start -> its
    # callback), never the stage sum. RSSI-only BLE/Wi-Fi configs dropped; configs
    # with no joint-success data excluded. Wi-Fi here is RSSI-only (its latency-run
    # timing flag was a no-op); BLE includes authenticated timing (measure).
    cfg_label = {
        "s0": "Single-\ndevice", "prox_ir": "IR", "prox_lifi": "LiFi",
        "prox_acoustic": "Acoustic\necho", "prox_ble_timing": "BLE RSSI\n+ timing",
        "prox_wifi_timing": "Wi-Fi\nRSSI", "prox_uwb": "UWB\nranging",
        "position_uwb": "UWB\npositioning", "ambient_audio": "Ambient\naudio",
        "multi_prox_ambient": "Combined"}
    idx = {(r["setting_id"], r["device"], r["stage"]): r for r in stage_rows}
    stages = ["authorization", "peer_handshake", "single_device", "cooperative"]
    stage_disp = {"authorization": "Authorization",
                  "peer_handshake": "Peer handshake",
                  "single_device": "Single-device", "cooperative": "Cooperative"}
    colors = {"authorization": "#4C72B0", "peer_handshake": "#55A868",
              "single_device": "#C44E52", "cooperative": "#8172B3"}
    drop = ("prox_ble", "prox_wifi_rssi")

    def has_data(sid):
        for dev in ("robot", "locker"):
            for st in stages + ["total"]:
                r = idx.get((sid, dev, st))
                if r and r["median_ms"] is not None:
                    return True
        return False
    order = [s for s in settings["order"] if s not in drop and has_data(s)]
    excluded = [s for s in settings["order"] if s not in drop and not has_data(s)]
    if excluded:
        print("stage figure: excluded (no joint-success trials):",
              ", ".join(excluded))
    fig, (axt, axb) = plt.subplots(
        2, 1, sharex=True, figsize=(7, 3.2),
        gridspec_kw={"height_ratios": [3.0, 1.1], "hspace": 0.10})
    w = 0.38
    bars = []          # (x, "R"/"L")
    ymax_s = 0.0       # top-panel max (s)
    zoom_max_ms = 0.0  # bottom-panel: max authorization+handshake (ms)
    for i, sid in enumerate(order):
        for j, device in enumerate(("robot", "locker")):
            x = i + (j - 0.5) * (w + 0.02)
            bars.append((x, "R" if device == "robot" else "L"))
            base = 0.0
            ah = 0.0
            for stage in stages:
                r = idx.get((sid, device, stage))
                if not r or r["median_ms"] is None:
                    continue  # nonapplicable / unmeasured: skip, never 0
                v = r["median_ms"] / 1000.0
                for ax in (axt, axb):
                    ax.bar(x, v, bottom=base, width=w, color=colors[stage],
                           edgecolor="white", linewidth=0.3)
                base += v
                if stage in ("authorization", "peer_handshake"):
                    ah = base
            zoom_max_ms = max(zoom_max_ms, ah * 1000.0)
            ymax_s = max(ymax_s, base)
            tot = idx.get((sid, device, "total"))
            if tot and tot["median_ms"] is not None:
                for ax in (axt, axb):
                    ax.plot(x, tot["median_ms"] / 1000.0, "ko", markersize=3,
                            zorder=5)
                ymax_s = max(ymax_s, tot["median_ms"] / 1000.0)
    # y ranges: top shows the seconds region above the break; bottom the ms zoom.
    zlim = (int(zoom_max_ms / 100) + 1) * 100 / 1000.0 + 0.05
    break_at = max(zlim, 0.45)
    axt.set_ylim(break_at, ymax_s * 1.08)
    axb.set_ylim(0, zlim)
    # hide the shared inner spines and draw diagonal break marks
    axt.spines["bottom"].set_visible(False)
    axb.spines["top"].set_visible(False)
    for s in ("top", "right"):
        axt.spines[s].set_visible(False)
        axb.spines[s].set_visible(False)
    axt.tick_params(labelbottom=False, bottom=False)
    dmk = dict(marker=[(-1, -0.6), (1, 0.6)], markersize=6, linestyle="none",
               color="k", mec="k", mew=0.8, clip_on=False)
    axt.plot([0, 1], [0, 0], transform=axt.transAxes, **dmk)
    axb.plot([0, 1], [1, 1], transform=axb.transAxes, **dmk)
    # x labels on the bottom panel: R/L under each bar, config name under each pair
    axb.set_xticks([x for x, _ in bars])
    axb.set_xticklabels([lab for _, lab in bars], fontsize=6)
    axb.tick_params(axis="x", length=0, pad=1)
    trans = mtransforms.blended_transform_factory(axb.transData, axb.transAxes)
    for i, sid in enumerate(order):
        axb.text(i, -0.36, cfg_label.get(sid, sid), transform=trans,
                 ha="center", va="top", fontsize=6.5, linespacing=0.9)
    axt.set_ylabel("Latency (s)", fontsize=8)
    axt.tick_params(axis="y", labelsize=7)
    axb.set_ylabel("ms", fontsize=7)
    axb.yaxis.set_major_formatter(FuncFormatter(lambda v, _: "%d" % (v * 1000)))
    axb.tick_params(axis="y", labelsize=6)
    axt.margins(x=0.01)
    handles = [Patch(color=colors[st]) for st in stages] + \
        [Line2D([0], [0], marker="o", color="k", linestyle="None", markersize=3)]
    labels = [stage_disp[st] for st in stages] + ["Measured total"]
    axt.legend(handles, labels, loc="lower center", bbox_to_anchor=(0.5, 1.0),
               ncol=5, fontsize=6.5, frameon=False, handlelength=1.1,
               handletextpad=0.4, columnspacing=1.0)
    fig.text(0.008, 0.955, "R = robot, L = locker", fontsize=6, va="top")
    fig.subplots_adjust(left=0.08, right=0.995, top=0.88, bottom=0.17)
    os.makedirs(os.path.join(exp_dir, "figures"), exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(exp_dir, "figures",
                                 "baseline_stage_latency.%s" % ext), dpi=200)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("exp_dir")
    ap.add_argument("--no-figures", action="store_true")
    args = ap.parse_args()
    analyze(args.exp_dir, figures=not args.no_figures)


if __name__ == "__main__":
    sys.exit(main())
