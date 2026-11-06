#!/usr/bin/env python3
"""Figures of one system-overhead experiment, drawn only from the CSVs that
analyze.py writes (latency_summary.csv, endpoint_results.csv,
trial_status.csv, sweep_configuration.csv) and settings.json, so they can be
redrawn without the raw trial files.

One function per figure; each writes <name>.png and <name>.pdf into
<experiment_dir>/figures/:

  baseline_stage_latency        requester stage latency per mechanism
  baseline_end_to_end_latency   requester end-to-end latency per mechanism
  parameter_latency             latency against each swept parameter
  endpoint_cooperative_latency  requester vs locker cooperative latency

  python3 plot_figures.py <experiment_dir> [--only NAME ...]
"""
import argparse
import csv
import json
import os

import numpy as np

PERCENTILE_METHOD = "linear"  # same as analyze.py
MECH_ORDER = ["IR", "LiFi", "Acoustic", "Bluetooth", "Wi-Fi", "UWB"]
STAGES = [("authorization_latency_us", "Authorization"),
          ("peer_handshake_latency_us", "Peer handshake"),
          ("cooperative_verification_latency_us", "Cooperative verification")]
COLORS = ["#4C72B0", "#DD8452", "#55A868", "#C44E52"]

CAPTIONS = {
    "baseline_stage_latency": "Requester stage latency per mechanism "
    "(baseline settings, successful trials), log scale. Bars: median; "
    "markers: p95 (not a confidence interval). Stages are not stacked and do "
    "not sum to the end-to-end latency.",
    "baseline_end_to_end_latency": "Requester end-to-end latency from "
    "authorization request to action callback entry (baseline settings, "
    "successful trials). Box: interquartile range with the median line; "
    "whiskers: the most extreme values within 1.5x IQR; points beyond are "
    "plotted individually. Markers: p95.",
    "parameter_latency": "Median (solid) and p95 (dashed) of the requester's "
    "cooperative-verification and end-to-end latency per sweep value; "
    "successful trials only.",
    "endpoint_cooperative_latency": "Cooperative verification latency of each "
    "endpoint on its own clock (baseline settings): median bars and p95 "
    "markers. Not a split of the end-to-end latency.",
}


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def num(text):
    return None if text in ("", None) else float(text)


class Data:
    """The experiment's summaries, keyed for plotting."""

    def __init__(self, exp_dir):
        self.exp_dir = exp_dir
        with open(os.path.join(exp_dir, "settings.json")) as f:
            settings = json.load(f)
        sdefs = settings["settings"]
        self.baseline = {sdefs[s]["mechanism"]: s for s in settings["order"]
                         if sdefs[s]["kind"] == "baseline"}
        self.mechs = [m for m in MECH_ORDER if m in self.baseline]
        # (setting, role, metric) -> (n, median_us, p95_us)
        self.summary = {}
        for r in read_csv(os.path.join(exp_dir, "latency_summary.csv")):
            self.summary[(r["setting_id"], r["endpoint_role"], r["metric"])] = (
                int(r["n"]), num(r["median_us"]), num(r["p95_us"]))
        self.sweeps = read_csv(os.path.join(exp_dir,
                                            "sweep_configuration.csv"))
        # Per-trial requester end-to-end values of formal joint successes.
        ok = {r["run_id"] for r in read_csv(os.path.join(
            exp_dir, "trial_status.csv"))
            if r["phase"] == "measured" and r["trial_status"] ==
            "joint_success"}
        self.end_to_end = {}
        for r in read_csv(os.path.join(exp_dir, "endpoint_results.csv")):
            if r["run_id"] in ok and r["endpoint_role"] == "requester" and \
                    r["end_to_end_latency_us"]:
                self.end_to_end.setdefault(r["setting_id"], []).append(
                    float(r["end_to_end_latency_us"]))

    def stat(self, sid, role, metric):
        return self.summary.get((sid, role, metric), (0, None, None))


def _plt():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    return plt


def _save(plt, fig, d, name, rect=(0, 0, 1, 1)):
    fig_dir = os.path.join(d.exp_dir, "figures")
    os.makedirs(fig_dir, exist_ok=True)
    fig.tight_layout(rect=rect)
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(fig_dir, "%s.%s" % (name, ext)), dpi=200)
    plt.close(fig)


def _no_data(ax, x):
    ax.text(x, 0.5, "no valid\nsamples", ha="center", va="bottom", fontsize=7,
            color="gray", transform=ax.get_xaxis_transform())


def plot_baseline_stage_latency(d):
    plt = _plt()
    fig, ax = plt.subplots(figsize=(7.5, 3.6))
    width = 0.26
    for i, (metric, label) in enumerate(STAGES):
        labeled = False
        for j, m in enumerate(d.mechs):
            n, med, p95 = d.stat(d.baseline[m], "requester", metric)
            if not n:
                continue
            x = j + (i - 1) * width
            ax.bar(x, med / 1e3, width, color=COLORS[i],
                   label=None if labeled else label)
            labeled = True
            ax.plot(x, p95 / 1e3, marker="_", color="black", markersize=10,
                    mew=2)
    for j, m in enumerate(d.mechs):
        if all(not d.stat(d.baseline[m], "requester", k)[0] for k, _ in STAGES):
            _no_data(ax, j)
    ax.plot([], [], marker="_", color="black", linestyle="none",
            markersize=10, mew=2, label="p95")
    ax.set_xticks(range(len(d.mechs)))
    ax.set_xticklabels(d.mechs)
    ax.set_yscale("log")  # stages differ by orders of magnitude
    ax.set_ylabel("Latency (ms, log scale)")
    ax.legend(fontsize=7, frameon=False)
    _save(plt, fig, d, "baseline_stage_latency")


def plot_baseline_end_to_end_latency(d):
    plt = _plt()
    fig, ax = plt.subplots(figsize=(6.5, 3.4))
    data, pos = [], []
    for j, m in enumerate(d.mechs):
        vals = d.end_to_end.get(d.baseline[m])
        if vals:
            data.append(np.asarray(vals) / 1e6)
            pos.append(j)
        else:
            _no_data(ax, j)
    if data:
        ax.boxplot(data, positions=pos, widths=0.5, whis=1.5)
        for p, v in zip(pos, data):
            ax.plot(p, np.percentile(v, 95, method=PERCENTILE_METHOD),
                    marker="v", color=COLORS[3])
    ax.plot([], [], color="C1", label="median")
    ax.plot([], [], marker="v", color=COLORS[3], linestyle="none",
            label="p95")
    ax.set_xticks(range(len(d.mechs)))
    ax.set_xticklabels(d.mechs)
    ax.set_xlim(-0.6, len(d.mechs) - 0.4)
    ax.set_ylabel("End-to-end latency (s)")
    ax.legend(fontsize=7, frameon=False)
    _save(plt, fig, d, "baseline_end_to_end_latency")


def plot_parameter_latency(d):
    panels = []
    for r in d.sweeps:
        key = (r["mechanism"], r["varied_parameter"])
        if key not in panels:
            panels.append(key)
    if not panels:
        return
    plt = _plt()
    cols = 3
    nrows = (len(panels) + cols - 1) // cols
    fig, axes = plt.subplots(nrows, cols, figsize=(9, 2.8 * nrows),
                             squeeze=False)
    for ax, (mech, name) in zip(axes.flat, panels):
        pts = sorted((float(r["value"]), r["setting_id"]) for r in d.sweeps
                     if (r["mechanism"], r["varied_parameter"]) == (mech, name))
        for metric, color, label in (
                ("cooperative_verification_latency_us", COLORS[0],
                 "Cooperative"),
                ("end_to_end_latency_us", COLORS[1], "End-to-end")):
            xs, med, p95 = [], [], []
            for v, sid in pts:
                n, m50, m95 = d.stat(sid, "requester", metric)
                if n:  # failed or unmeasured settings are left out
                    xs.append(v)
                    med.append(m50 / 1e6)
                    p95.append(m95 / 1e6)
            if xs:
                ax.plot(xs, med, "-o", color=color, label=label + " median",
                        markersize=3)
                ax.plot(xs, p95, "--", color=color, label=label + " p95")
        if not ax.lines:
            ax.text(0.5, 0.5, "no valid samples", ha="center",
                    transform=ax.transAxes, color="gray")
        ax.set_xticks([v for v, _ in pts])
        ax.set_xticklabels(["%g" % v for v, _ in pts])
        ax.set_title("%s: %s" % (mech, name), fontsize=9)
        ax.set_xlabel(name)
        ax.set_ylabel("Latency (s)")
    for ax in list(axes.flat)[len(panels):]:
        ax.axis("off")
    handles, labels = [], []
    for ax in axes.flat:
        for h, l in zip(*ax.get_legend_handles_labels()):
            if l not in labels:
                handles.append(h)
                labels.append(l)
    if handles:
        fig.legend(handles, labels, loc="lower center", ncol=4, fontsize=7,
                   frameon=False)
    _save(plt, fig, d, "parameter_latency", rect=(0, 0.05, 1, 1))


def plot_endpoint_cooperative_latency(d):
    plt = _plt()
    fig, ax = plt.subplots(figsize=(6.5, 3.4))
    metric = "cooperative_verification_latency_us"
    for i, (role, color) in enumerate((("requester", COLORS[0]),
                                       ("locker", COLORS[2]))):
        labeled = False
        for j, m in enumerate(d.mechs):
            n, med, p95 = d.stat(d.baseline[m], role, metric)
            if not n:
                continue
            x = j + (i - 0.5) * 0.36
            ax.bar(x, med / 1e6, 0.36, color=color,
                   label=None if labeled else role)
            labeled = True
            ax.plot(x, p95 / 1e6, marker="_", color="black", markersize=10,
                    mew=2)
    ax.set_xticks(range(len(d.mechs)))
    ax.set_xticklabels(d.mechs)
    ax.set_ylabel("Cooperative verification (s)")
    ax.legend(fontsize=7, frameon=False)
    _save(plt, fig, d, "endpoint_cooperative_latency")


FIGURES = {
    "baseline_stage_latency": plot_baseline_stage_latency,
    "baseline_end_to_end_latency": plot_baseline_end_to_end_latency,
    "parameter_latency": plot_parameter_latency,
    "endpoint_cooperative_latency": plot_endpoint_cooperative_latency,
}


def plot_all(exp_dir, only=None):
    d = Data(exp_dir)
    for name, fn in FIGURES.items():
        if not only or name in only:
            fn(d)
    with open(os.path.join(exp_dir, "figures", "captions.json"), "w") as f:
        json.dump(CAPTIONS, f, indent=2)
        f.write("\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("experiment_dir")
    ap.add_argument("--only", nargs="+", choices=sorted(FIGURES))
    args = ap.parse_args()
    plot_all(args.experiment_dir, args.only)


if __name__ == "__main__":
    main()
