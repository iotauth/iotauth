#!/usr/bin/env python3
"""Plot latency means and per-trial sample standard deviations from summarize_merged_latency.py."""

import csv
import json
import math
import shutil
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib.ticker import FuncFormatter


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "artifacts/system_overhead"
# Add the separately measured mean; no per-trial path-clearance data is available.
# The existing whiskers retain the variability of the recorded components only.
PATH_CLEARANCE_MEAN_S = 2.0139
ORDER = [
    ("s0", "Single-device"),
    ("prox_ir", "IR"),
    ("prox_lifi", "LiFi"),
    ("prox_acoustic", "Acoustic\necho"),
    ("prox_ble_timing", "BLE RSSI"),
    ("prox_wifi_timing", "Wi-Fi RSSI"),
    ("prox_uwb", "UWB\nranging"),
    ("position_uwb", "UWB\npositioning"),
    ("ambient_audio", "Ambient\naudio"),
]
STAGES = [
    ("authorization", "Authorization", "#4C72B0"),
    ("peer_handshake", "Peer handshake", "#55A868"),
    ("single_device", "Single-device", "#C44E52"),
    ("cooperative", "Cooperative", "#8172B3"),
]


def main():
    records = {}
    # All configurations use the same successful-trial cohorts as the paper.
    with (BASE / "merged/stage_latency.csv").open(newline="") as stream:
        for row in csv.DictReader(stream):
            records[(row["setting_id"], row["device"], row["stage"])] = row

    def seconds(setting, device, stage):
        row = records.get((setting, device, stage))
        if not row or not row["mean_ms"]:
            return None
        value = float(row["mean_ms"]) / 1000
        if device == "locker" and stage == "single_device":
            value += PATH_CLEARANCE_MEAN_S
        return value

    plt.rcParams.update({"font.size": 8, "pdf.fonttype": 42})
    fig, axes = plt.subplots(
        3, 1, sharex=True, figsize=(8.5, 3.25),
        gridspec_kw={"height_ratios": [0.8, 2.2, 0.8], "hspace": 0.08},
    )
    upper, middle, lower = axes
    width = 0.37
    ticks, labels = [], []
    plotted_means = []
    for index, (setting, _) in enumerate(ORDER):
        for offset, device in [(-0.2, "robot"), (0.2, "locker")]:
            x = index + offset
            ticks.append(x)
            labels.append("Robot" if device == "robot" else "Locker")
            bottom = 0.0
            for stage, _, color in STAGES:
                value = seconds(setting, device, stage)
                if value is None:
                    continue
                for ax in axes:
                    ax.bar(x, value, bottom=bottom, width=width,
                           color=color, edgecolor="white", linewidth=0.35)
                bottom += value
            stats = records[(setting, device, "stack_total")]
            sd = float(stats["sd_ms"]) / 1000
            recorded_mean = float(stats["mean_ms"]) / 1000
            added_mean = PATH_CLEARANCE_MEAN_S if device == "locker" else 0.0
            assert abs(bottom - recorded_mean - added_mean) < 1e-8
            plotted_means.append({
                "setting_id": setting, "device": device,
                "recorded_component_sum_mean_s": recorded_mean,
                "added_path_clearance_mean_s": added_mean,
                "plotted_component_sum_mean_s": bottom,
                "sd_excluding_path_clearance_s": sd,
            })
            for ax in axes:
                ax.errorbar(x, bottom, yerr=sd,
                            fmt="none", ecolor="#222222", elinewidth=0.8,
                            capsize=2.2, capthick=0.8, zorder=4)

    max_seconds = max(row["plotted_component_sum_mean_s"]
                      + row["sd_excluding_path_clearance_s"]
                      for row in plotted_means)
    upper.set_ylim(65, math.ceil(max_seconds * 1.03 / 5) * 5)
    upper.set_yticks([70, 85, 100])
    # Keep the full IR handshake and subsequent single-device segment visible.
    middle.set_ylim(1.3, 55)
    middle.set_yticks([10, 20, 30, 40, 50])
    lower.set_ylim(0, 1.2)
    lower.set_yticks([0, 0.5, 1.0])
    lower.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value * 1000:g}"))
    middle.set_ylabel("Latency (s)", labelpad=5)
    lower.set_ylabel("ms", labelpad=5)

    for ax in axes:
        ax.spines[["top", "right"]].set_visible(False)
        ax.tick_params(axis="y", labelsize=8)
        ax.margins(x=0.012)
    upper.spines["bottom"].set_visible(False)
    middle.spines["bottom"].set_visible(False)
    for ax in [upper, middle]:
        ax.tick_params(axis="x", bottom=False, labelbottom=False)
    mark = dict(marker=[(-1, -0.6), (1, 0.6)], markersize=6,
                linestyle="none", color="black", clip_on=False)
    for ax, y in [(upper, 0), (middle, 1), (middle, 0), (lower, 1)]:
        ax.plot([0, 1], [y, y], transform=ax.transAxes, **mark)

    lower.set_xticks(ticks, labels, fontsize=7)
    lower.tick_params(axis="x", length=0, pad=2)
    for index, (_, label) in enumerate(ORDER):
        lower.text(index, -0.35, label, transform=lower.get_xaxis_transform(),
                   ha="center", va="top", fontsize=7.2, linespacing=0.95)

    handles = [Patch(facecolor=color, label=label) for _, label, color in STAGES]
    handles.append(lower.errorbar([], [], yerr=[[], []], fmt="none", ecolor="#222222",
                                  elinewidth=0.8, capsize=2.2, capthick=0.8, label="±1 standard deviation"))
    upper.legend(handles=handles, loc="upper right", bbox_to_anchor=(0.995, 1.0),
                 ncol=2, frameon=False, fontsize=7.5, handlelength=1.1,
                 handletextpad=0.35, columnspacing=1.0, borderaxespad=0.15,
                 labelspacing=0.25)
    fig.subplots_adjust(left=0.075, right=0.995, top=0.985, bottom=0.19)

    target = BASE / "merged/figures/baseline_stage_latency.pdf"
    target.parent.mkdir(parents=True, exist_ok=True)
    (BASE / "merged/path_clearance_plot_adjustment.json").write_text(json.dumps({
        "source": "stage_latency.csv (unchanged)",
        "adjustment": "Add separately measured mean path-clearance time to locker single-device components.",
        "uncertainty": "Whiskers exclude path-clearance variability; no additional per-trial measurements are synthesized.",
        "rows": plotted_means,
    }, indent=2) + "\n")
    fig.savefig(target, bbox_inches="tight", pad_inches=0.03)
    fig.savefig(target.with_suffix(".png"), dpi=220, bbox_inches="tight", pad_inches=0.03)
    shutil.copy2(target, ROOT / "figures/baseline_stage_latency.pdf")
    shutil.copy2(target.with_suffix(".png"), ROOT / "figures/baseline_stage_latency.png")
    plt.close(fig)
    print(f"Updated {target} and the paper figure; no LaTeX compilation.")


if __name__ == "__main__":
    main()
