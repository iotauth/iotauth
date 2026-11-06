#!/usr/bin/env python3
"""Recompute paper latency means from its original successful-trial cohorts.

The archived median/p95/p99 summaries identify the trial populations. Validate
those statistics before adding means; retain medians in CSVs for provenance.
"""

import csv
import json
from pathlib import Path
from statistics import mean, stdev

import analyze_v2 as analyzer


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "artifacts/system_overhead"
TARGET = BASE / "merged"
COHORTS = {
    "s0": ("v2pilot", ["b034"]),
    "prox_ir": ("v3", ["b025"]),
    "prox_lifi": ("v3", ["b024"]),
    "prox_acoustic": ("v2pilot", ["b059"]),
    "prox_ble_timing": ("v3", ["b023"]),
    "prox_wifi_timing": ("v3", ["b009"]),
    "prox_uwb": ("v2pilot", ["b037"]),
    "position_uwb": ("v3", ["b017", "b018", "b019", "b020", "b021"]),
    "ambient_audio": ("v2pilot", ["b060"]),
}


def read_rows(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def summarize(values):
    stats = analyzer.summary(values)
    return {
        "n": stats["n"],
        "mean_ms": round(mean(values) / 1000, 6) if values else None,
        "sd_ms": stdev(values) / 1000 if len(values) > 1 else None,
        "min_ms": min(values) / 1000 if values else None,
        "max_ms": max(values) / 1000 if values else None,
        "median_ms": analyzer.ms(stats["median_us"]),
        "p95_ms": analyzer.ms(stats["p95_us"]),
        "p99_ms": analyzer.ms(stats["p99_us"]),
    }


def validate(stats, archived, count_field="n"):
    if stats["n"] != int(archived[count_field]):
        raise ValueError(f"Trial-count mismatch: {stats} versus {archived}")
    for field in ("median_ms", "p95_ms", "p99_ms"):
        expected = archived[field]
        actual = stats[field]
        if expected == "":
            if actual is not None:
                raise ValueError(f"Unexpected measurement for {field}")
        elif actual is None or abs(actual - float(expected)) > 0.11:
            raise ValueError(f"Cohort mismatch for {field}: {actual} != {expected}")


def main():
    archived_stages = {}
    for source in (BASE / "v2pilot/stage_latency.csv", TARGET / "stage_latency.csv"):
        for row in read_rows(source):
            archived_stages[(row["setting_id"], row["device"], row["stage"])] = row
    archived_procedures = read_rows(TARGET / "verification_latency.csv")
    loaded = {
        campaign: analyzer.load(str(BASE / campaign))[2]
        for campaign in {campaign for campaign, _ in COHORTS.values()}
    }
    successes = {}
    provenance = {}
    for setting, (campaign, blocks) in COHORTS.items():
        attempts = [
            run for run in loaded[campaign]
            if run["phase"] == "measured" and run["setting_id"] == setting
            and run["block_id"] in blocks
        ]
        successes[setting] = [run for run in attempts if run["ok"]]
        provenance[setting] = {
            "campaign": campaign, "blocks": blocks, "attempts": len(attempts),
            "successful_run_ids": [run["run_id"] for run in successes[setting]],
        }

    stages = []
    for setting in COHORTS:
        for role in ("robot", "locker"):
            for stage in analyzer.STAGE_ORDER:
                values = [
                    value for run in successes[setting]
                    if (value := analyzer.stage_value(run[role], role, stage)) is not None
                ]
                stats = summarize(values)
                validate(stats, archived_stages[(setting, role, stage)])
                stages.append({"setting_id": setting, "device": role,
                               "stage": stage, **stats})

            # The whiskers describe the same sum as the stacked bars. Compute
            # each trial's sum before computing SD, preserving stage covariances.
            sums = []
            for run in successes[setting]:
                components = []
                for stage in ("authorization", "peer_handshake", "single_device", "cooperative"):
                    value = analyzer.stage_value(run[role], role, stage)
                    if value is None:
                        if role == "locker" and stage == "authorization":
                            continue
                        raise ValueError(f"Missing {stage} for {setting}/{role}/{run['run_id']}")
                    components.append(value)
                sums.append(sum(components))
            stats = summarize(sums)
            plotted_means = sum(row["mean_ms"] or 0 for row in stages
                                if row["setting_id"] == setting and row["device"] == role
                                and row["stage"] != "total")
            if abs(plotted_means - stats["mean_ms"]) > 0.00001:
                raise ValueError(f"Stack mean mismatch for {setting}/{role}")
            stages.append({"setting_id": setting, "device": role,
                           "stage": "stack_total", **stats})

    sources = {
        (setting, method, role): check
        for _, check, method, setting, role in analyzer.LATENCY_SOURCES
    }
    procedures = []
    for row in archived_procedures:
        setting, role = row["source_setting"], row["measuring_role"]
        check = sources[(setting, row["method"], role)]
        values = [
            value for run in successes[setting]
            if (value := analyzer.check_duration(run[role], check)) is not None
        ]
        stats = summarize(values)
        validate(stats, row, "n_timed")
        if len(successes[setting]) != int(row["successes"]):
            raise ValueError(f"Success-count mismatch for {setting}")
        if provenance[setting]["attempts"] != int(row["attempts"]):
            raise ValueError(f"Attempt-count mismatch for {setting}")
        procedures.append({**row, "mean_ms": stats["mean_ms"]})

    # Write only after every stage and procedure matches the archived cohort.
    analyzer.write_csv(
        str(TARGET / "stage_latency.csv"), stages,
        ["setting_id", "device", "stage", "n", "mean_ms", "sd_ms", "min_ms", "max_ms", "median_ms", "p95_ms", "p99_ms"],
    )
    fields = list(archived_procedures[0])
    if "mean_ms" not in fields:
        fields.insert(fields.index("median_ms"), "mean_ms")
    analyzer.write_csv(str(TARGET / "verification_latency.csv"), procedures, fields)
    report = {
        "statistic": "arithmetic mean of the original successful-trial cohorts",
        "validation": "All original counts, medians, p95 and p99 reproduced",
        "range_definition": "Whiskers show mean +/- one sample SD (ddof=1) of each successful trial's sum of the four plotted stages; not the independently measured end-to-end interval",
        "cohorts": provenance, "stages": stages, "procedures": procedures,
    }
    (TARGET / "mean_latency_report.json").write_text(json.dumps(report, indent=2) + "\n")
    for row in procedures:
        print(f"{row['method']}: mean={row['mean_ms'] / 1000:.4f} s, n={row['n_timed']}")


if __name__ == "__main__":
    main()
