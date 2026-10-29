"""Command-line interface for the ambient-audio similarity tool.

Subcommands:
  compare   A.wav B.wav   -> similarity score + per-band detail (human + JSON/CSV)
  capture   OUT.wav       -> record a fresh clip from the microphone (Pi only)
  benchmark A.wav B.wav   -> repeat compare N times, report processing-time stats
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys

from .similarity import CompareConfig, compare


def _add_config_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--sample-rate", type=int, default=CompareConfig.sample_rate)
    p.add_argument("--filter-order", type=int, default=CompareConfig.filter_order)
    p.add_argument("--max-lag-ms", type=float, default=CompareConfig.max_lag_ms)
    p.add_argument("--min-duration-s", type=float, default=CompareConfig.min_duration_s)
    p.add_argument("--min-power-dbfs", type=float, default=CompareConfig.min_power_dbfs)
    p.add_argument("--threshold", type=float, default=CompareConfig.similarity_threshold)


def _config_from_args(args: argparse.Namespace) -> CompareConfig:
    return CompareConfig(
        sample_rate=args.sample_rate,
        filter_order=args.filter_order,
        max_lag_ms=args.max_lag_ms,
        min_duration_s=args.min_duration_s,
        min_power_dbfs=args.min_power_dbfs,
        similarity_threshold=args.threshold,
    )


def _print_summary(result: dict) -> None:
    ra, rb = result["recording_a"], result["recording_b"]
    print("=== ambient-audio similarity (Sound-Proof-inspired) ===")
    print(f"A: {ra['path']}  {ra['duration_s']:.2f}s  "
          f"power={ra['power_dbfs']:.1f} dBFS  clip={ra['clipping_fraction']:.4f}")
    print(f"B: {rb['path']}  {rb['duration_s']:.2f}s  "
          f"power={rb['power_dbfs']:.1f} dBFS  clip={rb['clipping_fraction']:.4f}")
    print(f"bands used: {result['config']['n_bands_used']}  "
          f"max_lag={result['config']['max_lag_ms']} ms")
    print("  center_hz   max_ncc   lag_ms   skipped")
    for b in result["bands"]:
        flag = "yes" if b["skipped"] else ""
        print(f"  {b['center_hz']:>8}   {b['max_ncc']:.4f}   "
              f"{b['best_lag_ms']:+7.1f}   {flag}")
    v = result["validity"]
    print(f"final_score = {result['final_score']:.4f}  "
          f"(threshold {result['config']['similarity_threshold']})")
    print(f"inputs_valid={result['inputs_valid']} "
          f"(long_enough={v['long_enough']} loud_enough={v['loud_enough']} "
          f"has_valid_band={v['has_valid_band']})")
    print(f"ACCEPTED = {result['accepted']}")
    t = result["timings_ms"]
    print(f"timing(ms): load={t['load']:.1f} filter={t['filter']:.1f} "
          f"correlate={t['correlate']:.1f} total={t['total']:.1f}")


def _write_csv(result: dict, path: str) -> None:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            ["center_hz", "low_hz", "high_hz", "max_ncc", "best_lag_samples",
             "best_lag_ms", "a_band_energy", "b_band_energy", "skipped"]
        )
        for b in result["bands"]:
            w.writerow([
                b["center_hz"], f"{b['low_hz']:.2f}", f"{b['high_hz']:.2f}",
                f"{b['max_ncc']:.6f}", b["best_lag_samples"],
                f"{b['best_lag_ms']:.3f}", f"{b['a_band_energy']:.6e}",
                f"{b['b_band_energy']:.6e}", int(b["skipped"]),
            ])


def _cmd_compare(args: argparse.Namespace) -> int:
    cfg = _config_from_args(args)
    result = compare(args.a, args.b, cfg)
    _print_summary(result)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2)
    if args.csv:
        _write_csv(result, args.csv)
    return 0


def _cmd_benchmark(args: argparse.Namespace) -> int:
    cfg = _config_from_args(args)
    totals, filters, corrs = [], [], []
    score = None
    for _ in range(args.repeat):
        r = compare(args.a, args.b, cfg)
        totals.append(r["timings_ms"]["total"])
        filters.append(r["timings_ms"]["filter"])
        corrs.append(r["timings_ms"]["correlate"])
        score = r["final_score"]
    print(f"benchmark n={args.repeat}  final_score={score:.4f}")
    for name, xs in (("total", totals), ("filter", filters), ("correlate", corrs)):
        print(f"  {name:10s} mean={statistics.mean(xs):.1f}ms "
              f"min={min(xs):.1f} max={max(xs):.1f} "
              f"median={statistics.median(xs):.1f}")
    return 0


def _cmd_score(args: argparse.Namespace) -> int:
    """Machine-readable one line for the C mechanism to parse:
    "<score_milli> <valid> <accepted> <a_power_dbfs> <b_power_dbfs>"."""
    cfg = _config_from_args(args)
    result = compare(args.a, args.b, cfg)

    def dbfs_int(x: float) -> int:
        return -120 if x == float("-inf") else int(round(x))

    print("%d %d %d %d %d" % (
        int(round(result["final_score"] * 1000)),
        1 if result["inputs_valid"] else 0,
        1 if result["accepted"] else 0,
        dbfs_int(result["recording_a"]["power_dbfs"]),
        dbfs_int(result["recording_b"]["power_dbfs"]),
    ))
    return 0


def _cmd_capture(args: argparse.Namespace) -> int:
    from .capture import capture as do_capture  # ALSA only needed here

    meta = do_capture(
        args.out,
        duration_s=args.duration,
        device=args.device,
        sample_rate=args.sample_rate,
    )
    print(json.dumps(meta, indent=2))
    if meta["capture_error"]:
        return 1
    if not meta["sample_count_ok"]:
        print("WARNING: actual sample count differs from expected", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ambient_audio")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("compare", help="compare two recordings")
    pc.add_argument("a")
    pc.add_argument("b")
    pc.add_argument("--json", help="write full result as JSON")
    pc.add_argument("--csv", help="write per-band detail as CSV")
    _add_config_args(pc)
    pc.set_defaults(func=_cmd_compare)

    pb = sub.add_parser("benchmark", help="repeat compare, report timing")
    pb.add_argument("a")
    pb.add_argument("b")
    pb.add_argument("--repeat", type=int, default=10)
    _add_config_args(pb)
    pb.set_defaults(func=_cmd_benchmark)

    ps = sub.add_parser("score", help="print one machine-readable result line")
    ps.add_argument("a")
    ps.add_argument("b")
    _add_config_args(ps)
    ps.set_defaults(func=_cmd_score)

    pp = sub.add_parser("capture", help="record a clip from the microphone (Pi only)")
    pp.add_argument("out")
    pp.add_argument("--duration", type=float, default=3.0)
    pp.add_argument("--device", default="plughw:3,0")
    pp.add_argument("--sample-rate", type=int, default=48000)
    pp.set_defaults(func=_cmd_capture)

    args = parser.parse_args(argv)
    return args.func(args)
