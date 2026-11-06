#!/usr/bin/env python3
"""QR-code exchange (static-ID discovery) measurement, separate from the SST
benchmark.

The locker displays its entity id as a QR on its framebuffer; the robot's camera
captures and decodes it and verifies the decoded value equals the displayed id.
This is static-ID discovery, not session-bound verification and not an
Auth-selected proximity mechanism; report it as such.

Each device's own CLOCK_MONOTONIC is used; nothing is subtracted across devices.
Locker QR generate/display preparation is timed separately on the locker. The
robot scan procedure (capture + decode + verify, with retries) is timed on the
robot by qr_scan_bench.py.

  bench_qr.py --robot <host> --locker <host> --repo <path> --id <entity_id>
              --warmup 5 --measured 100 --out <dir>

Requires: the robot camera physically aimed at the locker's display showing the
QR; qrencode + fbi on the locker; rpicam-jpeg + zbarimg on the robot. Fixed and
recorded: distance, angle, lighting, QR size (qrencode -s 20 -m 4), capture
(1640x1232). Failed trials are kept in the raw JSON.
"""
import argparse
import json
import os
import statistics
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def ssh(host, cmd, timeout=120):
    p = subprocess.run(["ssh", "-o", "BatchMode=yes", host, cmd],
                       capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def pct(vals, q):
    xs = sorted(vals)
    if not xs:
        return None
    import math
    r = (len(xs) - 1) * q / 100.0
    lo = math.floor(r)
    hi = math.ceil(r)
    if lo == hi:
        return xs[int(r)]
    return xs[lo] + (xs[hi] - xs[lo]) * (r - lo)  # linear, matches numpy


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--robot", required=True)
    ap.add_argument("--locker", required=True)
    ap.add_argument("--repo", default="project/iotauth")
    ap.add_argument("--id", default="net1.locker1")
    ap.add_argument("--warmup", type=int, default=5)
    ap.add_argument("--measured", type=int, default=100)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    # 1) Locker: generate + display the QR, timed on the locker's clock.
    disp = (
        "python3 - <<'PY'\n"
        "import subprocess,time\n"
        "t0=time.monotonic_ns()\n"
        "subprocess.run(['qrencode','-o','/tmp/locker_qr.png','-s','20','-m','4','%s'],check=True)\n"
        "subprocess.run('sudo pkill -x fbi >/dev/null 2>&1 || true',shell=True)\n"
        "subprocess.run('sudo setsid fbi -T 1 -d /dev/fb0 --noverbose /tmp/locker_qr.png </dev/null >/dev/null 2>&1 &',shell=True)\n"
        "time.sleep(1.0)\n"  # let the viewer paint before the robot scans
        "t1=time.monotonic_ns()\n"
        "print((t1-t0)//1000)\n"
        "PY" % a.id)
    rc, out, err = ssh(a.locker, disp)
    if rc != 0:
        raise SystemExit("locker QR display failed: %s" % err.strip()[-300:])
    prep_us = int(out.strip().splitlines()[-1])
    print("locker QR display prep: %.1f ms" % (prep_us / 1000.0))

    # 2) Robot: run the scan benchmark on its own clock.
    if subprocess.run(["scp", "-q", os.path.join(HERE, "qr_scan_bench.py"),
                       "%s:/tmp/qr_scan_bench.py" % a.robot]).returncode != 0:
        raise SystemExit("cannot deploy qr_scan_bench.py")
    rc, out, err = ssh(a.robot, "python3 /tmp/qr_scan_bench.py %s %d %d "
                       "/tmp/qr_results.json" % (a.id, a.warmup, a.measured),
                       timeout=a.measured * 10 + 300)
    if rc != 0:
        raise SystemExit("robot scan failed: %s" % err.strip()[-300:])
    print(out.strip())
    if subprocess.run(["scp", "-q", "%s:/tmp/qr_results.json" % a.robot,
                       os.path.join(a.out, "qr_raw.json")]).returncode != 0:
        raise SystemExit("cannot collect qr_results.json")

    # 3) Summarize measured matches.
    results = json.load(open(os.path.join(a.out, "qr_raw.json")))
    meas = [r for r in results if r["phase"] == "measured"]
    matched = [r for r in meas if r["match"]]
    durs = [r["duration_us"] for r in matched]
    row = dict(
        requirement="QR-code exchange (static-ID discovery)",
        method="camera+display", expected_id=a.id,
        capture="1640x1232", qr="qrencode -s20 -m4",
        locker_display_prep_ms=round(prep_us / 1000.0, 1),
        successes=len(matched), attempts=len(meas),
        median_ms=round(pct(durs, 50) / 1000.0, 1) if durs else None,
        p95_ms=round(pct(durs, 95) / 1000.0, 1) if durs else None,
        p99_ms=round(pct(durs, 99) / 1000.0, 1) if durs else None,
        attempts_per_scan_mean=round(
            statistics.mean(r["attempts"] for r in meas), 2) if meas else None,
        failures=len(meas) - len(matched))
    with open(os.path.join(a.out, "qr_latency.json"), "w") as f:
        json.dump(row, f, indent=2)
    print(json.dumps(row, indent=2))


if __name__ == "__main__":
    sys.exit(main())
