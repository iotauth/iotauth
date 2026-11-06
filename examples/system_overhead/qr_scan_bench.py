#!/usr/bin/env python3
"""Robot-side QR scan benchmark (runs on the robot Pi).

Replicates qr_io.h's qr_scan_entity_id exactly: up to 3 attempts of
rpicam-jpeg (1640x1232) + zbarimg --raw, success on the first non-empty decode.
Times each scan on the robot's own CLOCK_MONOTONIC (time.monotonic_ns) from just
before the scan procedure to just after verifying the decoded value against the
expected id. Writes a JSON array of per-trial records.

  qr_scan_bench.py <expected_id> <warmup> <measured> <out.json>
"""
import json
import subprocess
import sys
import time

DN = subprocess.DEVNULL


def scan():
    """Returns (decoded_value, attempts) mirroring qr_scan_entity_id."""
    attempts = 0
    for a in range(1, 4):
        attempts = a
        r = subprocess.run(
            ["rpicam-jpeg", "-o", "/tmp/robot_qr.jpg", "-t", "1500",
             "--width", "1640", "--height", "1232", "--nopreview"],
            stdout=DN, stderr=DN)
        if r.returncode != 0:
            continue
        p = subprocess.run(["zbarimg", "--quiet", "--raw", "/tmp/robot_qr.jpg"],
                           capture_output=True, text=True)
        out = p.stdout.strip()
        val = out.splitlines()[0].strip() if out else ""
        if val:
            return val, attempts
    return "", attempts


def main():
    expected, warmup, measured, out = (sys.argv[1], int(sys.argv[2]),
                                       int(sys.argv[3]), sys.argv[4])
    results = []
    for i in range(warmup + measured):
        phase = "warmup" if i < warmup else "measured"
        t0 = time.monotonic_ns()
        val, attempts = scan()
        t1 = time.monotonic_ns()
        results.append(dict(index=i, phase=phase,
                            duration_us=(t1 - t0) // 1000, attempts=attempts,
                            decoded=val, match=(val == expected)))
    with open(out, "w") as f:
        json.dump(results, f)
    m = [r for r in results if r["phase"] == "measured"]
    print("done: %d/%d measured matches" % (sum(r["match"] for r in m), len(m)))


if __name__ == "__main__":
    main()
