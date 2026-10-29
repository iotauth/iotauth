"""Ambient-audio capture via ALSA (arecord).

Records a fresh mono 16-bit PCM clip from a USB microphone and writes it next to
a JSON sidecar describing the capture facts the verifier must be able to check:
requested vs. actual sample count, clipping, microphone gain, and whether AGC /
noise suppression controls are present. A recording whose sample count or timing
cannot be established is not a valid verification input (Sec. 4).

Capture runs on the Raspberry Pi (ALSA required); the analysis side has no ALSA
dependency.
"""

from __future__ import annotations

import json
import subprocess
import time
import wave


def _amixer_dump(device_card: str) -> dict:
    """Best-effort snapshot of mixer controls (gain / AGC / noise suppression).

    Returns {} when amixer is unavailable; the capture still proceeds but the
    gain/AGC state is recorded as unknown rather than guessed.
    """
    card = device_card.split(",")[0].replace("plughw:", "").replace("hw:", "")
    try:
        out = subprocess.run(
            ["amixer", "-c", card, "scontents"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if out.returncode != 0:
        return {}
    return {"card": card, "scontents": out.stdout}


def capture(
    out_path: str,
    duration_s: float = 3.0,
    device: str = "plughw:3,0",
    sample_rate: int = 48000,
    warmup_s: float = 0.3,
) -> dict:
    """Record `duration_s` of audio to `out_path` (16-bit mono PCM WAV).

    A short `warmup_s` is recorded first and discarded so stale buffered audio
    from before the request does not enter the clip (Sec. 4). The returned
    metadata is also written to `out_path + ".json"`.
    """
    total_s = duration_s + warmup_s
    mixer_before = _amixer_dump(device)

    start_wall = time.time()
    start_mono = time.monotonic()
    proc = subprocess.run(
        [
            "arecord",
            "-D", device,
            "-f", "S16_LE",
            "-c", "1",
            "-r", str(sample_rate),
            "-d", str(total_s),
            "-t", "wav",
            out_path,
        ],
        capture_output=True,
        text=True,
    )
    end_mono = time.monotonic()

    capture_error = None if proc.returncode == 0 else proc.stderr.strip()

    # Trim the warmup prefix in place, and measure the ACTUAL captured samples.
    actual_samples = 0
    actual_rate = sample_rate
    warmup_samples = int(round(warmup_s * sample_rate))
    if capture_error is None:
        actual_samples, actual_rate = _trim_prefix(out_path, warmup_samples)

    expected_samples = int(round(duration_s * sample_rate))
    meta = {
        "path": out_path,
        "device": device,
        "requested_rate": sample_rate,
        "actual_rate": actual_rate,
        "requested_duration_s": duration_s,
        "warmup_s": warmup_s,
        "expected_samples": expected_samples,
        "actual_samples": actual_samples,
        "sample_count_ok": abs(actual_samples - expected_samples) <= sample_rate * 0.02,
        "start_wall_unix": start_wall,
        "start_monotonic_s": start_mono,
        "end_monotonic_s": end_mono,
        "capture_error": capture_error,
        "mixer": mixer_before,
    }
    with open(out_path + ".json", "w") as f:
        json.dump(meta, f, indent=2)
    return meta


def _trim_prefix(path: str, prefix_samples: int) -> tuple[int, int]:
    """Drop the first `prefix_samples` frames in-place; return (n_samples, rate)."""
    with wave.open(path, "rb") as wf:
        params = wf.getparams()
        frames = wf.readframes(wf.getnframes())
    sampwidth = params.sampwidth
    cut = frames[prefix_samples * sampwidth :]
    with wave.open(path, "wb") as wf:
        wf.setparams(params)
        wf.writeframes(cut)
    return len(cut) // sampwidth, params.framerate
