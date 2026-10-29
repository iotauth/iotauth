"""Ambient-audio similarity (Sound-Proof-inspired).

Compares two ambient-sound recordings and reports a single similarity score,
following the general approach of Sound-Proof (Karapanos et al., USENIX Security
2015, Sec. 6): split both signals into 1/3-octave bands, take the normalized
cross-correlation per band, and average the per-band maxima.

This is a Sound-Proof-*inspired* implementation, not an exact reproduction.
Known deviations from the paper are documented in README.md and recorded in the
per-comparison result (`deviations` field).

The score is NOT a probability. A score of 0.13 does not mean "13% chance of
being co-located"; it is the mean of per-band normalized cross-correlations.
"""

from __future__ import annotations

import time
import wave
from dataclasses import dataclass, field

import numpy as np
from scipy import signal

# ISO preferred 1/3-octave band centers (Hz). The default comparison range is
# 50 Hz - 4 kHz (Sec. 6.2); bands above Nyquist are dropped at design time.
THIRD_OCTAVE_CENTERS_HZ = (
    50, 63, 80, 100, 125, 160, 200, 250, 315, 400,
    500, 630, 800, 1000, 1250, 1600, 2000, 2500, 3150, 4000,
)


@dataclass
class CompareConfig:
    """Fixed comparison settings. Record these alongside every result."""

    sample_rate: int = 48000
    band_centers_hz: tuple[int, ...] = THIRD_OCTAVE_CENTERS_HZ
    filter_order: int = 4  # Butterworth order per band, applied as SOS
    max_lag_ms: float = 150.0  # alignment tolerance, NOT an RTT deadline (Sec. 5)
    min_duration_s: float = 2.5  # reject recordings shorter than this
    # Placeholder thresholds -- calibrate on real recordings, do not treat the
    # paper's 0.13 / 40 dB as physical constants for our USB microphone.
    min_power_dbfs: float = -55.0
    similarity_threshold: float = 0.13  # reference value only (Sec. 6.4)
    # A band whose per-signal energy falls below this (relative to full-band
    # energy) is treated as having no usable content: fixed score 0.0, flagged.
    band_energy_floor: float = 1e-6


@dataclass
class BandResult:
    center_hz: int
    low_hz: float
    high_hz: float
    max_ncc: float
    best_lag_samples: int
    best_lag_ms: float
    a_band_energy: float
    b_band_energy: float
    skipped: bool


@dataclass
class Recording:
    """Decoded PCM plus the capture facts needed to judge validity."""

    samples: np.ndarray  # float64 in [-1, 1], mono, DC not yet removed
    sample_rate: int
    path: str
    n_samples: int
    duration_s: float
    clipping_fraction: float
    meta: dict = field(default_factory=dict)


def load_wav(path: str) -> Recording:
    """Load a mono 16-bit PCM WAV into float64 samples in [-1, 1].

    Clipping fraction is measured on the raw int16 samples (|value| at full
    scale), before any float conversion.
    """
    with wave.open(path, "rb") as wf:
        n_channels = wf.getnchannels()
        sampwidth = wf.getsampwidth()
        sample_rate = wf.getframerate()
        n_frames = wf.getnframes()
        raw = wf.readframes(n_frames)

    if sampwidth != 2:
        raise ValueError(f"{path}: expected 16-bit PCM, got {sampwidth * 8}-bit")
    if n_channels != 1:
        raise ValueError(f"{path}: expected mono, got {n_channels} channels")

    ints = np.frombuffer(raw, dtype="<i2").astype(np.float64)
    clipping_fraction = float(np.mean(np.abs(ints) >= 32767)) if ints.size else 0.0
    samples = ints / 32768.0
    duration_s = ints.size / sample_rate if sample_rate else 0.0

    return Recording(
        samples=samples,
        sample_rate=sample_rate,
        path=path,
        n_samples=int(ints.size),
        duration_s=duration_s,
        clipping_fraction=clipping_fraction,
    )


def power_dbfs(x: np.ndarray) -> float:
    """RMS power in dBFS (0 dBFS = full-scale sine). Returns -inf for silence."""
    if x.size == 0:
        return float("-inf")
    mean_sq = float(np.mean(x * x))
    if mean_sq <= 0.0:
        return float("-inf")
    return float(10.0 * np.log10(mean_sq))


def third_octave_bands(
    centers_hz: tuple[int, ...], sample_rate: int
) -> list[tuple[int, float, float]]:
    """Return (center, low_edge, high_edge) per 1/3-octave band within Nyquist.

    Band edges are center * 2**(-/+ 1/6). Bands whose high edge reaches the
    Nyquist guard are dropped so the Butterworth design stays well-conditioned.
    """
    nyquist = sample_rate / 2.0
    factor = 2.0 ** (1.0 / 6.0)
    bands = []
    for c in centers_hz:
        low = c / factor
        high = c * factor
        if high < nyquist * 0.99:
            bands.append((c, low, high))
    return bands


def _band_sos(low_hz: float, high_hz: float, sample_rate: int, order: int) -> np.ndarray:
    nyquist = sample_rate / 2.0
    return signal.butter(
        order, [low_hz / nyquist, high_hz / nyquist], btype="band", output="sos"
    )


def normalized_cross_correlation(
    x: np.ndarray, y: np.ndarray, max_lag_samples: int
) -> tuple[float, int]:
    """Max |NCC| and its lag within +/- max_lag_samples.

    NCC uses the full-signal energy for normalization (not a per-lag windowed
    energy), so a tiny overlap at a large lag cannot inflate the score; the lag
    window is also small relative to the recording. Returns (0.0, 0) when either
    signal has no energy.
    """
    ex = float(np.dot(x, x))
    ey = float(np.dot(y, y))
    if ex <= 0.0 or ey <= 0.0:
        return 0.0, 0

    corr = signal.correlate(x, y, mode="full", method="fft")
    norm = np.sqrt(ex * ey)
    ncc = corr / norm

    # Lag 0 sits at index len(y) - 1 in a "full" correlation.
    zero_idx = len(y) - 1
    lo = max(0, zero_idx - max_lag_samples)
    hi = min(len(ncc) - 1, zero_idx + max_lag_samples)
    window = ncc[lo : hi + 1]

    rel_idx = int(np.argmax(np.abs(window)))
    best_lag = (lo + rel_idx) - zero_idx
    return float(np.abs(window[rel_idx])), best_lag


def compare(path_a: str, path_b: str, config: CompareConfig | None = None) -> dict:
    """Compare two recordings and return a full result dict.

    The caller gets every intermediate quantity (per-band correlation, lag,
    band energies, powers, clipping, timings) so nothing is silently dropped.
    """
    cfg = config or CompareConfig()
    t0 = time.perf_counter()

    rec_a = load_wav(path_a)
    rec_b = load_wav(path_b)
    t_load = time.perf_counter()

    # DC removal (Sec. 6.1), then global power on the DC-removed signal.
    a = rec_a.samples - np.mean(rec_a.samples) if rec_a.samples.size else rec_a.samples
    b = rec_b.samples - np.mean(rec_b.samples) if rec_b.samples.size else rec_b.samples

    a_power = power_dbfs(a)
    b_power = power_dbfs(b)
    max_lag_samples = int(round(cfg.max_lag_ms / 1000.0 * cfg.sample_rate))

    bands = third_octave_bands(cfg.band_centers_hz, cfg.sample_rate)
    a_energy_total = float(np.dot(a, a)) if a.size else 0.0
    b_energy_total = float(np.dot(b, b)) if b.size else 0.0

    band_results: list[BandResult] = []
    t_filter_total = 0.0
    t_corr_total = 0.0
    for center, low, high in bands:
        sos = _band_sos(low, high, cfg.sample_rate, cfg.filter_order)
        tf = time.perf_counter()
        a_band = signal.sosfiltfilt(sos, a)
        b_band = signal.sosfiltfilt(sos, b)
        t_filter_total += time.perf_counter() - tf

        a_be = float(np.dot(a_band, a_band))
        b_be = float(np.dot(b_band, b_band))
        a_floor = cfg.band_energy_floor * a_energy_total
        b_floor = cfg.band_energy_floor * b_energy_total
        skipped = a_be <= a_floor or b_be <= b_floor

        if skipped:
            band_results.append(
                BandResult(center, low, high, 0.0, 0, 0.0, a_be, b_be, True)
            )
            continue

        tc = time.perf_counter()
        max_ncc, lag = normalized_cross_correlation(a_band, b_band, max_lag_samples)
        t_corr_total += time.perf_counter() - tc
        band_results.append(
            BandResult(
                center_hz=center,
                low_hz=low,
                high_hz=high,
                max_ncc=max_ncc,
                best_lag_samples=lag,
                best_lag_ms=lag / cfg.sample_rate * 1000.0,
                a_band_energy=a_be,
                b_band_energy=b_be,
                skipped=False,
            )
        )

    # Final score = mean of per-band max NCC over the VALID (non-skipped) bands.
    # We never cherry-pick a favorable subset of bands after the fact.
    valid_scores = [br.max_ncc for br in band_results if not br.skipped]
    final_score = float(np.mean(valid_scores)) if valid_scores else 0.0

    # Validity requirements (Sec. 6.4). The threshold decision is reported but
    # kept separate from the structural validity of the recordings.
    long_enough = bool(
        rec_a.duration_s >= cfg.min_duration_s and rec_b.duration_s >= cfg.min_duration_s
    )
    loud_enough = bool(a_power >= cfg.min_power_dbfs and b_power >= cfg.min_power_dbfs)
    inputs_valid = bool(long_enough and loud_enough and valid_scores)
    accepted = bool(inputs_valid and final_score > cfg.similarity_threshold)

    t_end = time.perf_counter()

    return {
        "final_score": final_score,
        "accepted": accepted,
        "inputs_valid": inputs_valid,
        "validity": {
            "long_enough": long_enough,
            "loud_enough": loud_enough,
            "has_valid_band": bool(valid_scores),
        },
        "config": {
            "sample_rate": cfg.sample_rate,
            "filter_order": cfg.filter_order,
            "max_lag_ms": cfg.max_lag_ms,
            "min_duration_s": cfg.min_duration_s,
            "min_power_dbfs": cfg.min_power_dbfs,
            "similarity_threshold": cfg.similarity_threshold,
            "band_energy_floor": cfg.band_energy_floor,
            "n_bands_used": len(bands),
        },
        "recording_a": _rec_summary(rec_a, a_power),
        "recording_b": _rec_summary(rec_b, b_power),
        "bands": [vars(br) for br in band_results],
        "timings_ms": {
            "load": (t_load - t0) * 1000.0,
            "filter": t_filter_total * 1000.0,
            "correlate": t_corr_total * 1000.0,
            "total": (t_end - t0) * 1000.0,
        },
        "deviations": [
            "Sound-Proof-inspired, not an exact reproduction.",
            "Butterworth SOS band filters (zero-phase sosfiltfilt); paper does "
            "not fix a filter family/order.",
            "Band range 50 Hz-4 kHz on a USB microphone; thresholds are "
            "placeholders pending calibration, not the paper's 0.13 / 40 dB.",
        ],
    }


def _rec_summary(rec: Recording, power: float) -> dict:
    return {
        "path": rec.path,
        "sample_rate": rec.sample_rate,
        "n_samples": rec.n_samples,
        "duration_s": rec.duration_s,
        "power_dbfs": power,
        "clipping_fraction": rec.clipping_fraction,
    }
