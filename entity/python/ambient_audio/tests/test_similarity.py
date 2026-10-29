"""Unit tests for the ambient-audio similarity scoring.

Synthetic signals only -- no microphone or hardware. These pin the scoring
behaviour: identical/shifted ambient-like signals score high, uncorrelated
signals score low, silence is rejected, and malformed WAVs are refused.
"""

from __future__ import annotations

import os
import tempfile
import unittest
import wave

import numpy as np

from ambient_audio.similarity import CompareConfig, compare, load_wav

SR = 16000
DUR = 3.0
CFG = CompareConfig(sample_rate=SR)


def _write_wav(path: str, samples: np.ndarray, sr: int = SR, sampwidth: int = 2,
               channels: int = 1) -> None:
    ints = np.clip(samples * 32768.0, -32768, 32767).astype("<i2")
    with wave.open(path, "wb") as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(sampwidth)
        wf.setframerate(sr)
        wf.writeframes(ints.tobytes())


def _ambient(seed: int, n: int) -> np.ndarray:
    """Band-limited colored noise standing in for ambient sound."""
    rng = np.random.default_rng(seed)
    x = rng.standard_normal(n)
    # light low-pass so energy spreads across the 50 Hz-4 kHz bands
    kernel = np.ones(8) / 8.0
    x = np.convolve(x, kernel, mode="same")
    return x / (np.max(np.abs(x)) + 1e-9) * 0.5


class SimilarityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.n = int(DUR * SR)

    def _path(self, name):
        return os.path.join(self.tmp, name)

    def test_identical_signals_score_high(self):
        x = _ambient(1, self.n)
        a, b = self._path("a.wav"), self._path("b.wav")
        _write_wav(a, x)
        _write_wav(b, x)
        r = compare(a, b, CFG)
        self.assertGreater(r["final_score"], 0.9)
        self.assertTrue(r["accepted"])

    def test_shift_within_lag_window_still_high(self):
        x = _ambient(2, self.n)
        shift = int(0.05 * SR)  # 50 ms, within the 150 ms window
        a, b = self._path("a.wav"), self._path("b.wav")
        _write_wav(a, x)
        _write_wav(b, np.roll(x, shift))
        r = compare(a, b, CFG)
        self.assertGreater(r["final_score"], 0.7)
        # the recovered lag should be close to the injected shift
        lags = [band["best_lag_samples"] for band in r["bands"] if not band["skipped"]]
        self.assertTrue(any(abs(abs(lag) - shift) < 0.02 * SR for lag in lags))

    def test_uncorrelated_signals_score_low(self):
        a, b = self._path("a.wav"), self._path("b.wav")
        _write_wav(a, _ambient(3, self.n))
        _write_wav(b, _ambient(999, self.n))
        r = compare(a, b, CFG)
        self.assertLess(r["final_score"], 0.3)
        self.assertFalse(r["accepted"])

    def test_silence_is_rejected(self):
        a, b = self._path("a.wav"), self._path("b.wav")
        _write_wav(a, np.zeros(self.n))
        _write_wav(b, np.zeros(self.n))
        r = compare(a, b, CFG)
        self.assertFalse(r["validity"]["loud_enough"])
        self.assertFalse(r["inputs_valid"])
        self.assertFalse(r["accepted"])

    def test_too_short_is_rejected(self):
        short = int(1.0 * SR)  # 1 s < min_duration_s 2.5 s
        a, b = self._path("a.wav"), self._path("b.wav")
        _write_wav(a, _ambient(4, short))
        _write_wav(b, _ambient(4, short))
        r = compare(a, b, CFG)
        self.assertFalse(r["validity"]["long_enough"])
        self.assertFalse(r["inputs_valid"])

    def test_rejects_stereo(self):
        a = self._path("stereo.wav")
        x = _ambient(5, self.n)
        _write_wav(a, np.repeat(x, 2), channels=2)
        with self.assertRaises(ValueError):
            load_wav(a)


if __name__ == "__main__":
    unittest.main()
