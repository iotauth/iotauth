# Ambient-audio similarity (Sound-Proof-inspired)

Standalone capture + similarity tool for physical-context verification based on
**passive ambient sound**: two Raspberry Pis each record their surroundings and
the recordings are compared for time/frequency similarity.

This is a **Sound-Proof-inspired** implementation, not an exact reproduction of
the paper (Karapanos et al., *Sound-Proof: Usable Two-Factor Authentication
Based on Ambient Sound*, USENIX Security 2015). Known deviations are listed
below and recorded in every result (`deviations` field).

It is a **separate mechanism** from the existing acoustic keyed-echo
(`entity/c/ultrasonic_com`), which it does not replace. It does **not** play any
chirp or random sound (no DoubleEcho / Listening-Watch); comparison is on
naturally occurring ambient audio only.

## Scope of this phase (Phase 1 — standalone)

Implemented here: `capture`, `compare`, `benchmark` (plan sections 3–6).
**Not** in this phase: clock synchronization, authenticated-session transport,
threshold calibration, and the formal evaluation (plan sections 5, 7–11). Those
require two co-located Pis and are done later.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt   # numpy, scipy
```

Capture additionally needs ALSA (`arecord`, `amixer`) and runs on the Pi only.
Analysis (`compare`, `benchmark`) has no ALSA dependency.

## Usage

Run from `entity/python/` so the package is importable:

```bash
cd entity/python

# Record a 3 s clip on a Pi (USB mic is plughw:3,0 in this testbed)
python -m ambient_audio capture clip.wav --duration 3 --device plughw:3,0

# Compare two recordings; write machine-readable outputs
python -m ambient_audio compare A.wav B.wav --json out.json --csv bands.csv

# Processing-time benchmark (repeats the comparison)
python -m ambient_audio benchmark A.wav B.wav --repeat 10
```

`compare` prints a human summary (per-band max NCC, lag, validity, timings) and,
with `--json`/`--csv`, writes the full result and per-band detail.

## How the score is computed (sections 4–6)

- **Capture** (`capture.py`): mono 16-bit PCM at 48 kHz. A short warmup is
  recorded and discarded so stale buffered audio is excluded. The JSON sidecar
  records requested vs. actual sample count, clipping, and the mixer snapshot
  (gain / AGC / noise-suppression controls). A clip whose sample count cannot be
  established is not a valid verification input.
- **Preprocessing** (`similarity.py`): DC removal, global power in **dBFS**
  (0 dBFS = full-scale sine), clipping fraction.
- **Band split**: ISO 1/3-octave bands, centers 50 Hz–4 kHz, as 4th-order
  Butterworth **SOS** band filters applied zero-phase (`sosfiltfilt`) identically
  to both signals. Bands above the Nyquist guard are dropped.
- **Per-band normalized cross-correlation**: FFT-based cross-correlation
  normalized by the **full-signal** energy of each band; the maximum absolute
  value within ±`max_lag_ms` (default 150 ms) is the band score. Full-energy
  normalization plus the small lag window prevent a tiny high-lag overlap from
  inflating the score. A band whose energy is below `band_energy_floor` on either
  side is skipped (fixed rule, flagged — never cherry-picked).
- **Final score** = mean of the per-band maxima over **all valid** bands.

The score is **not a probability**: 0.13 is not "13% co-located".

## Validity and thresholds (section 6.4)

A comparison is `accepted` only if inputs are valid (both long enough, both above
`min_power_dbfs`, at least one usable band) **and** `final_score >
similarity_threshold`.

The defaults are **placeholders pending calibration**:
`similarity_threshold=0.13` (paper reference value only) and
`min_power_dbfs=-55`. The paper's 0.13 / 40 dB are **not** copied as physical
constants for our USB microphone — power here is dBFS and must be calibrated
separately.

## Deviations from Sound-Proof

- Sound-Proof-inspired, not an exact reproduction.
- Butterworth SOS band filters (zero-phase); the paper does not fix a filter
  family/order.
- 50 Hz–4 kHz on a USB microphone; thresholds are placeholders, not the paper's
  0.13 / 40 dB. Power is expressed in dBFS.
- One phone compares in the paper; in our system either endpoint may compare for
  its own action (but two computations over the same pair are **not** two
  independent security checks).

## Tests

```bash
cd entity/python
PYTHONPATH=. .venv/bin/python -m unittest ambient_audio.tests.test_similarity -v
```

Synthetic-audio tests pin the scoring: identical and within-window-shifted
signals score high, uncorrelated signals score low, and silence / too-short /
non-mono inputs are rejected.
