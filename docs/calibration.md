# Calibration (Phase 4 gate, Phase 9 matrix)

Run 2026-10-28 on WSL2 (timing degraded, case E2; repeat on native Linux before publishing numbers).
Matrix: 32 synthetic scenarios x 3 seeds + 15 real OpenSSH sessions (vanilla 9.4p1, 9.6p1, 9.8p1,
10.6p1 in the isolated Docker lab) x 3 seeds = 141 capture runs. Reproduce with
`uv run sshleak lab matrix --seeds 3 && uv run sshleak lab calibrate`.

**Status: thresholds are provisional (`calibrated = false`). Nothing below has been applied.**

## Detector scores against labels (current thresholds)

After the L4 fix described below, all 45 real sessions match their labels (re-analysed), and
`sshleak selftest` passes 47/47.

| Detector | Fire cases | Recall | Quiet cases | False positives |
| --- | --- | --- | --- | --- |
| L1 timing unprotected | 57 | 100% | 24 | 0 |
| L2 obfuscation inactive | 6 | 100% | 15 | 0 |
| L3 chaff separable | 9 | 100% | 15 | 0 |
| L4 password pattern | 6 (synthetic) | 100% | 3 + 27 real | 0 |
| L5 length exposed | 12 | 100% | 6 | 0 |
| L6 command boundaries | 3 | 100% | 0 | n/a |
| L7 residual timing | 0 | n/a | 3 | 0 |
| L8 obfuscation cost | 6 | 100% | 3 | 0 |
| L9 compression | 6 | 100% | 12 | 0 |
| L10 weak algorithms | 9 | 100% | 9 | 0 |
| L11 client too old | 15 | 100% | 18 | 0 |
| L12 session type | 24 | 100% | 0 | n/a |
| L13 other hop | 0 | n/a | 0 | n/a (needs live process info) |

Targets from the plan: recall >= 95% on L1-L4 and <= 2% false positives per detector are met on this
matrix, except that the matrix has no labelled positive cases for L7 and L13.

## What real OpenSSH traffic showed

- Cadence: measured send interval 20.0-20.7 ms for the default and 80.1 ms for `interval:80`; the
  grid fraction is 0.99+ with obfuscation and at most 0.31 without, so the cadence test separates the
  classes widely.
- L3 (CVE-2024-39894): the 9.6p1 client sends real+chaff as one 72-byte segment on 6.6-6.7% of ticks;
  9.8p1 and 10.6p1 never do (max 0.4%).
- A 10.6p1 client against a 9.4p1 server (no `ping@openssh.com`) sends no chaff at all: L1 and L2
  fire. This backs proposed gap G4 (L2 should name the server as the cause).
- Echo-off typing (`read -s`): OpenSSH servers send a simulated echo (SSH_MSG_IGNORE), so there are no
  missing replies. On 9.4p1 that reply arrives faster than a real echo (median 312 us vs 552 us).
  L4's window-median latency test caught this in 1 of 3 real unprotected runs, with no false
  positives. Under obfuscation it is not applied (fixed below).
- Short command output arrives as 44-84 B packets; the Enter rule was changed accordingly (decisions).

## Fix found by the matrix

The first matrix showed L4's latency test firing on real obfuscated sessions with no password
(chaff PONGs are as fast as simulated echo). L4 now applies the latency test only when there is no
send cadence, and every no-password scenario is labelled `L4: not_fired` so false positives are
counted. After the fix: 0 false positives on 45 real sessions.

## Proposed thresholds (for your acceptance)

From `sshleak lab calibrate` (full file: `docs/thresholds.candidate.toml`):

| Threshold | Current | Proposed | Basis |
| --- | --- | --- | --- |
| cadence.grid_min_fraction | 0.8 | 0.65 | separates 0.309 (unprotected max) from 0.991 (obfuscated min) |
| cadence.peak_min_fraction | 0.5 | 0.633 | separates 0.275 from 0.991 |
| L3.min_double_fraction | 0.01 | 0.035 | separates 0.004 (fixed max) from 0.067 (flawed min) |
| L7.min_abs_rho | 0.3 | keep 0.3 | max observed abs(rho) 0.081 |
| L4.latency_ratio_max | 0.5 | keep | no separating value: real echo-off windows 0.32-0.52 overlap normal typing 0.54-0.69 |

My reading: the current cadence and L3 values already sit inside the separating gaps, so the
proposals are midpoints rather than corrections. L4's latency signal is real but weak on this
machine; keep it as is and treat L4 against OpenSSH servers as low recall.
