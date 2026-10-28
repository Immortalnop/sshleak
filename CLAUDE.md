# sshleak: rules for every session

Read `docs/plan.md`, `docs/decisions.md` and this file first. Implement only the current phase or the
gap (`G*` in the plan's "Gaps and fixes" table) you were asked for; proposed gaps G4-G10 and G13 are
add-ons for later.

## Hard rules
- No code path may store, log or write payload bytes. Only `capture/decode.py` and
  `flows/handshake.py` touch payload views; the handshake parser keeps only banners and algorithm
  names and drops its buffer at NEWKEYS (decision G1). `tests/test_safety.py` greps for violations
  and walks every object the pipeline holds.
- There is no option to save payloads or captures. Do not add one.
- Every catalogue case ID gets a test named after it (e.g. `test_F5_late_join`).
- Thresholds live in `sshleak/thresholds/thresholds.toml`. Never hard-code one, and never loosen one
  to make a test pass: stop and ask. New values come from `sshleak lab calibrate` and are accepted by
  the owner (recorded in `docs/decisions.md`).
- Every detector returns `fired`, `not_fired`, `insufficient_evidence` or `skipped` (with a reason),
  never a bare boolean.
- Loopback is the default. Non-local capture needs `--allow-nonlocal` plus a valid scope file; never
  weaken the guard.
- Golden captures must be synthetic or self-generated in the isolated lab (`--network none`). Never
  commit captures of real sessions, keys or datasets.

## Commands
- Tests: `uv run pytest` (fast suite). `uv run pytest -m docker` (real OpenSSH builds),
  `-m slow` (soak), `-m nightly` (long fuzz). Live tests run only with capture rights.
- Lab: `uv run sshleak lab build`, `lab run all`, `lab matrix`, `lab calibrate`.
- End of a phase: full tests, `uv run sshleak doctor`, `uv run sshleak selftest`, CHANGELOG entry.
  Commits and tags only when the owner asks (decision: git initialised, no commits).

## Layout
`sshleak/`: `guard/` safety guard, `discovery/` sockets and processes, `capture/` pcap/pcapng reader,
decoder and backends, `flows/` handshake parser and tracker, `phases/` segmenter, `analysis/` shared
statistics, `detectors/` one file per L-ID, `config/` ssh -G reader, `findings/` engine and report
schema, `output/` formatters, `cli/`, `lab/` (synthetic generator, scenarios, Docker lab, selftest,
calibration), `thresholds/`.
