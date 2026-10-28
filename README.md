# sshleak

`sshleak scan` is a passive, local detector for SSH keystroke timing and size leaks. It finds SSH
connections, looks only at packet metadata (time, size, direction) plus the cleartext handshake
(software versions and algorithm names), and reports findings with severity, confidence, evidence
and a fix. It never decrypts anything and never stores payload bytes.

Default: observe loopback (`lo`, 127.0.0.1 and ::1) for 30 seconds.

```
$ sshleak scan --pcap tests/golden/real_d_flawed.pcap
 f1  127.0.0.1:42338 -> 127.0.0.1:2222  client OpenSSH_9.6  server OpenSSH_9.6  4,385 pkts  shell
  HIGH  L3   chaff separable    conf 0.66   real sends ~2x chaff size in 139/2100 ticks (6.6%); ...
        fix: Upgrade the client to OpenSSH 9.8 or later ...
```

## Install

```
uv sync                 # Python 3.11+ (uv installs 3.12 if needed)
uv run sshleak doctor   # checks capture rights, kernel, offload, clock, OpenSSH, Docker
```

Live capture runs tcpdump as a subprocess. Grant capture rights to tcpdump only, never to Python:

```
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(command -v tcpdump)")"
```

Or run under `sudo`. Saved captures (`--pcap`) need no privileges.

## Commands

| Command | Does |
| --- | --- |
| `sshleak scan [--iface lo] [--target IP] [--duration 30]` | One-shot passive scan of live flows |
| `sshleak scan --pcap file.pcap` | Same detectors on a saved pcap/pcapng |
| `sshleak watch [--pcap f] [--interval 5]` | Continuous; emits a finding when evidence first suffices, then updates |
| `sshleak flows` | Lists SSH flows: ports, versions, process, phase, packets |
| `sshleak explain L3` | Meaning, evidence rule, statistic and fix of a finding |
| `sshleak ci --fail-on high` | Pipeline gate (JSON by default) |
| `sshleak selftest [--build]` | Labelled leaky and safe sessions (synthetic + real OpenSSH in Docker) |
| `sshleak lab list / synth / build / run / matrix / calibrate` | Labelled traffic for calibration and tests |
| `sshleak report saved.json` | Show a saved JSON report (older schemas migrated, newer read-only) |
| `sshleak doctor` | Environment checks |

Useful flags: `--flow f2`, `--only L1,L3`, `--min-packets N`, `--format table|json|jsonl|sarif`,
`--redact/--no-redact`, `--config-check` (reads the client's effective config with `ssh -G`),
`--thresholds file.toml`, `--fail-on high|medium|info|none`, `-v`.

Exit codes: 0 clean, 1 findings at or above `--fail-on`, 2 evidence insufficient for checks requested
with `--only`, 3 environment or invocation error, 4 safety refusal, 5 internal error.

## Findings

| ID | Finding | Severity |
| --- | --- | --- |
| L1 | Keystroke timing unprotected | High |
| L2 | Obfuscation configured but not active | High |
| L3 | Chaff distinguishable from real keystrokes (CVE-2024-39894) | High |
| L4 | Password-entry pattern visible | High |
| L5 | Keystroke count / command length exposed | Medium |
| L6 | Command-boundary timing | Medium |
| L7 | Residual timing under obfuscation | Medium |
| L8 | Obfuscation cost out of bounds | Info |
| L9 | Compression on interactive session | Medium |
| L10 | Weak cipher or MAC family (incl. Terrapin without strict KEX) | Medium |
| L11 | Client lacks the feature (OpenSSH < 9.5) | Medium |
| L12 | Session type exposed | Info |
| L13 | Multiplexed or jump-host path hides observation point | Info |

Each detector returns `fired`, `not_fired`, `insufficient_evidence` or `skipped` with a reason. When
metadata cannot prove something the answer is "insufficient evidence", never "safe".

Score: 100 = no leaks; each fired finding subtracts its severity weight (High 30, Medium 12, Info 2)
times its confidence.

## Safety

- Loopback only by default. A non-loopback interface or target needs `--allow-nonlocal` and a
  scope file (`[scope]` owner, signed_off_by, expires, interfaces, targets); otherwise exit 4.
  Approved non-local runs are appended to `~/.local/state/sshleak/audit.jsonl`.
- Metadata only: banner and KEXINIT are read for names; encrypted payload is discarded at parse time
  and never stored, logged or written. There is no option to save payloads.
- Passive: `scan` and `watch` send no packets. The lab only talks to its own sshd inside an isolated
  container (`--network none`).
- Other users' flows are shown only as counts unless you are root and pass `--all-users`; command
  lines and file paths are redacted by default.
- Capturing other people's traffic without authorisation can be illegal. Only scan hosts and
  networks you own or have written permission to test.

## Lab and tests

```
uv run pytest                     # fast suite
uv run sshleak lab build          # vanilla OpenSSH 9.4p1 / 9.6p1 / 9.8p1 / 10.6p1, SHA256-pinned
uv run pytest -m docker           # real OpenSSH sessions
uv run sshleak selftest           # end to end
uv run sshleak lab matrix && uv run sshleak lab calibrate   # Phase 9 numbers + proposals
```

## Status

Thresholds are provisional (`calibrated = false`) until you accept the calibration in
`docs/calibration.md`. Timing captured on WSL2 or a VM is reported as degraded. See `docs/plan.md`
for the plan and `docs/decisions.md` for decisions.
