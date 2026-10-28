<!-- Saved from the plan doc 'sshleak scan — Live SSH Timing-Leak Detector: Plan' (rev 24). -->

# sshleak scan — Live SSH Timing-Leak Detector: Plan

2026-10-27 · AMM

## Summary

`sshleak scan` is a passive, local detector: it finds live SSH connections, watches only packet metadata (time, size, direction), and flags timing and size leaks with evidence and a fix. Default target is `127.0.0.1`.

**What changes from the research plan**

| Research plan | Scanner |
| --- | --- |
| Answers "how much leaks?" with trained attack models | Answers "is it leaking right now, and why?" with rule + statistical detectors |
| Replays dataset keystrokes; offline | Observes real connections; live or from a pcap |
| Needs datasets, GPU, hours | Needs none at run time; seconds to minutes |
| Verdict = bits per keystroke | Verdict = findings, each with severity, confidence, evidence, remediation |
| Isolated lab only | Lab is reused only to calibrate and test the detectors |

The research harness is kept as a small `sshleak lab` module: it produces labelled traffic so every detector has ground truth.

**Design principle:** a detector may only claim what metadata can prove. Otherwise it reports "insufficient evidence", never "safe" and never a guess.

## Findings the scanner flags

Severity: **High** = an observer can recover typed content or defeat the defence; **Medium** = structure or timing exposed; **Info** = context. Every finding carries confidence (0-1), evidence (packet counts, stats), and a fix.

| ID | Finding | Signal used | Sev | Fix |
| --- | --- | --- | --- | --- |
| L1 | Keystroke timing unprotected | Interactive client-to-server stream of small packets, gap distribution has no fixed cadence | High | Enable `ObscureKeystrokeTiming` on the client; upgrade to a fixed OpenSSH |
| L2 | Obfuscation configured but not active | Config says on, no cadence peak at the interval in capture | High | Check effective config (`ssh -G`), client version, X11 interaction |
| L3 | Chaff distinguishable from real keystrokes | Bimodal packet sizes in the chaff phase, or server reply count differs per packet (bug class from OpenSSH 9.5-9.7) | High | Upgrade to a release with the fix (version to confirm, see open questions) |
| L4 | Password-entry pattern visible | Client packets with no matching server echo for a stretch, then a burst on Enter | High | Use keys or agent auth; avoid typing secrets in a remote prompt over a leaky setup |
| L5 | Keystroke count / command length exposed | Number of client packets in a burst follows typed length | Medium | Obfuscation interval plus chaff; consider a padding layer |
| L6 | Command-boundary timing | Pause then burst on Enter, response size after it | Medium | Obfuscation; shell prompt noise |
| L7 | Residual timing under obfuscation | Gap variance inside the quantum correlates with packet sizes or reply latency | Medium | Larger interval; verify client build |
| L8 | Obfuscation cost out of bounds | Chaff bytes/s and added latency above set thresholds | Info | Tune `interval:N` |
| L9 | Compression on interactive session | `-C` negotiated, size follows content | Medium | Disable compression for interactive use |
| L10 | Weak cipher or MAC family | Negotiated algorithm names from the cleartext KEX | Medium | Prefer chacha20-poly1305 or AES-GCM |
| L11 | Client lacks the feature | Client banner version older than 9.5 | Medium | Upgrade the client |
| L12 | Session type exposed | Size and gap shape reveals shell vs sftp vs scp vs port-forward | Info | Not fixable by timing options; document |
| L13 | Multiplexed or jump-host path hides observation point | Flow seen on a different hop than the client | Info | Re-run scan at the client's own interface |

**Passive scope:** L1-L7, L9-L13 need only metadata and the cleartext banner/KEX. L2 and L11 additionally read the local client config when the client process is on this host.

## Architecture

*(diagram: scanner pipeline · 8 stages)*

The detector bank also reads the local client and server config when the connection's process is on this host.

| Component | Responsibility | Key decisions |
| --- | --- | --- |
| Safety guard | Validates interface, targets and privileges first | Loopback default; non-local needs explicit flag + scope file; exit 4 on refusal |
| Flow discovery | Lists live TCP connections and identifies SSH by banner, not port | `ss`/`/proc/net/tcp` plus psutil; owning process and command line when readable |
| Capture | Reads packets for chosen flows only | BPF filter pinned to the flow 4-tuple; snaplen 4096 B; payload discarded at parse, never stored (G1) |
| Flow tracker | Per-flow records: time (ns), direction, TCP payload length, seq | Drops retransmits, handles reordering, caps memory per flow |
| Phase segmenter | Splits handshake, auth, interactive, bulk transfer, idle | Uses message-size shape and gaps; needs no decryption |
| Detector bank | Runs L1-L13 over interactive segments | Each detector is a plugin with a minimum-evidence rule |
| Findings engine | Merges detector output, scores, deduplicates, attaches fixes | Severity from rule, confidence from sample size and effect |
| Output | Table, JSON, JSONL stream, exit codes | Versioned schema; redaction by default |

**Same code, three inputs:** live interface, saved pcap, or the built-in lab generator. Detectors never know which.

## CLI

**Default invocation:** `sshleak scan` observes loopback (`lo`, `127.0.0.1` and `::1`) for 30 seconds, finds SSH flows by banner, reports findings, exits.

| Command | Does |
| --- | --- |
| `sshleak doctor` | Checks capture rights, kernel, offload, clock, OpenSSH versions, tcpdump/libpcap |
| `sshleak scan [--iface lo] [--target 127.0.0.1] [--duration 30]` | One-shot passive scan of live flows |
| `sshleak watch` | Continuous; emits a finding the first time evidence is sufficient, then updates it |
| `sshleak scan --pcap file.pcap` | Same detectors on a saved capture (offline, repeatable) |
| `sshleak flows` | Lists discovered SSH flows: ports, versions, process, phase, packets seen |
| `sshleak explain L3` | Prints what the finding means, the evidence rule, and the fix |
| `sshleak selftest` | Spawns its own ephemeral loopback sshd + typing generator and checks every detector fires on known-leaky and stays quiet on known-safe traffic |
| `sshleak lab ...` | Research harness from the first plan (labelled traffic for calibration) |
| `sshleak ci --fail-on high` | Gate for pipelines: scan, then non-zero exit above a severity |

**Useful flags:** `--flow <id>`, `--only L1,L3`, `--min-packets N`, `--format table|json|jsonl|sarif`, `--redact/--no-redact`, `--config-check` (read local ssh_config/sshd_config), `--thresholds file.toml`.

**Exit codes:** 0 clean · 1 findings at or above `--fail-on` · 2 evidence insufficient for requested checks · 3 environment error · 4 safety refusal · 5 internal error (never silent).

**Sample output**

```
Flow 2  127.0.0.1:51822 -> 127.0.0.1:22  client OpenSSH_9.6  server OpenSSH_9.6  1,284 pkts
  HIGH  L3  chaff separable   conf 0.93   real packets ~2x chaff size in 612/614 cases
        fix: upgrade to a release containing the chaff fix
  MED   L5  length exposed    conf 0.81   burst packet count tracks typed length (r = 0.97)
  INFO  L8  obfuscation cost  +9.8 ms p95, 41 KB/s chaff
Score 38/100  (3 findings, 0 checks skipped)
```

The numbers above are an illustration of the format, not a result.

## Engineering depth

**1. Flow identification without trusting ports**

- Match the cleartext `SSH-2.0-...` banner in the first payload of each direction. Parse client and server software versions and the KEXINIT algorithm lists (all cleartext).
- Flows that start mid-stream (scanner launched after connect): mark `late-join`; version and KEX unknown, so L10/L11 are skipped and reported as skipped. Timing detectors still run on size shape.
- Loopback specifics: each packet appears once on `lo` (not twice); GSO/GRO can present packets larger than MTU. Detector inputs use post-offload-disabled capture in `selftest`, and live scans flag when offload may merge packets.

**2. Phase segmentation (no decryption)**

| Phase | How recognised |
| --- | --- |
| Handshake | Cleartext banner + KEX messages |
| Auth | First encrypted exchanges, bounded count; ends when sustained session traffic starts |
| Interactive | Many small client packets with small server replies close behind |
| Bulk | Large packets, high throughput (scp/sftp/forward) |
| Idle | No payload beyond keepalive cadence |

Segments with fewer than `min_packets` (default 60 client packets) are not analysed; the finding is "insufficient evidence", exit 2 when it was a requested check.

**3. Detector design rules**

- Each detector declares: inputs, minimum evidence, test statistic, threshold source, false-positive guard.
- Thresholds come from `sshleak lab` calibration across the config matrix, shipped as versioned `thresholds.toml`, never hand-tuned in code.
- Statistics: bootstrap CIs on effect sizes; two-sample tests (e.g. KS / Mann-Whitney) for distribution claims; multiple-testing correction across detectors; confidence combines sample size and effect size.
- Examples: **L1** = gap distribution not concentrated on a grid. **L2** = periodicity test (autocorrelation / histogram peaks) at the configured interval fails. **L3** = size or reply-count mixture is bimodal beyond a threshold. **L4** = run of client packets with no server reply within the echo window, then a burst.

**4. Correlating live flow with local config (optional, ****`--config-check`****)**

- Map flow to owning process via socket inode; read its command line (needs same user or root).
- Run `ssh -G <host>` equivalent parse to get the effective `ObscureKeystrokeTiming` value; compare with observed cadence (L2). If the process is not readable, say so and skip, never guess.

**5. Performance and safety of the scanner itself**

- Zero-copy ring buffer capture; BPF filter in kernel so only chosen flows reach user space.
- Memory cap per flow (rolling window of last N packets); global flow cap with eviction.
- Time handling: use capture-hardware or kernel timestamps; record timestamp source and resolution in output.
- Drop accounting from the capture handle; any drops mark findings `degraded`.
- Deterministic output given the same pcap and thresholds file.

**6. Extensibility**

- Detector plugin interface (Python entry points); capture backend interface (AF_PACKET, pcap file, lab generator); output formatters (table, JSON, JSONL, SARIF).

## Gaps and fixes (pre-Phase 0 review)

A review before Phase 0 found 13 gaps; each row says the fix, where it lands, and its status. Rows marked "Needs your decision" go to `docs/decisions.md` before their phase starts.

| ID | Gap | Fix | Affects | Status |
| --- | --- | --- | --- | --- |
| G1 | Banner and KEXINIT parsing needs payload bytes, but the plan says payload is truncated at capture | Rule relaxed: one capture with snaplen 4096 B so the banner and KEXINIT parse; only versions and algorithm names are kept. Encrypted payload may pass through memory but is discarded at parse time and never stored, logged or written. The no-payload test checks records, logs and output | Phase 1, 3 · Safety | Adopted |
| G2 | Flows that started before the scan (late-join) never show a banner, so default `scan` would miss live sessions | Fallback runs only once the scan has started; nothing is collected beforehand. Sessions already open are identified by owning process (`ssh`/`sshd` via psutil), then by encrypted size shape; flow marked late-join with lower confidence | Phase 1 · F5, D3 | Adopted |
| G3 | A raw AF_PACKET socket on `lo` sees each packet twice (libpcap hides this) | Drop PACKET_OUTGOING copies on `lo`; take direction from the 4-tuple | Phase 1 · C4 | Adopted |
| G4 | L2 only checks the client config | Chaff is SSH2_MSG_PING, sent only if the server advertises `ping@openssh.com` (server ≥ 9.5). L2 expects obfuscation only when client ≥ 9.5, server ≥ 9.5, a pty, and not disabled; otherwise it says why it is absent | Phase 4, 7 · L2, L11 | Proposed |
| G5 | L3 cannot be decided by version | Flaw is 9.5–9.7 client vs 9.5+ server, fixed upstream in 9.8 ([CVE-2024-39894](https://ubuntu.com/security/CVE-2024-39894)); distros backported it (Ubuntu `9.6p1-3ubuntu13.4` is fixed). Version is a low-confidence hint; firing needs evidence: two SSH packets per tick, e.g. 72-byte segments (2 × 36) | Phase 6 · L3, V2 | Proposed |
| G6 | Several SSH messages can share one TCP segment | Size-based detectors work in multiples of the base packet size, not raw segment lengths | Phase 4, 6 · L3, L5 | Proposed |
| G7 | L8 added latency cannot be measured passively (keypress time is unseen) | Report expected added latency (mean interval/2, max one interval) plus measured chaff bytes/s | Phase 4 · L8 | Proposed |
| G8 | L13 has no passive signal on loopback | Detect from client command line or config (`-J`, `ProxyJump`, `ControlMaster`) under `--config-check`; otherwise skipped | Phase 7 · L13, C8 | Proposed |
| G9 | Distro packages may carry the backport, so they cannot serve as the flawed build | Vanilla source builds pinned by SHA256: 9.4p1 (no feature), 9.6p1 (flawed), 9.8p1 (first fixed), 10.6p1 (latest). Client and sshd containers run with `--network host` so traffic stays on `lo`; pty typing generator; throwaway keys | Phase 2 · lab, selftest | Proposed |
| G10 | Byte-identical JSON needs more than fixed inputs | Seeded bootstrap RNG, fixed float format, sorted keys, wall-clock times kept outside the deterministic block | Phase 5 · D8 | Proposed |
| G11 | Capture privilege for a Python process | Default: `tcpdump` subprocess with `setcap cap_net_raw,cap_net_admin=eip` on tcpdump (narrowest grant; kernel nanosecond timestamps and drop counts). Running under `sudo` also works; `doctor` reports which one applies. Native AF_PACKET backend later as a plugin. Never setcap the Python interpreter | Phase 1 · E1 | Adopted |
| G12 | Packet parsing library | Own small parser: pcap and pcapng (SHB, IDB, EPB, `if_tsresol`); link types Ethernet, SLL, SLL2, raw IP, NULL; IPv4/IPv6; TCP. dpkt only as a dev-time cross-check in tests; scapy ruled out (too slow for live rates) | Phase 1 · C6 | Adopted |
| G13 | Dev machine (WSL2, Ubuntu 22.04): Python 3.10, OpenSSH client 8.9, no sshd | uv-managed Python 3.12 (`tomllib`); the local 8.9 target can only show unprotected traffic (L1, L11), so all obfuscation tests use lab containers | Before Phase 0 · E2 | Proposed |

Sources for G4, G5: [OpenSSH 9.8 release notes](https://www.openssh.org/txt/release-9.8), [OpenSSH 9.5 release notes](https://www.openssh.org/txt/release-9.5), [chaff packet capture write-up](https://eieio.games/blog/ssh-sends-100-packets-per-keystroke/).

## Case catalogue

Every case has an automated test and one defined outcome: **Handled** (correct result), **Skipped** (check not run, reported as skipped), **Degraded** (result kept, marked lower confidence), or **Refused** (stops with reason and exit code).

| ID | Case | Outcome | Behaviour |
| --- | --- | --- | --- |
| **Discovery** |  |  |  |
| F1 | No SSH flows on the interface | Handled | "No flows" message, exit 0; `watch` keeps waiting |
| F2 | SSH on a non-standard port | Handled | Found by banner |
| F3 | Non-SSH traffic on port 22 | Handled | Banner mismatch, ignored |
| F4 | Many concurrent flows (100+) | Handled | Per-flow cap; summary table; `--flow` to focus |
| F5 | Flow starts before scanner (late-join) | Skipped | Version/KEX checks skipped, timing checks run |
| F6 | Flow ends mid-scan | Handled | Analysed on what was seen |
| F7 | Flow closes and reconnects on a new port | Handled | Treated as new flow, linked by process if known |
| F8 | IPv6 `::1` flows | Handled | Same pipeline |
| **Session shapes** |  |  |  |
| S1 | Idle session, only keepalives | Skipped | Insufficient evidence |
| S2 | Fewer than min packets typed | Skipped | Exit 2 if requested |
| S3 | Bulk scp/sftp only | Handled | Classified bulk; interactive detectors skipped; L12 reports type |
| S4 | Interactive then bulk in one session | Handled | Segmented; detectors per segment |
| S5 | Port forwarding / tunnels | Degraded | Mixed traffic; L12 info; timing detectors lower confidence |
| S6 | tmux/screen with constant redraw | Degraded | Server noise measured; L4/L5 confidence lowered |
| S7 | Pasted bulk input | Handled | Burst classified, excluded from per-key stats |
| S8 | Remote command with no pty (`ssh host cmd`) | Handled | Not interactive; keystroke detectors skipped |
| S9 | X11 forwarding traffic | Handled | Verified against 10.0 behaviour; noted |
| S10 | mosh (UDP, not SSH) | Skipped | Out of scope for TCP capture; documented |
| **Capture and clock** |  |  |  |
| C1 | Packet drops in capture | Degraded | Findings marked `degraded` with drop count |
| C2 | Offload merges packets | Degraded | Warned; `doctor` shows how to disable |
| C3 | Clock step during scan | Degraded | Affected window dropped |
| C4 | Retransmits, reordering | Handled | Filtered / sorted by seq |
| C5 | Rekey in session | Handled | Window excluded |
| C6 | Truncated or corrupt pcap | Handled | Reads valid prefix; reports truncation |
| C7 | Pcap with relative-only timestamps | Handled | Gap-based detectors still valid |
| C8 | Capture on wrong hop (jump host) | Degraded | L13 reports it |
| **Config and versions** |  |  |  |
| V1 | Client older than 9.5 | Handled | L11 reported |
| V2 | Client version with the chaff flaw | Handled | L3 verified by evidence, not by version alone |
| V3 | Obfuscation interval changed (`interval:N`) | Handled | Cadence detector finds N from data |
| V4 | Process not readable (other user, no root) | Skipped | Config check skipped with reason |
| V5 | Custom/unknown SSH implementation | Degraded | Banner unknown; timing detectors run, version checks skipped |
| V6 | Compression, odd ciphers | Handled | L9 / L10 |
| **Environment** |  |  |  |
| E1 | No capture permission | Refused | Exit 3 with exact fix |
| E2 | WSL2 / VM | Degraded | Timing resolution noted; confidence capped |
| E3 | Interface missing | Refused | Exit 3 |
| E4 | Capture library missing | Refused | Exit 3, install hint |
| E5 | Ctrl-C | Handled | Partial results printed, clean shutdown |
| E6 | Low disk / memory | Degraded | Caps enforced, warned |
| **Safety** |  |  |  |
| P1 | `--iface` non-loopback without flags | Refused | Exit 4 |
| P2 | Target not owned / scope file missing | Refused | Exit 4 |
| P3 | Scope file expired | Refused | Exit 4 |
| P4 | User asks to save payloads | Refused | Option does not exist |
| **Output** |  |  |  |
| O1 | Output to a pipe / non-TTY | Handled | No colour, no animation |
| O2 | Schema version mismatch in saved reports | Handled | Migrated or read-only with warning |

## Safety and privacy

A packet sniffer is dual-use. The scanner is built so it can audit your own traffic and cannot easily be turned on other people's.

1. **Loopback by default.** Non-loopback interface or target needs `--allow-nonlocal`, a scope file (host, owner, expiry, signed off by you), and is logged. Otherwise exit 4.
2. **Metadata only.** The cleartext SSH banner and KEXINIT are read only for versions and algorithm names. Records hold only time, direction, length, sequence. Encrypted payload bytes are discarded at parse time and never stored, logged or written (see G1). There is no option to save them.
3. **No decryption, no key handling.** The tool never reads private keys, agent sockets or session keys.
4. **Passive.** `scan` and `watch` send no packets. `selftest` and `lab` only talk to their own ephemeral loopback sshd.
5. **Multi-user hosts.** Flows owned by other users are shown only as counts unless run as root with `--all-users`; their command lines are redacted by default.
6. **Redaction.** Reports omit usernames, hostnames and command lines unless `--no-redact` is passed. Findings describe the pattern, not what was typed.
7. **Least privilege.** Prefer `CAP_NET_RAW` granted to the binary over running as root; `doctor` shows how.
8. **Responsible findings.** A new flaw in an SSH implementation is reported privately to its maintainers before publication.

Capturing other people's traffic without authorisation can be illegal. The tool and its docs say so at first run.

## Testing and accuracy targets

**Ground truth comes from the lab.** `sshleak lab` generates labelled sessions across a matrix: OpenSSH versions (pre-9.5, 9.5-9.7, fixed, latest) × obfuscation (off, default, `interval:N`) × session shape (shell, tmux, bulk, password prompt, paste) × cipher × compression. Each session is labelled with which findings must fire.

**Test layers**

| Layer | What | Runs |
| --- | --- | --- |
| Unit | Banner/KEX parser, flow tracker, phase segmenter, each detector statistic | Every commit |
| Golden pcaps | Small labelled pcaps in the repo (synthetic or self-generated only) | Every commit |
| Property | Random packet streams: no crash, bounded memory, deterministic output | Every commit |
| Fuzz | Malformed banners, truncated pcaps, giant packets, bad timestamps | Nightly |
| Matrix | Full lab matrix, detectors scored against labels | Weekly / per release |
| Selftest | `sshleak selftest` end to end on a fresh machine | Per release, by you |
| Soak | Hours of live loopback, 100 flows | Per release |

**Targets (set after Phase 6 data; initial goals)**

| Metric | Target |
| --- | --- |
| Recall on High findings (L1-L4) in matrix | ≥ 95% with ≥ 60 client packets |
| False-positive rate on known-safe configs | ≤ 2% per detector |
| Inconclusive correctly declared when evidence is thin | 100% (never a guess) |
| Flow discovery by banner | 100% on matrix |
| Scan overhead on loopback (CPU) | < 5% of one core at 1,000 packets/s |
| Memory per flow | < 2 MB; total capped |
| Reproducibility | Same pcap + thresholds → byte-identical JSON |

**Regression rule:** a detector change must not lower recall or raise false positives on the stored matrix results; the diff is shown in the PR.

## Claude Code implementation plan

One phase per Claude Code session. Each ends with green tests and a git tag. The scanner ships useful at Phase 5; the rest deepens it.

**Stack:** Python 3.11+ with uv · Typer CLI · Pydantic for config and report schema · scapy or dpkt for parsing, libpcap/AF_PACKET for capture · psutil for flow-to-process · NumPy/SciPy for statistics · Rich for tables · pytest + Hypothesis · Docker only for pinned OpenSSH builds in `lab`/`selftest`.

**Repo layout:** `sshleak/` with `guard/`, `discovery/`, `capture/`, `flows/`, `phases/`, `detectors/` (one file per L-ID), `config/` (ssh_config reader), `findings/`, `output/`, `cli/`, `lab/`, `thresholds/`; plus `tests/golden/`, `docs/`.

**Rules for every session (put in ****`CLAUDE.md`****):**

- Read this plan and `CLAUDE.md` first; implement only the current phase.
- No code path may store or log payload bytes. A test greps for it.
- Every case ID gets a test named after it (e.g. `test_F5_late_join`).
- Thresholds live in `thresholds.toml`; never hard-code or loosen one to pass a test; stop and ask.
- Every detector returns `fired`, `not_fired` or `insufficient_evidence`, never a bare boolean.
- End each phase with: full tests, `sshleak doctor` clean, changelog, tag `phase-N`.

| # | Phase | Build | Done when | Stop and ask |
| --- | --- | --- | --- | --- |
| 0 | Scaffold + guard | Repo, CLI skeleton, `CLAUDE.md`, safety guard, exit codes, output schema, `doctor` | P1-P4 tests pass; `doctor` runs | — |
| 1 | Capture + flows | AF_PACKET/pcap backends, BPF, flow discovery by banner, flow tracker, `flows` command | F1-F8, C4, C6, C7 pass on golden pcaps and live loopback | Capture permission setup |
| 2 | Lab | Ephemeral sshd runner, typing generator, labelled session writer, pinned OpenSSH containers | A labelled pcap set is produced; labels verified by hand on 3 sessions | A build fails on old libs |
| 3 | Phases + banner/KEX | Segmenter, banner and KEXINIT parser, L10, L11 | S1-S4, S8, V1, V6 pass | — |
| 4 | Timing detectors | L1, L2, L5, L6 with min-evidence rules | Fire on labelled leaky sessions, stay quiet on known-safe | **Gate: you review first calibration numbers** |
| 5 | Findings + `scan` | Findings engine, score, table/JSON output, `scan`, `explain`, `selftest` | Default `sshleak scan` works end to end on loopback; selftest green | Score formula |
| 6 | Chaff + password detectors | L3, L4, L7 with bimodality / echo-gap tests | V2 test: a flaw build fires L3, a fixed build does not | Fixed-version confirmation |
| 7 | Config check | Process mapping, ssh_config reader, L2 cross-check, V3-V5 | V4 skipped cleanly; L2 agrees with `ssh -G` | Root/capability design |
| 8 | Degradation + environment | C1-C3, C5, C8, E1-E6, S5-S7 handling, confidence capping | All environment/degraded cases produce their defined outcome | — |
| 9 | Calibration + matrix | Full lab matrix run, threshold fitting, targets table filled, regression harness | Targets met or documented as not met | Threshold acceptance |
| 10 | `watch` + `ci` + perf | Streaming mode, `ci --fail-on`, SARIF, soak test, performance tests | Soak passes; overhead target met | — |
| 11 | Hardening + release | Fuzz, docs, packaging, schema migration (O2), signed release | Fresh-machine install from docs works | **Gate: before any public release** |

**Prompt template per session:**

```
Read CLAUDE.md and docs/plan.md. Implement Phase N only: .
Write tests for these case IDs: . Done when: .
Stop and ask me if: , or if any threshold would need loosening.
Finish with the test run, doctor output, changelog and tag phase-N.
```

## Your instructions

**Before Phase 0**

- [ ] Ubuntu on WSL2 is enough for building and testing; results there are labelled "degraded" (case E2). Use native Linux for numbers you publish.
- [ ] Install Docker Engine (steps from earlier), plus `tcpdump`, `iproute2`, `ethtool`, `libpcap-dev`, Wireshark.
- [ ] Install Claude Code and log in; create a private GitHub repo; save this doc as `docs/plan.md`.
- [ ] Install OpenSSH server locally and confirm you can `ssh 127.0.0.1` with key auth; this is your live test target.
- [ ] Grant capture rights safely: after Phase 1 Claude Code will tell you the exact `setcap` command; read it before running.
- [ ] Search GitHub and PyPI for existing SSH timing auditors or detectors by name; note them in `docs/prior-art.md`.
- [ ] Find the OpenSSH release that fixed the 9.5-9.7 chaff flaw and add it to the plan.

**Each phase**

1. Fresh Claude Code session; paste the prompt template filled from the phase row.
2. Read every privileged command before approving it (capture, Docker, namespaces).
3. Read the diff and run the tests yourself once.
4. If Claude Code stops and asks, decide and record it in `docs/decisions.md`.
5. Merge, tag, tick the checklist.

**Decisions only you make**

| When | Decision |
| --- | --- |
| Phase 4 gate | Do the first calibration numbers look sane? Open one capture in Wireshark and check the 20 ms cadence by eye |
| Phase 5 | How the 0-100 score is computed and what it should mean |
| Phase 6 | Which OpenSSH version counts as fixed |
| Phase 9 | Threshold acceptance: recall vs false positives trade-off |
| Phase 11 gate | Public release? License? Does a finding need private disclosure first? |

**Never**

- Run the scanner on a network or host you do not own or have written permission to test.
- Commit pcaps made from real sessions, keys, or datasets to the repo (golden pcaps must be synthetic or self-generated test traffic only).
- Accept a change that loosens a threshold or control to get a green run.

## Objectives, risks, open questions

**Objectives**

- [ ] D1 `sshleak scan` on loopback works with no arguments and exits with a defined code
- [ ] D2 Passive only: payload never stored; test proves it
- [ ] D3 Flows found by banner, including late-join and many concurrent flows
- [ ] D4 L1-L13 implemented, each with minimum-evidence rule and fix text
- [ ] D5 Every case in the catalogue has a test and a defined outcome
- [ ] D6 Thresholds fitted from the lab matrix; targets table met or honestly reported
- [ ] D7 `selftest` passes on a fresh machine
- [ ] D8 Same pcap + thresholds → identical JSON
- [ ] D9 `watch`, `ci`, SARIF output, schema versioning
- [ ] D10 Safety guard refuses non-owned targets by default
- [ ] D11 Plugin interfaces for detectors, capture backends, formatters

**Risks**

| Risk | Likelihood | Fallback |
| --- | --- | --- |
| Obfuscation removes most signal, so few detectors can fire from metadata alone | High | Report L2/L3/L8 (is it working, is it flawed, what it costs); keep L1/L5 for unprotected setups |
| Password-entry pattern (L4) is noisy on real shells | Medium | Ship as medium-confidence; require echo-gap + burst; allow `--only` and tuning |
| Thresholds overfit to the lab | Medium | Hold-out configs; second machine; report limits |
| Capture rights are awkward on WSL2 | Medium | Develop against pcap files; use `lo` capture inside the VM; native Linux for final |
| Versions with the flaw are hard to build | Medium | Containers with old base images; fall back to documented pcaps |
| Scope creep into a full IDS | Medium | Hold the finding list L1-L13; new detectors need a case and a test first |

**Open questions**

- Which OpenSSH release fixed the 9.5-9.7 chaff flaw (confirm from release notes).
- Prior art: any existing defender-side SSH timing detector (search before claiming novelty).
- Exact echo-window and burst parameters for L4 (come from calibration, not guessed).
- Whether `--all-users` is worth shipping or should be dropped for safety.

## Sources

- [OpenSSH 9.5 release notes](https://www.openssh.com/txt/release-9.5)
- [ObscureKeystrokeTiming overview](https://blog.melashri.net/micro/obscure-keystroke-timing/)
- [libssh tracking issue on ping and obfuscation](https://gitlab.com/libssh/libssh-mirror/-/issues/241)
- [Chaff flaw write-up](https://habr.com/ru/articles/844368)
