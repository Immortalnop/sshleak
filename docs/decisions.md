# Decisions

Decisions only the owner makes, plus implementation decisions they rest on. Newest first.

| Date | Decision | Detail |
| --- | --- | --- |
| 2026-10-28 | Enter detection rule changed (L5/L6) | Real lab traffic showed short command output arrives as 44-84 B packets, below the old "3 units" rule. Output = a server packet larger than one echo unit that is not an echo+pong pair (2 units). Threshold key `L5.enter_output_min_units = 1.0`. |
| 2026-10-28 | L4 latency statistic changed (pending threshold acceptance) | Real 9.4p1 sessions: simulated echo for echo-off keys arrives faster than real echo (median 312 us vs 552 us). L4 now compares the median of consecutive keystroke latencies with the session median. `L4.latency_ratio_max` stays at the provisional 0.5 until you accept a calibrated value (see docs/calibration.md). |
| 2026-10-28 | Thresholds: provisional | `calibrated = false`. Phase 4 gate and Phase 9 threshold acceptance are open; see docs/calibration.md for the matrix numbers and proposals. |
| 2026-10-28 | CLI dependency pin | Typer pinned below 0.16 (with click 8.x) so usage errors map to exit 3 through click's public API. |
| 2026-10-27 | Score formula (Phase 5) | 100 = no leaks. Per flow: 100 - sum(weight x confidence) over fired findings, weights High 30, Medium 12, Info 2 (`[score]` in thresholds.toml), floored at 0. Overall score = worst flow. Skipped or insufficient checks do not change the score; the report says it is partial. |
| 2026-10-27 | Lab builds (Phase 2) | Vanilla OpenSSH portable 9.4p1, 9.6p1, 9.8p1, 10.6p1 built from openbsd.org tarballs, SHA256 pinned and checked against each release's notes. sshd, client and tcpdump run inside one container with `--network none` and a minimal capability set. |
| 2026-10-27 | Git | `git init` only; no commits or tags unless asked. |
| 2026-10-27 | Fixed OpenSSH version (Phase 6) | Upstream fix for the chaff flaw is OpenSSH 9.8 (2024-07-01), CVE-2024-39894, commit 146c420d. Distributions backported it (Ubuntu noble 1:9.6p1-3ubuntu13.4), so L3 is decided by evidence, never by version. |
| 2026-10-27 | G12 packet parser | Own pcap/pcapng parser and decoder; dpkt only as a test cross-check; no scapy. |
| 2026-10-27 | G11 capture privilege (Phase 7 root/capability design) | Default backend: tcpdump subprocess with `setcap cap_net_raw,cap_net_admin=eip` on tcpdump; sudo also works. Never setcap the Python interpreter. Native AF_PACKET later as a plugin. |
| 2026-10-27 | G3 loopback duplicates | Drop PACKET_OUTGOING copies on loopback (SLL/SLL2); direction from the 4-tuple. |
| 2026-10-27 | G2 late-join fallback | Only at scan time; nothing collected before. Flows without a banner are identified by owning process, then by size shape; marked late-join with lower confidence. |
| 2026-10-27 | G1 payload rule relaxed | One capture with snaplen 4096 B. Banner and KEXINIT are parsed for versions and algorithm names only; encrypted payload may pass through memory but is discarded at parse time and never stored, logged or written. |

## Open (yours to decide)
- Phase 4 gate: do the first calibration numbers look sane? (docs/calibration.md; open a capture in Wireshark and check the 20 ms cadence.)
- Phase 9: accept or reject the proposed thresholds (`L4.latency_ratio_max` and others).
- Whether `--all-users` should ship (implemented, root only) or be removed.
- Phase 11 gate: public release, licence, private disclosure.
- Proposed gaps G4-G10, G13 (add-ons).
