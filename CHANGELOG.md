# Changelog

## 0.1.0 (unreleased)

Phases 0-11 of docs/plan.md implemented, with adopted gaps G1, G2, G3, G11, G12. Proposed gaps
G4-G10 and G13 are not included (add-ons).

- Phase 0: CLI skeleton, exit codes 0-5, safety guard (P1-P4, scope files, audit log), report schema
  1.0, `doctor`.
- Phase 1: own pcap/pcapng reader and decoder (Ethernet, VLAN, SLL, SLL2, NULL/LOOP, raw IP);
  tcpdump live backend (snaplen 4096); flow tracker with retransmit/reorder handling and caps; banner
  discovery with late-join fallback (process, then size shape); `flows`.
- Phase 2: synthetic labelled generator; Docker lab with vanilla OpenSSH 9.4p1/9.6p1/9.8p1/10.6p1
  (SHA256-pinned), pty typing driver, labels verified with the client's own `ssh -G`.
- Phase 3: phase segmenter (handshake, auth, interactive, bulk, mixed, idle, rekey); KEXINIT
  negotiation; L10, L11.
- Phase 4: cadence statistic; L1, L2, L5, L6.
- Phase 5: findings engine (Holm correction, confidence caps, score), table/JSON/JSONL output, `scan`,
  `explain`, `selftest`.
- Phase 6: L3 (two-unit ticks, CVE-2024-39894), L4 (echo-off runs; simulated-echo latency), L7.
- Phase 7: `--config-check` (ssh -G on the client process, own user only), L2 cross-check, V3-V5.
- Phase 8: degradation handling C1-C3, C5, C8, E1-E6, S5-S7 with confidence caps.
- Phase 9: `lab matrix` and `lab calibrate` (proposals only; thresholds remain provisional).
- Phase 10: `watch`, `ci --fail-on`, SARIF 2.1.0, performance and soak tests.
- Phase 11: Hypothesis fuzzing, saved-report migration (O2), packaging; docs.
