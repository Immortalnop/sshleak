# Prior art

Searched 2026-10-27 (web search; GitHub and PyPI by name). A fuller GitHub/PyPI search is still on
the owner's checklist before any claim of novelty.

| Work | What it is | Relation to sshleak |
| --- | --- | --- |
| [Song, Wagner, Tian 2001](https://people.eecs.berkeley.edu/~dawnsong/papers/ssh-timing.pdf) | Timing analysis of keystrokes in SSH; Herbivore attack | The attack class L1/L5/L6 detect exposure to |
| [OpenSSH 9.5 release notes](https://www.openssh.org/txt/release-9.5) | ObscureKeystrokeTiming (20 ms default), ping@openssh.com | The defence L1-L3, L7, L8 check |
| [OpenSSH 9.8 release notes](https://www.openssh.org/txt/release-9.8) | Fix for the 9.5-9.7 chaff logic error (CVE-2024-39894) | What L3 detects |
| [eieio: ssh sends 100 packets per keystroke](https://eieio.games/blog/ssh-sends-100-packets-per-keystroke/) | Measured chaff: 36 B PING/PONG, cost | Input to L8 and the synthetic model |
| [pentestmonkey/timing-attack-checker](https://github.com/pentestmonkey/timing-attack-checker) | Times SSH logins for user enumeration | Login timing, not keystroke timing; no pcap analysis |
| Chaosreader / sshkeydata workflows | Offline pcap tooling | Session recovery oriented; no defender-side leak checks |
| [libssh issue: ping and obfuscation](https://gitlab.com/libssh/libssh-mirror/-/work_items/241) | Tracking support in libssh | Non-OpenSSH implementations lack the feature (V5) |

No defender-side tool that passively checks whether a live SSH session leaks keystroke timing was
found.
