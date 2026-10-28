"""Labelled synthetic scenarios: one per catalogue case, with expected detector outcomes.

Expectations use detector statuses: fired, not_fired, skipped, insufficient_evidence.
Detectors not listed for a flow are not asserted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sshleak.lab.synth import (
    Bulk, Exec, Forward, Idle, Obfuscation, Password, Paste, Redraw, SessionSpec, Type,
    frames_for, kex_profile, merge, typing_script, write_pcap, write_pcapng,
)

F, NF, SK, INS = "fired", "not_fired", "skipped", "insufficient_evidence"


def typing(n: int, seed: int, lo: int = 6, hi: int = 14) -> list:
    return typing_script(n, seed, lo, hi)


@dataclass
class Scenario:
    name: str
    cases: tuple[str, ...]
    description: str
    sessions: list[SessionSpec]
    expect: dict[int, dict[str, str]] = field(default_factory=dict)  # session index -> detector -> status
    fmt: str = "pcap"
    if_drops: int | None = None
    truncate_to: float | None = None  # keep this fraction of the file
    relative: bool = False
    clock_step_s: float | None = None  # shift timestamps back by this much halfway through
    expect_flows: int | None = None


def _base(name: str, **kw) -> SessionSpec:
    return SessionSpec(name=name, **kw)


UNPROTECTED = {"L4": NF, "L1": F, "L2": SK, "L3": SK, "L5": F, "L6": F, "L7": SK, "L8": SK, "L9": NF, "L11": F, "L12": F, "L13": SK}
FIXED = {"L4": NF, "L1": NF, "L2": NF, "L3": NF, "L5": NF, "L7": NF, "L8": NF, "L9": NF, "L10": NF, "L11": NF, "L12": F}


def catalogue(variant: int = 0) -> list[Scenario]:
    """All scenarios; `variant` re-seeds every session (used by the calibration matrix)."""
    off = 7919 * variant

    def T(n: int, seed: int, **kw) -> list:
        return typing(n, seed + off, **kw)

    def B(name: str, **kw) -> SessionSpec:
        kw["seed"] = kw.get("seed", 1) + off
        return _base(name, **kw)

    S: list[Scenario] = []
    S.append(Scenario("unprotected", ("V1", "L1", "L5", "L6", "L11"), "OpenSSH 9.4 client, no obfuscation",
                      [B("unprotected", client_sw="OpenSSH_9.4", server_sw="OpenSSH_9.4",
                             client_kex=kex_profile("client", strict=False), server_kex=kex_profile("server", strict=False),
                             script=T(12, 1), seed=1)],
                      {0: UNPROTECTED | {"L10": F}}))
    S.append(Scenario("fixed", ("L1", "L3"), "OpenSSH 9.8 fixed obfuscation at 20 ms",
                      [B("fixed", client_sw="OpenSSH_9.8", server_sw="OpenSSH_9.8",
                             obfuscation=Obfuscation(20), script=T(12, 2), seed=2)],
                      {0: FIXED}))
    S.append(Scenario("flawed", ("V2", "L3"), "OpenSSH 9.6 client with the chaff flaw",
                      [B("flawed", client_sw="OpenSSH_9.6", server_sw="OpenSSH_9.6",
                             obfuscation=Obfuscation(20, flawed=True), script=T(12, 3), seed=3)],
                      {0: {"L1": NF, "L2": NF, "L3": F, "L4": NF, "L5": F, "L11": NF}}))
    S.append(Scenario("default_off", ("L2",), "OpenSSH 10.0 client with obfuscation off",
                      [B("default_off", client_sw="OpenSSH_10.0", server_sw="OpenSSH_10.0",
                             script=T(12, 4), seed=4)],
                      {0: {"L1": F, "L2": F, "L3": SK, "L11": NF}}))
    S.append(Scenario("interval80", ("V3", "L8"), "interval:80 set on a 9.8 client",
                      [B("interval80", obfuscation=Obfuscation(80), script=T(12, 5), seed=5)],
                      {0: {"L1": NF, "L2": NF, "L3": NF, "L8": F}}))
    S.append(Scenario("password_plain", ("L4",), "echo-off prompt on a server without simulated echo",
                      [B("password_plain", client_sw="OpenSSH_9.4", server_sw="dropbear_2022.83",
                             simulated_echo=False,
                             script=T(6, 6) + [Password(10)] + T(6, 7) + [Password(12)], seed=6)],
                      {0: {"L4": F, "L1": F}}))
    S.append(Scenario("password_openssh", ("L4",), "echo-off prompt, OpenSSH simulated echo (faster than real echo)",
                      [B("password_openssh", client_sw="OpenSSH_9.4", server_sw="OpenSSH_9.4",
                             script=T(6, 8) + [Password(10)] + T(6, 9) + [Password(12)], seed=7)],
                      {0: {"L4": F}}))
    S.append(Scenario("no_password", ("L4",), "plain typing: no echo-off pattern",
                      [B("no_password", client_sw="OpenSSH_9.4", server_sw="OpenSSH_9.4",
                             script=T(14, 10), seed=8)],
                      {0: {"L4": NF}}))
    S.append(Scenario("compression", ("V6", "L9"), "client asks for zlib (-C)",
                      [B("compression", client_kex=kex_profile("client", compression=("zlib@openssh.com", "zlib", "none")),
                             obfuscation=Obfuscation(20), script=T(10, 11), seed=9)],
                      {0: {"L9": F, "L10": NF}}))
    S.append(Scenario("weak_cipher", ("V6", "L10"), "aes128-cbc with hmac-sha1-96",
                      [B("weak_cipher",
                             client_kex=kex_profile("client", ciphers=("aes128-cbc", "aes128-ctr"), macs=("hmac-sha1-96", "hmac-sha2-256")),
                             server_kex=kex_profile("server", ciphers=("aes128-ctr", "aes128-cbc"), macs=("hmac-sha2-256", "hmac-sha1-96")),
                             obfuscation=Obfuscation(20), script=T(10, 12), seed=10)],
                      {0: {"L10": F, "L9": NF}}))
    S.append(Scenario("idle", ("S1",), "idle session with keepalives only",
                      [B("idle", script=[Idle(60, keepalive_s=15)], seed=11)],
                      {0: {"L1": SK, "L2": SK, "L3": SK, "L4": SK, "L5": SK}}))
    S.append(Scenario("few_packets", ("S2",), "fewer keystrokes than min_packets",
                      [B("few_packets", client_sw="OpenSSH_9.4", server_sw="OpenSSH_9.4", script=T(2, 13), seed=12)],
                      {0: {"L1": INS, "L5": INS}}))
    S.append(Scenario("scp", ("S3", "L12"), "bulk scp download only",
                      [B("scp", script=[Bulk(8_000_000, "scp")], seed=13)],
                      {0: {"L1": SK, "L3": SK, "L12": F}}))
    S.append(Scenario("sftp", ("S3", "L12"), "bulk sftp download only",
                      [B("sftp", script=[Bulk(8_000_000, "sftp")], seed=14)],
                      {0: {"L1": SK, "L12": F}}))
    S.append(Scenario("interactive_then_bulk", ("S4",), "typing then a transfer in one session",
                      [B("interactive_then_bulk", client_sw="OpenSSH_9.4", server_sw="OpenSSH_9.4",
                             script=T(12, 15) + [Bulk(6_000_000, "scp")], seed=15)],
                      {0: {"L1": F, "L5": F}}))
    S.append(Scenario("forward", ("S5",), "port-forward traffic", [B("forward", script=[Forward(30)], seed=16)],
                      {0: {"L12": F, "L1": SK}}))
    S.append(Scenario("tmux", ("S6",), "typing under constant redraw",
                      [B("tmux", client_sw="OpenSSH_9.4", server_sw="OpenSSH_9.4",
                             script=[*T(4, 17), Redraw(25)] + T(10, 18), seed=17)],
                      {0: {"L1": F}}))
    S.append(Scenario("paste", ("S7",), "typing with pasted blocks",
                      [B("paste", client_sw="OpenSSH_9.4", server_sw="OpenSSH_9.4",
                             script=T(5, 19) + [Paste(400)] + T(6, 20) + [Paste(900)] + T(4, 21), seed=18)],
                      {0: {"L1": F}}))
    S.append(Scenario("exec", ("S8",), "remote command without a pty",
                      [B("exec", script=[Exec(3000)], seed=19)],
                      {0: {"L1": SK, "L4": SK, "L5": SK}}))
    S.append(Scenario("late_join", ("F5",), "scan started after connect (no banner)",
                      [B("late_join", client_sw="OpenSSH_9.4", late_join=True, script=T(12, 22), seed=20)],
                      {0: {"L1": F, "L9": SK, "L10": SK, "L11": SK}}))
    S.append(Scenario("ipv6", ("F8",), "IPv6 loopback",
                      [B("ipv6", client_ip="::1", server_ip="::1", client_sw="OpenSSH_9.4", server_sw="OpenSSH_9.4",
                             script=T(12, 23), seed=21)],
                      {0: {"L1": F, "L11": F}}))
    S.append(Scenario("nonstd_port", ("F2",), "SSH on port 2222",
                      [B("nonstd_port", server_port=2222, client_sw="OpenSSH_9.4", script=T(12, 24), seed=22)],
                      {0: {"L1": F, "L11": F}}, expect_flows=1))
    S.append(Scenario("non_ssh_22", ("F3",), "something else on port 22",
                      [B("non_ssh_22", non_ssh_banner=b"HTTP/1.0 200 OK\r\n\r\n", seed=23)],
                      {}, expect_flows=0))
    S.append(Scenario("many_flows", ("F4",), "120 concurrent short flows",
                      [B(f"many_{i}", client_port=40000 + i, client_sw="OpenSSH_9.4", script=T(1, 100 + i),
                             start_s=i * 0.01, seed=100 + i) for i in range(120)],
                      {}, expect_flows=120))
    S.append(Scenario("flow_ends", ("F6",), "flow closes mid-capture; another continues",
                      [B("ends", client_sw="OpenSSH_9.4", script=T(10, 25), seed=24),
                       B("continues", client_port=50023, client_sw="OpenSSH_9.4", script=T(14, 26), seed=25,
                             close=False)],
                      {0: {"L1": F}, 1: {"L1": F}}, expect_flows=2))
    S.append(Scenario("reconnect", ("F7",), "client reconnects on a new port",
                      [B("first", client_sw="OpenSSH_9.4", script=T(6, 27), seed=26),
                       B("second", client_port=50099, client_sw="OpenSSH_9.4", script=T(6, 28), start_s=30, seed=27)],
                      {}, expect_flows=2))
    S.append(Scenario("retrans_reorder", ("C4",), "retransmits and reordering",
                      [B("retrans", client_sw="OpenSSH_9.4", script=T(12, 29), retransmit_p=0.05,
                             reorder_p=0.02, seed=28)],
                      {0: {"L1": F, "L11": F}}))
    S.append(Scenario("clock_step", ("C3",), "wall clock steps back mid-capture",
                      [B("clock_step", client_sw="OpenSSH_9.4", script=T(16, 30), seed=29)],
                      {0: {"L1": F}}, clock_step_s=5.0))
    S.append(Scenario("truncated", ("C6",), "capture file cut short",
                      [B("truncated", client_sw="OpenSSH_9.4", script=T(16, 31), seed=30)],
                      {}, truncate_to=0.7))
    S.append(Scenario("relative_ts", ("C7",), "timestamps relative to capture start",
                      [B("relative", client_sw="OpenSSH_9.4", script=T(12, 32), seed=31)],
                      {0: {"L1": F}}, relative=True))
    S.append(Scenario("drops", ("C1",), "pcapng reporting kernel drops",
                      [B("drops", client_sw="OpenSSH_9.4", script=T(12, 33), seed=32)],
                      {0: {"L1": F}}, fmt="pcapng", if_drops=37))
    S.append(Scenario("unknown_impl", ("V5",), "non-OpenSSH client banner",
                      [B("unknown_impl", client_sw="libssh_0.10.6", server_sw="OpenSSH_9.8", script=T(12, 34), seed=33)],
                      {0: {"L1": F, "L11": SK, "L2": SK}}))
    return S


def by_name(name: str) -> Scenario:
    for s in catalogue():
        if s.name == name:
            return s
    raise KeyError(name)


def write_scenario(sc: Scenario, path: Path, *, marker: bytes | None = None) -> list:
    """Write the scenario's capture to `path`; return per-session labels."""
    streams, labels = [], []
    base_ns = 0 if sc.relative else 1_793_000_000_000_000_000
    for spec in sc.sessions:
        frames, lab = frames_for(spec, marker=marker, base_ns=base_ns + 1_000_000)
        streams.append(frames)
        labels.append(lab)
    frames = merge(*streams)
    if sc.clock_step_s and frames:
        mid = len(frames) // 2
        shift = int(sc.clock_step_s * 1e9)
        for f in frames[mid:]:
            f.ts_ns -= shift
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        if sc.fmt == "pcapng":
            write_pcapng(fh, frames, if_drops=sc.if_drops)
        else:
            write_pcap(fh, frames)
    if sc.truncate_to:
        data = path.read_bytes()
        path.write_bytes(data[: int(len(data) * sc.truncate_to)])
    return labels
