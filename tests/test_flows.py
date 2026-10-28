"""Banner/KEXINIT parsing, negotiation, flow tracking and discovery cases (F1-F8, C4)."""

from __future__ import annotations

import io

import pytest

from sshleak.capture.decode import ACK, PSH, SYN, Packet
from sshleak.flows.handshake import SideHandshake
from sshleak.flows.tracker import FlowTracker
from sshleak.kex import KexInit, KexParseError, build_kexinit_payload, negotiate, parse_kexinit
from sshleak.lab.synth import frame_clear, kex_profile
from sshleak.versions import parse_banner, parse_software
from tests.conftest import run_cli, statuses


def test_banner_parsing():
    b = parse_banner(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4")
    assert b.software == "OpenSSH_9.6p1" and b.comments == "Ubuntu-3ubuntu13.4"
    assert parse_banner(b"SSH-1.5-old") is None
    assert parse_banner(b"HTTP/1.1 200 OK") is None
    assert parse_banner(b"SSH-2.0-" + b"x" * 300) is None
    assert parse_banner(b"SSH-2.0-a\x01b") is None


@pytest.mark.parametrize("sw,impl,ver", [
    ("OpenSSH_9.6p1", "openssh", (9, 6)), ("OpenSSH_10.6", "openssh", (10, 6)),
    ("OpenSSH_for_Windows_9.5", "openssh", (9, 5)), ("dropbear_2022.83", "dropbear", (2022, 83)),
    ("libssh_0.10.6", "libssh", (0, 10)), ("PuTTY_Release_0.80", "putty", None), ("Go", "go", None),
    ("Weird_1", "other", None),
])
def test_software_versions(sw, impl, ver):
    s = parse_software(sw)
    assert (s.impl, s.version) == (impl, ver)


def test_kexinit_roundtrip_and_negotiation():
    c = kex_profile("client", compression=("zlib@openssh.com", "none"))
    s = kex_profile("server")
    assert parse_kexinit(build_kexinit_payload(c)) == c
    n = negotiate(c, s)
    assert n.kex == "mlkem768x25519-sha256"
    assert n.enc_c2s == "chacha20-poly1305@openssh.com" and n.mac_c2s == "<implicit>"
    assert n.comp_c2s == "zlib@openssh.com" and n.strict_kex
    assert c.role_hint == "client" and s.role_hint == "server"


def test_kexinit_rejects_garbage():
    with pytest.raises(KexParseError):
        parse_kexinit(b"\x14" + b"\x00" * 16 + b"\xff\xff\xff\xff")
    with pytest.raises(KexParseError):
        parse_kexinit(b"\x15")


def _feed(hs: SideHandshake, data: bytes, seq: int = 1000, snap: int | None = None):
    view = memoryview(data if snap is None else data[:snap])
    hs.feed(seq, len(data), view)
    return seq + len(data)


def test_handshake_parses_split_segments_and_stops_at_newkeys():
    k = kex_profile("server")
    stream = b"SSH-2.0-OpenSSH_9.8\r\n" + frame_clear(build_kexinit_payload(k)) + frame_clear(b"\x15") + b"ENCRYPTED" * 50
    hs = SideHandshake(is_client=False)
    seq = 1
    for i in range(0, len(stream), 7):
        seq = _feed(hs, stream[i:i + 7], seq)
    assert hs.banner.software == "OpenSSH_9.8" and hs.kexinit == k and hs.state == "encrypted"
    assert len(hs._buf) == 0  # nothing held after NEWKEYS


def test_handshake_server_pre_banner_lines_allowed_client_not():
    hs = SideHandshake(is_client=False)
    _feed(hs, b"Welcome\r\nSSH-2.0-OpenSSH_9.8\r\n")
    assert hs.banner is not None
    hc = SideHandshake(is_client=True)
    _feed(hc, b"GET / HTTP/1.0\r\n\r\n")
    assert hc.state == "failed" and hc.failure == "not ssh"


def test_handshake_snaplen_short_fails_cleanly():
    k = kex_profile("client")
    stream = b"SSH-2.0-x\r\n" + frame_clear(build_kexinit_payload(k))
    hs = SideHandshake(is_client=True)
    _feed(hs, stream, snap=20)
    assert hs.state == "failed" and "snaplen" in hs.failure and len(hs._buf) == 0


def test_handshake_late_join_never_buffers():
    hs = SideHandshake()
    hs.feed(5, 36, memoryview(b"\x8a" * 36), first_data_late=True)
    assert hs.state == "failed" and hs.failure == "late-join" and len(hs._buf) == 0


def _pkt(ts, src, sport, dst, dport, seq, flags, n):
    return Packet(ts, src, dst, sport, dport, seq, 0, flags, n, 4)


def test_C4_retransmits_dropped_reorder_kept():
    tr = FlowTracker()
    mv = memoryview(b"")
    tr.add(_pkt(1, "10.0.0.1", 5000, "10.0.0.2", 22, 99, SYN, 0), mv)
    tr.add(_pkt(2, "10.0.0.1", 5000, "10.0.0.2", 22, 100, PSH | ACK, 36), memoryview(b"SSH-2.0-x\r\n"))
    tr.add(_pkt(3, "10.0.0.1", 5000, "10.0.0.2", 22, 172, PSH | ACK, 36), mv)  # skips 136..171 (hole)
    tr.add(_pkt(4, "10.0.0.1", 5000, "10.0.0.2", 22, 136, PSH | ACK, 36), mv)  # fills the hole: reordered
    tr.add(_pkt(5, "10.0.0.1", 5000, "10.0.0.2", 22, 136, PSH | ACK, 36), mv)  # duplicate: retransmit
    f = tr.all_flows()[0]
    assert f.retransmits == 1 and f.reordered == 1 and f.data_packets == 3


def test_F4_flow_cap_evicts():
    from sshleak.flows.tracker import Limits

    tr = FlowTracker(Limits(max_flows=10))
    for i in range(25):
        tr.add(_pkt(i, "127.0.0.1", 40000 + i, "127.0.0.1", 22, 1, PSH | ACK, 36), memoryview(b"\x00" * 36))
    assert len(tr.flows) == 10 and tr.stats.evicted == 15


def test_F1_no_flows(tmp_path):
    from sshleak.lab.synth import write_pcap

    p = tmp_path / "empty.pcap"
    with open(p, "wb") as fh:
        write_pcap(fh, [])
    res = run_cli("scan", "--pcap", p)
    assert res.code == 0 and "No SSH flows found" in res.out


def test_F2_nonstandard_port(analysed):
    rep, _ = analysed("nonstd_port")
    assert len(rep.flows) == 1 and rep.flows[0].server.endswith(":2222")
    assert rep.flows[0].identified_by == "banner"


def test_F3_non_ssh_on_port_22_ignored(analysed):
    rep, _ = analysed("non_ssh_22")
    assert rep.flows == [] and rep.summary.flows_not_ssh == 1


def test_F4_many_flows(analysed):
    rep, _ = analysed("many_flows")
    assert len(rep.flows) == 120 and len({f.id for f in rep.flows}) == 120


def test_F4_flow_filter(scenario_pcap):
    res = run_cli("scan", "--pcap", scenario_pcap("many_flows"), "--flow", "f7", "--format", "json")
    import json

    data = json.loads(res.out)
    assert [f["id"] for f in data["flows"]] == ["f7"]


def test_F5_late_join(analysed):
    rep, _ = analysed("late_join")
    flow = rep.flows[0]
    assert flow.late_join and flow.identified_by == "shape"
    st = statuses(rep)
    assert st["L10"] == st["L11"] == st["L9"] == "skipped" and st["L1"] == "fired"
    assert any("late-join" in d for d in flow.degraded)


def test_F6_flow_ends_mid_scan(analysed):
    rep, _ = analysed("flow_ends")
    assert len(rep.flows) == 2
    assert all(statuses(rep, i)["L1"] == "fired" for i in range(2))


def test_F7_reconnect_new_flow(analysed):
    rep, _ = analysed("reconnect")
    assert len(rep.flows) == 2 and rep.flows[0].client != rep.flows[1].client


def test_F7_linked_by_process():
    from sshleak.discovery.sockets import ProcInfo
    from sshleak.pipeline import FlowAnalysis, Pipeline

    class Ctx:
        def __init__(self, pid):
            self.meta = type("M", (), {"client_proc": ProcInfo(pid, "ssh", 0)})()

    class Model:
        def __init__(self, i):
            self.id, self.linked_to = i, []

    fas = [FlowAnalysis(None, Model("f1"), Ctx(10)), FlowAnalysis(None, Model("f2"), Ctx(10)),
           FlowAnalysis(None, Model("f3"), Ctx(11))]
    Pipeline._link_reconnects(fas)
    assert fas[1].model.linked_to == ["f1"] and fas[2].model.linked_to == []


def test_F8_ipv6(analysed):
    rep, _ = analysed("ipv6")
    assert rep.flows[0].ip_version == 6 and rep.flows[0].client.startswith("[::1]")
    assert statuses(rep)["L1"] == "fired"


def test_C4_retransmit_scenario(analysed):
    rep, _ = analysed("retrans_reorder")
    f = rep.flows[0]
    assert f.retransmits > 0 and f.reordered > 0
    assert statuses(rep)["L1"] == "fired"
