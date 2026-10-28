"""Capture parsing: pcap/pcapng variants, link types, truncation, drops, loopback dedup (G3)."""

from __future__ import annotations

import io
import struct

import pytest

from sshleak.capture.decode import ACK, PSH, DecodeStats, decode
from sshleak.capture.pcapfile import CaptureFormatError, CaptureReader, RawFrame
from sshleak.lab.synth import SessionSpec, Type, _frame, frames_for, write_pcap, write_pcapng


def _session_frames(**kw):
    frames, _ = frames_for(SessionSpec(name="t", script=[Type(5)], seed=3, **kw))
    return frames


def _read(data: bytes):
    rd = CaptureReader(io.BytesIO(data))
    return list(rd), rd.stats


def test_pcap_nanosecond_roundtrip():
    frames = _session_frames()
    buf = io.BytesIO()
    write_pcap(buf, frames)
    got, st = _read(buf.getvalue())
    assert st.format == "pcap" and st.ts_resolution_ns == 1 and not st.truncated
    assert [g.ts_ns for g in got] == [f.ts_ns for f in frames]
    assert [g.orig_len for g in got] == [f.orig_len for f in frames]


@pytest.mark.parametrize("endian,magic,mult", [("<", 0xA1B2C3D4, 1000), (">", 0xA1B2C3D4, 1000), (">", 0xA1B23C4D, 1)])
def test_pcap_endianness_and_microseconds(endian, magic, mult):
    data = bytes(range(60))
    hdr = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack(endian + "IIII", 100, 250, len(data), len(data)) + data
    got, st = _read(hdr + rec)
    assert got[0].ts_ns == 100 * 10**9 + 250 * mult
    assert st.ts_resolution_ns == mult


def test_pcapng_roundtrip_with_drops():
    frames = _session_frames()
    buf = io.BytesIO()
    write_pcapng(buf, frames, if_drops=12)
    got, st = _read(buf.getvalue())
    assert st.format == "pcapng" and st.if_drops == 12 and st.ts_resolution_ns == 1
    assert [g.ts_ns for g in got] == [f.ts_ns for f in frames]


def test_pcapng_microsecond_default_resolution():
    def block(btype, body):
        body += b"\x00" * ((4 - len(body) % 4) % 4)
        return struct.pack("<II", btype, 12 + len(body)) + body + struct.pack("<I", 12 + len(body))

    data = bytes(64)
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack("<HHI", 1, 0, 65535))
    out += block(6, struct.pack("<IIIII", 0, 0, 1_500_000, len(data), len(data)) + data)
    got, st = _read(out)
    assert got[0].ts_ns == 1_500_000_000
    assert st.ts_resolution_ns == 1000


def test_not_a_capture():
    with pytest.raises(CaptureFormatError):
        _read(b"hello world, not a pcap")


@pytest.mark.parametrize("cut", [10, 30, 1000, -7])
def test_C6_truncated_input_keeps_valid_prefix(cut):
    frames = _session_frames()
    buf = io.BytesIO()
    write_pcap(buf, frames)
    data = buf.getvalue()[:cut]
    got, st = _read(data)
    assert st.truncated
    assert len(got) <= len(frames)
    for g, f in zip(got, frames):
        assert g.ts_ns == f.ts_ns


def test_crosscheck_with_dpkt():
    dpkt = pytest.importorskip("dpkt")
    frames = _session_frames(client_ip="::1", server_ip="::1")
    buf = io.BytesIO()
    write_pcap(buf, frames)
    ours = []
    stats = DecodeStats()
    for raw in CaptureReader(io.BytesIO(buf.getvalue())):
        d = decode(raw, stats)
        ours.append((d[0].sport, d[0].dport, d[0].seq, d[0].payload_len))
    theirs = []
    for _ts, data in dpkt.pcap.Reader(io.BytesIO(buf.getvalue())):
        eth = dpkt.ethernet.Ethernet(data)
        tcp = eth.data.data
        plen = eth.data.plen - tcp.off * 4
        theirs.append((tcp.sport, tcp.dport, tcp.seq, plen))
    assert ours == theirs


def _tcp_frame(linktype: int, prefix: bytes, ipv6=False) -> RawFrame:
    data, orig = _frame("::1" if ipv6 else "127.0.0.1", "::1" if ipv6 else "127.0.0.1", 5000, 22, 1, 1,
                        PSH | ACK, b"x" * 10, 10)
    ip = data[14:]
    return RawFrame(1, linktype, prefix + ip, len(prefix) + len(ip))


def test_G3_sll_loopback_outgoing_duplicate_dropped():
    st = DecodeStats()
    outgoing = struct.pack(">HHH8sH", 4, 772, 0, b"\x00" * 8, 0x0800)
    incoming = struct.pack(">HHH8sH", 0, 772, 0, b"\x00" * 8, 0x0800)
    assert decode(_tcp_frame(113, outgoing), st) is None
    assert st.loopback_duplicates == 1
    assert decode(_tcp_frame(113, incoming), st)[0].payload_len == 10


def test_G3_sll2_loopback_outgoing_duplicate_dropped():
    st = DecodeStats()
    out_hdr = struct.pack(">HHIHBB8s", 0x86DD, 0, 1, 772, 4, 0, b"\x00" * 8)
    in_hdr = struct.pack(">HHIHBB8s", 0x86DD, 0, 1, 772, 0, 0, b"\x00" * 8)
    assert decode(_tcp_frame(276, out_hdr, ipv6=True), st) is None
    assert decode(_tcp_frame(276, in_hdr, ipv6=True), st)[0].ipv == 6
    assert st.loopback_duplicates == 1


@pytest.mark.parametrize("linktype,prefix", [(0, struct.pack("<I", 2)), (108, struct.pack(">I", 2)), (101, b""), (228, b"")])
def test_other_link_types(linktype, prefix):
    pkt, head = decode(_tcp_frame(linktype, prefix), DecodeStats())
    assert pkt.dport == 22 and pkt.payload_len == 10 and bytes(head) == b"x" * 10


def test_vlan_tagged_ethernet():
    data, orig = _frame("127.0.0.1", "127.0.0.1", 5000, 22, 1, 1, PSH | ACK, b"y" * 4, 4)
    tagged = data[:12] + b"\x81\x00\x00\x05" + data[12:]
    pkt, _ = decode(RawFrame(1, 1, tagged, len(tagged)), DecodeStats())
    assert pkt.payload_len == 4


def test_payload_len_uses_ip_length_not_snaplen():
    data, orig = _frame("127.0.0.1", "127.0.0.1", 5000, 22, 1, 1, PSH | ACK, b"z" * 100, 30000)
    pkt, head = decode(RawFrame(1, 1, data, orig), DecodeStats())
    assert pkt.payload_len == 30000 and len(head) == 100


def test_ipv4_fragments_and_non_tcp_skipped():
    st = DecodeStats()
    data, _ = _frame("127.0.0.1", "127.0.0.1", 1, 2, 0, 0, ACK, b"", 0)
    frag = bytearray(data)
    frag[14 + 6] = 0x20  # MF
    assert decode(RawFrame(1, 1, bytes(frag), len(frag)), st) is None and st.fragments == 1
    udp = bytearray(data)
    udp[14 + 9] = 17
    assert decode(RawFrame(1, 1, bytes(udp), len(udp)), st) is None
