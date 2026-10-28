"""Property and fuzz tests: random streams never crash, memory stays bounded, output is deterministic."""

from __future__ import annotations

import io
import struct

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sshleak.capture.decode import ACK, PSH, SYN, DecodeStats, Packet, decode
from sshleak.capture.pcapfile import CaptureFormatError, CaptureReader, RawFrame
from sshleak.capture.sources import CaptureInfo
from sshleak.flows.handshake import SideHandshake
from sshleak.flows.tracker import FlowTracker, Limits
from sshleak.lab.synth import _frame
from sshleak.pipeline import Pipeline, ScanOptions

packet = st.tuples(
    st.integers(0, 10**12),  # ts
    st.sampled_from(["127.0.0.1", "::1", "10.0.0.1"]),
    st.integers(1, 65535),
    st.integers(0, 2**32 - 1),
    st.sampled_from([SYN, ACK, PSH | ACK, 0x11, 0x04]),
    st.integers(0, 65000),
    st.binary(max_size=64),
)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(packet, max_size=300))
def test_random_streams_no_crash_bounded_deterministic(pkts):
    def run():
        th = __import__("sshleak.thresholds", fromlist=["load"]).load()
        p = Pipeline(th, ScanOptions())
        p.tracker = FlowTracker(Limits(max_records_per_flow=1000, max_flows=16))
        for ts, ip, port, seq, flags, n, head in sorted(pkts):
            other = "::1" if ":" in ip else "127.0.0.1"
            data, orig = _frame(ip, other, port, 22, seq, 0, flags, head[:n], n)
            p.ingest(RawFrame(ts, 1, data, orig))
        assert len(p.tracker.flows) <= 16
        for f in p.tracker.flows.values():
            assert len(f.ts) <= 1000 + 250
        return p.report(CaptureInfo("pcap", "x", "file")).model_dump_json()

    assert run() == run()


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=4096))
def test_fuzz_reader_garbage(data):
    try:
        list(CaptureReader(io.BytesIO(data)))
    except CaptureFormatError:
        pass


@settings(max_examples=200, deadline=None)
@given(st.binary(min_size=1, max_size=3000), st.integers(0, 2**32 - 1))
def test_fuzz_handshake_parser(data, seq):
    for is_client in (True, False, None):
        hs = SideHandshake(is_client)
        hs.feed(seq, len(data), memoryview(data))
        assert len(hs._buf) <= 65_536
        if not hs.active:
            assert len(hs._buf) == 0


@settings(max_examples=200, deadline=None)
@given(st.integers(0, 300), st.binary(max_size=200))
def test_fuzz_decode_frames(linktype, data):
    decode(RawFrame(0, linktype, data, len(data)), DecodeStats())


@settings(max_examples=100, deadline=None)
@given(st.binary(min_size=0, max_size=255))
def test_fuzz_malformed_banners(junk):
    hs = SideHandshake(is_client=True)
    hs.feed(1, len(junk) + 2, memoryview(b"SSH-" + junk[:-2] if len(junk) > 2 else b"SSH-" + junk))
    hs2 = SideHandshake(is_client=False)
    hs2.feed(1, len(junk) + 2, memoryview(junk + b"\r\n"))


@pytest.mark.nightly
@settings(max_examples=5000, deadline=None)
@given(st.binary(max_size=20000))
def test_nightly_fuzz_reader_mutations(data):
    hdr = struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 4096, 1)
    try:
        list(CaptureReader(io.BytesIO(hdr + data)))
    except CaptureFormatError:
        pass


def test_giant_and_bad_timestamp_records():
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    giant = struct.pack("<IIII", 1, 2, 10**8, 10**8)
    rd = CaptureReader(io.BytesIO(hdr + giant))
    assert list(rd) == [] and rd.stats.truncated
    rec = struct.pack("<IIII", 0xFFFFFFFF, 0xFFFFFFFF, 4, 4) + b"abcd"
    assert len(list(CaptureReader(io.BytesIO(hdr + rec)))) == 1
