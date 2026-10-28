"""Performance targets: CPU per packet and memory per flow; soak (slow)."""

from __future__ import annotations

import time
import tracemalloc

import pytest

from sshleak.capture.sources import CaptureInfo
from sshleak.lab.scenarios import by_name
from sshleak.lab.synth import Obfuscation, SessionSpec, frames_for, to_raw, typing_script
from sshleak.pipeline import Pipeline, ScanOptions


def test_ingest_cost_under_5pct_of_a_core_at_1000pps(th):
    """Target: < 5% of one core at 1,000 packets/s => < 50 us per packet on ingest."""
    frames, _ = frames_for(by_name("fixed").sessions[0])
    raw = to_raw(frames) * 3
    p = Pipeline(th, ScanOptions())
    t0 = time.process_time()
    for fr in raw:
        p.ingest(fr)
    per_pkt = (time.process_time() - t0) / len(raw)
    assert per_pkt < 50e-6, f"{per_pkt * 1e6:.1f} us/packet"


def test_memory_per_flow_under_2mb(th):
    spec = SessionSpec(name="long", obfuscation=Obfuscation(20), script=typing_script(150, 1), seed=5)
    frames, _ = frames_for(spec)
    raw = to_raw(frames)
    tracemalloc.start()
    p = Pipeline(th, ScanOptions())
    for fr in raw:
        p.ingest(fr)
    raw = None
    frames = None
    cur, _peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    flow = p.tracker.all_flows()[0]
    per_record = (len(flow.ts) * 8 + len(flow.ln) * 4 + len(flow.fa))
    cap_bytes = th.limits.max_records_per_flow * 1.25 * (8 + 4 + 1)
    assert cap_bytes < 2 * 2**20  # the cap itself bounds a flow below 2 MB
    assert per_record < 2 * 2**20 and cur < 8 * 2**20


@pytest.mark.slow
def test_soak_100_flows(th):
    """Soak: 100 concurrent typing flows replayed through the watch engine."""
    from sshleak.watch import Watcher

    streams = []
    for i in range(100):
        f, _ = frames_for(SessionSpec(name=f"s{i}", client_port=30000 + i, obfuscation=Obfuscation(20) if i % 2 else None,
                                      client_sw="OpenSSH_9.8" if i % 2 else "OpenSSH_9.4",
                                      script=typing_script(10, i), seed=i, start_s=i * 0.05))
        streams += f
    streams.sort(key=lambda fr: fr.ts_ns)
    p = Pipeline(th, ScanOptions())
    events = []
    w = Watcher(p, events.append, interval_s=10)
    rep = w.run(iter(to_raw(streams)), lambda: CaptureInfo("pcap", "soak", "file"), packet_clock=True)
    assert rep.summary.flows_analysed == 100
    assert sum(1 for f in rep.flows for x in f.findings if x.id == "L1") == 50
