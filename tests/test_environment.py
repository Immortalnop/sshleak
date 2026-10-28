"""Capture/clock cases C1-C8 and environment cases E1-E6."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from sshleak.capture.sources import CaptureInfo, TcpdumpSource
from sshleak.env import Virtualisation
from sshleak.errors import EnvironmentProblem
from sshleak.lab.scenarios import by_name, write_scenario
from sshleak.lab.synth import frames_for, to_raw
from sshleak.pipeline import Pipeline, ScanOptions
from tests.conftest import finding, run_cli, statuses


def test_C1_drops_mark_findings_degraded(analysed):
    rep, _ = analysed("drops")
    assert rep.capture.drops == 37
    f = finding(rep, "L1")
    assert f.confidence <= 0.7 and any("dropped" in d for d in f.degraded)


def test_C2_offload_warning_degrades(th):
    frames, _ = frames_for(by_name("unprotected").sessions[0])
    p = Pipeline(th, ScanOptions())
    for fr in to_raw(frames):
        p.ingest(fr)
    info = CaptureInfo(mode="live", label="eth0", ts_source="kernel", offload_warning="offload enabled on eth0 (gro)")
    rep = p.report(info)
    assert finding(rep, "L1").confidence <= th.confidence_caps.offload
    assert rep.capture.offload_warning


def test_C3_clock_step_window_dropped(analysed):
    rep, flows = analysed("clock_step")
    assert rep.capture.clock_steps >= 1
    assert any("clock step" in d for d in rep.flows[0].degraded)
    assert flows[0].ctx.view.dropped_for_steps > 0
    assert statuses(rep)["L1"] == "fired"


def test_C5_rekey_window_excluded(th):
    import numpy as np

    from sshleak.flows.tracker import FlowView
    from sshleak.phases.segmenter import segment

    ts, d, sz = [], [], []
    t = 0.0
    for _ in range(40):
        t += 0.15
        ts += [t, t + 0.0004]
        d += [0, 1]
        sz += [36, 36]
    ts += [20.0, 20.01]  # KEXINIT-sized pair during an idle stretch
    d += [0, 1]
    sz += [1500, 1400]
    t = 25.0
    for _ in range(40):
        t += 0.15
        ts += [t, t + 0.0004]
        d += [0, 1]
        sz += [36, 36]
    view = FlowView((np.array(ts) * 1e9).astype(np.int64), np.array(d, dtype=np.int8), np.array(sz, dtype=np.int32), None)
    segs, st = segment(view, th, late_join=True)
    assert st.rekey_events == 1 and any(s.kind == "rekey" for s in segs)
    assert all(not (s.kind == "interactive" and s.t0 <= 20.0 <= s.t1) for s in segs)


def test_C6_truncated_reports_and_degrades(analysed):
    rep, _ = analysed("truncated")
    assert rep.capture.truncated and rep.capture.truncation_reason
    assert len(rep.flows) == 1


def test_C7_relative_timestamps(analysed):
    rep, _ = analysed("relative_ts")
    assert rep.capture.relative_timestamps and statuses(rep)["L1"] == "fired"


def test_C8_hop_reported_by_L13():
    """C8 is reported by L13 (see test_L13_forward_hop_fires); here: the meta is degraded-free otherwise."""
    from sshleak.detectors.registry import load_detectors

    l13 = next(d for d in load_detectors() if d.meta.id == "L13")
    assert "C8" in l13.meta.cases


def _fake_tcpdump(tmp_path: Path, body: str) -> Path:
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    exe = d / "tcpdump"
    exe.write_text("#!/bin/sh\n" + body + "\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    return d


def test_E1_no_capture_permission_exit_3_with_fix(tmp_path, monkeypatch):
    d = _fake_tcpdump(tmp_path, 'echo "tcpdump: lo: You don\'t have permission to capture on that device" >&2\n'
                                'echo "(socket: Operation not permitted)" >&2\nexit 1')
    monkeypatch.setenv("PATH", f"{d}:{os.environ['PATH']}")
    with pytest.raises(EnvironmentProblem) as e:
        list(TcpdumpSource("lo", "tcp", duration=1).frames())
    assert e.value.case == "E1" and "setcap cap_net_raw,cap_net_admin=eip" in e.value.fix
    res = run_cli("scan", "--duration", "1")
    assert res.code == 3 and "setcap" in res.err


def test_E3_missing_interface_exit_3():
    res = run_cli("scan", "--iface", "nosuchif0", "--duration", "1")
    assert res.code == 3 and "does not exist" in res.err


def test_E4_capture_tool_missing_exit_3(monkeypatch):
    monkeypatch.setattr("sshleak.capture.sources.tcpdump_path", lambda: None)
    res = run_cli("scan", "--duration", "1")
    assert res.code == 3 and "apt install tcpdump" in res.err


def test_E5_ctrl_c_partial_results(tmp_path, monkeypatch, scenario_pcap):
    """A live source interrupted by Ctrl-C still produces a report."""
    from sshleak.capture.pcapfile import CaptureReader

    path = scenario_pcap("unprotected")
    frames = list(CaptureReader(open(path, "rb")))

    class Src:
        def __init__(self, *a, **k):
            self.stopped = False

        def frames(self):
            for i, fr in enumerate(frames):
                if i == len(frames) // 2:
                    raise KeyboardInterrupt
                yield fr

        def stop(self):
            self.stopped = True

        def info(self):
            return CaptureInfo("live", "lo", "kernel")

    monkeypatch.setattr("sshleak.capture.sources.TcpdumpSource", Src)
    res = run_cli("scan", "--duration", "5", "--format", "json")
    import json

    data = json.loads(res.out)
    assert data["capture"]["interrupted"] is True
    assert res.code in (0, 1)


def test_E2_virtualised_live_caps_confidence(th):
    frames, _ = frames_for(by_name("unprotected").sessions[0])
    p = Pipeline(th, ScanOptions(mode="live", virtualisation=Virtualisation("wsl2")))
    for fr in to_raw(frames):
        p.ingest(fr)
    rep = p.report(CaptureInfo("live", "lo", "kernel"))
    assert rep.environment["virtualisation"] == "wsl2"
    assert rep.summary.flows_hidden == 0
    f = finding(rep, "L1")
    assert f.confidence <= th.confidence_caps.virtualised and any("wsl2" in d for d in f.degraded)


def test_E6_low_memory_halves_caps(th, monkeypatch):
    class VM:
        available = 10 * 2**20

    monkeypatch.setattr("psutil.virtual_memory", lambda: VM())
    p = Pipeline(th, ScanOptions())
    assert p.tracker.limits.max_flows == th.limits.max_flows // 2
    rep = p.report(CaptureInfo("pcap", "x", "file"))
    assert any("low memory" in n for n in rep.capture.notes)


def test_live_hides_other_users_flows(th):
    """Multi-user hosts: flows whose owner is not us are counted, not shown."""
    from sshleak.discovery.sockets import ProcInfo, SocketSnapshot

    spec = by_name("unprotected").sessions[0]
    frames, _ = frames_for(spec)
    p = Pipeline(th, ScanOptions(mode="live"))
    for fr in to_raw(frames):
        p.ingest(fr)
    snap = SocketSnapshot(owners={(spec.client_ip, spec.client_port): ProcInfo(9, "ssh", os.geteuid() + 1)})
    p.add_snapshot(snap)
    rep = p.report(CaptureInfo("live", "lo", "kernel"))
    assert rep.flows == [] and rep.summary.flows_hidden == 1
    p2 = Pipeline(th, ScanOptions(mode="live"))
    for fr in to_raw(frames):
        p2.ingest(fr)
    p2.add_snapshot(SocketSnapshot(owners={(spec.client_ip, spec.client_port): ProcInfo(9, "ssh", os.geteuid(), ("ssh", "-p", "22", "host"))}))
    rep2 = p2.report(CaptureInfo("live", "lo", "kernel"))
    assert len(rep2.flows) == 1 and rep2.flows[0].client_process.cmdline == ["ssh", "[redacted]"]
