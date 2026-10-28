"""Analyse a capture file and compare against labelled expectations."""

from __future__ import annotations

from pathlib import Path

from sshleak.capture.sources import PcapSource
from sshleak.findings.report import Report
from sshleak.pipeline import FlowAnalysis, Pipeline, ScanOptions
from sshleak.thresholds import Thresholds

OBSERVE = "observe"


def analyse_file(path: Path, th: Thresholds, **opts) -> tuple[Report, list[FlowAnalysis]]:
    pipeline = Pipeline(th, ScanOptions(mode="pcap", **opts))
    src = PcapSource(path)
    for frame in src.frames():
        if frame is not None:
            pipeline.ingest(frame)
    info = src.info()
    flows, _, _ = pipeline.analyse_flows(info)
    return pipeline.report(info), flows


def mismatches(report: Report, expect: dict[int, dict[str, str]], expect_flows: int | None = None) -> tuple[list[str], dict]:
    """Return (problems, observed) where observed lists 'observe' expectations' actual statuses."""
    probs: list[str] = []
    observed: dict[str, str] = {}
    flows = report.flows
    if expect_flows is not None and len(flows) != expect_flows:
        probs.append(f"{len(flows)} flows analysed, expected {expect_flows}")
    for idx, exp in expect.items():
        if idx >= len(flows):
            probs.append(f"flow #{idx} missing")
            continue
        st = {c.id: c for c in flows[idx].checks}
        for det, want in exp.items():
            got = st.get(det)
            if got is None:
                probs.append(f"{det}: not run")
            elif want == OBSERVE:
                observed[det] = got.status
            elif got.status != want:
                probs.append(f"{det}: {got.status} (want {want}{'; ' + got.reason if got.reason else ''})")
    return probs, observed
