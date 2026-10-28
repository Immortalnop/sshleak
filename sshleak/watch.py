"""`sshleak watch`: re-evaluate periodically, emit a finding when evidence first
suffices, then emit updates when its confidence or status changes."""

from __future__ import annotations

import json
import time
from typing import Callable, Iterator

from sshleak.capture.pcapfile import RawFrame
from sshleak.capture.sources import CaptureInfo
from sshleak.findings.report import Report
from sshleak.pipeline import Pipeline

UPDATE_DELTA = 0.05


class Watcher:
    def __init__(self, pipeline: Pipeline, emit: Callable[[dict], None], interval_s: float = 5.0):
        self.p = pipeline
        self.emit = emit
        self.interval_s = interval_s
        self.state: dict[tuple[str, str], float] = {}

    def evaluate(self, capture: CaptureInfo, at_s: float) -> Report:
        report = self.p.report(capture)
        seen: set[tuple[str, str]] = set()
        for flow in report.flows:
            for f in flow.findings:
                key = (flow.id, f.id)
                seen.add(key)
                prev = self.state.get(key)
                if prev is None or abs(prev - f.confidence) >= UPDATE_DELTA:
                    self.emit({
                        "type": "finding", "event": "new" if prev is None else "update", "t": round(at_s, 3),
                        "flow": flow.id, "client": flow.client, "server": flow.server, "id": f.id,
                        "severity": f.severity, "confidence": f.confidence, "summary": f.summary,
                    })
                    self.state[key] = f.confidence
        for key in [k for k in self.state if k not in seen]:
            self.emit({"type": "finding", "event": "cleared", "t": round(at_s, 3), "flow": key[0], "id": key[1]})
            del self.state[key]
        return report

    def run(self, frames: Iterator[RawFrame | None], info: Callable[[], CaptureInfo], *, packet_clock: bool) -> Report:
        """packet_clock: evaluate on capture time (pcap replay) instead of wall time."""
        start_wall = time.monotonic()
        last_eval = 0.0
        first_ts: int | None = None
        now = 0.0
        for frame in frames:
            if frame is not None:
                self.p.ingest(frame)
                if first_ts is None:
                    first_ts = frame.ts_ns
                if packet_clock:
                    now = (frame.ts_ns - first_ts) / 1e9
            if not packet_clock:
                now = time.monotonic() - start_wall
            if now - last_eval >= self.interval_s:
                self.evaluate(info(), now)
                last_eval = now
        return self.evaluate(info(), now if packet_clock else time.monotonic() - start_wall)


def event_line(ev: dict, fmt: str) -> str:
    if fmt == "jsonl":
        return json.dumps(ev, sort_keys=True)
    if ev.get("event") == "cleared":
        return f"[{ev['t']:>8.1f}s] cleared  {ev['flow']} {ev['id']}"
    return (f"[{ev['t']:>8.1f}s] {ev['event']:<7} {ev['severity'].upper():<6} {ev['id']:<4} {ev['flow']} "
            f"{ev['client']} -> {ev['server']}  conf {ev['confidence']:.2f}  {ev['summary']}")
