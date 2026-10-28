"""L6 Command-boundary timing."""

from __future__ import annotations

import numpy as np

from sshleak.analysis.stats import confidence, r
from sshleak.detectors.base import Detector, DetectorMeta, DetectorResult, Severity, keystroke_gate


class L6CommandBoundary(Detector):
    meta = DetectorMeta(
        id="L6",
        title="Command-boundary timing",
        short="command boundaries",
        severity=Severity.MEDIUM,
        meaning="Pauses before Enter and the size of the response after it show when each command was "
        "run and how much output it produced.",
        signal="Typing burst, Enter, then a server response larger than an echo.",
        min_evidence="min_packets keystrokes and min_events Enter events.",
        statistic="Count of Enter events; response size and think-pause distributions.",
        false_positive_guard="Under working obfuscation timing is quantised to the interval, so confidence "
        "is scaled by obfuscated_confidence_factor.",
        fix="Keep ObscureKeystrokeTiming on; shell prompt noise (e.g. a prompt that redraws) blurs boundaries.",
        threshold_keys=("L6.*", "echo.response_window_s"),
    )

    def run(self, ctx) -> DetectorResult:
        gate = keystroke_gate(ctx)
        if gate:
            return gate
        ia = ctx.interactive
        t6 = ctx.th.L6
        ev_list = ia.events
        if len(ev_list) < t6.min_events:
            return self.insufficient(f"{len(ev_list)} Enter events, need {t6.min_events}", {"enter_events": len(ev_list)})
        resp = np.array([e.response_bytes for e in ev_list], dtype=float)
        pause = np.array([e.pause_s for e in ev_list], dtype=float)
        cad = ia.cadence
        factor = t6.obfuscated_confidence_factor if cad.present else 1.0
        ev = {
            "enter_events": len(ev_list),
            "median_response_bytes": r(float(np.median(resp)), 0),
            "median_pause_before_enter_ms": r(float(np.median(pause)) * 1000, 1),
            "timing_quantum_ms": r(cad.interval_ms, 2) if cad.present else None,
        }
        conf = confidence(0.8, len(ev_list) * 10, ctx.th.global_.confidence_n0) * factor
        summary = f"{len(ev_list)} command boundaries with response sizes (median {ev['median_response_bytes']:.0f} B)"
        return self.fired(conf, summary, ev)
