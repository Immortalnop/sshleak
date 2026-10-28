"""L5 Keystroke count / command length exposed."""

from __future__ import annotations

import numpy as np

from sshleak.analysis.stats import confidence, r
from sshleak.detectors.base import Detector, DetectorMeta, DetectorResult, Severity, keystroke_gate


def burst_counts(ia, use_double: bool) -> list[int]:
    counts = []
    for e in ia.events:
        sl = slice(e.burst_start, e.tick + 1)
        if use_double:
            counts.append(int((ia.tick_units[sl] == 2).sum()))
        else:
            counts.append(e.tick + 1 - e.burst_start)
    return counts


class L5KeystrokeCount(Detector):
    meta = DetectorMeta(
        id="L5",
        title="Keystroke count / command length exposed",
        short="length exposed",
        severity=Severity.MEDIUM,
        meaning="The number of client packets before each Enter follows the number of characters typed, "
        "so an observer learns the length of every command.",
        signal="Packets per typing burst ending in an Enter (a server response larger than an echo).",
        min_evidence="min_packets keystrokes and min_bursts Enter events.",
        statistic="Per-burst count of keystroke packets (or of two-unit ticks when chaff is separable).",
        false_positive_guard="With working obfuscation the count includes chaff with a random tail, so the "
        "detector does not fire; constant server output lowers confidence (S6).",
        fix="Keep ObscureKeystrokeTiming on (fixed client), which adds chaff with a random tail; consider a "
        "padding layer for high-risk sessions.",
        threshold_keys=("L5.*",),
        cases=("S6",),
    )

    def run(self, ctx) -> DetectorResult:
        gate = keystroke_gate(ctx)
        if gate:
            return gate
        ia = ctx.interactive
        t5 = ctx.th.L5
        n_ev = len(ia.events)
        caps = ("redraw_noise",) if ia.server_noise_ratio > ctx.th.L4.redraw_noise_max else ()
        if n_ev < t5.min_bursts:
            return self.insufficient(f"{n_ev} Enter events, need {t5.min_bursts}", {"enter_events": n_ev})
        cad = ia.cadence
        if cad.present:
            doubles = int((ia.tick_units[ia.in_run] == 2).sum())
            if doubles < ctx.th.L3.min_double_ticks:
                return self.not_fired("keystroke count masked by chaff (fixed-interval sends of one size)",
                                      {"enter_events": n_ev, "interval_ms": r(cad.interval_ms, 2)})
            counts, basis, effect = burst_counts(ia, True), "two-unit ticks (chaff separable)", 0.8
        else:
            counts, basis, effect = burst_counts(ia, False), "one packet per keystroke", 0.9
        arr = np.array(counts, dtype=float)
        ev = {
            "enter_events": n_ev,
            "counting_basis": basis,
            "median_keys_per_command": r(float(np.median(arr)), 1),
            "max_keys_per_command": int(arr.max()),
            "distinct_lengths": int(len(np.unique(arr))),
        }
        conf = confidence(effect, ia.n_client, ctx.th.global_.confidence_n0)
        summary = f"packet count per command visible in {n_ev} commands (median {ev['median_keys_per_command']:.0f} keys)"
        return self.fired(conf, summary, ev, None, caps)
