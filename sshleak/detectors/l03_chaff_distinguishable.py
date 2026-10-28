"""L3 Chaff distinguishable from real keystrokes."""

from __future__ import annotations

import numpy as np

from sshleak.analysis.stats import binom_greater, bootstrap_ci, confidence, r, rng_for
from sshleak.detectors.base import Detector, DetectorMeta, DetectorResult, Severity, keystroke_gate


class L3ChaffDistinguishable(Detector):
    meta = DetectorMeta(
        id="L3",
        title="Chaff distinguishable from real keystrokes",
        short="chaff separable",
        severity=Severity.HIGH,
        meaning="The obfuscation sends fake keystrokes, but real ones still stand out: on a tick with a "
        "real keystroke the client sends two packets (real + chaff), so ticks of 2 units mark typing. "
        "This is the OpenSSH 9.5-9.7 client flaw (CVE-2024-39894).",
        signal="Send ticks inside the fixed-interval run carrying 2 packet units, and server replies of 2 units.",
        min_evidence="Cadence present and min_double_ticks two-unit ticks.",
        statistic="One-sided binomial test of the two-unit tick share against the timer-noise share; "
        "bootstrap CI of that share.",
        false_positive_guard="Pastes (>= paste_min_units) are excluded before ticks are built; a fixed client "
        "packs several typed bytes into one padded unit, so fast typing does not create 2-unit ticks.",
        fix="Upgrade the client to OpenSSH 9.8 or later (or a distribution build with the CVE-2024-39894 "
        "backport); as a stopgap, ObscureKeystrokeTiming=no removes the false sense of protection.",
        threshold_keys=("L3.*", "ticks.*"),
        cases=("V2",),
    )

    def run(self, ctx) -> DetectorResult:
        gate = keystroke_gate(ctx)
        if gate:
            return gate
        ia = ctx.interactive
        if not ia.cadence.present:
            return self.skipped("obfuscation not active (no fixed send interval)")
        t3 = ctx.th.L3
        run = ia.in_run
        n = int(run.sum())
        units = ia.tick_units[run]
        double = units == 2
        nd = int(double.sum())
        frac = nd / n if n else 0.0
        srv = ia.reply_units[run]
        srv_double = float((srv == 2).mean()) if n else 0.0
        p = binom_greater(nd, n, t3.noise_fraction)
        g = ctx.th.global_
        ci = bootstrap_ci(double.astype(float), np.mean, g.bootstrap_resamples, rng_for(g.seed, ctx.meta.flow_id, "L3"))
        ev = {
            "run_ticks": n,
            "two_unit_ticks": nd,
            "two_unit_fraction": r(frac, 4),
            "two_unit_fraction_ci95": [r(ci[0], 4), r(ci[1], 4)] if ci else None,
            "server_two_unit_reply_fraction": r(srv_double, 4),
            "unit_bytes": ia.unit,
            "interval_ms": r(ia.cadence.interval_ms, 2),
        }
        if nd >= t3.min_double_ticks and frac >= t3.min_double_fraction and p <= g.alpha:
            effect = min(1.0, frac / (10 * t3.min_double_fraction))
            conf = confidence(effect, n, g.confidence_n0)
            summary = f"real sends ~2x chaff size in {nd}/{n} ticks ({frac:.1%}); a fixed client sends one unit per tick"
            return self.fired(conf, summary, ev, p)
        if nd < t3.min_double_ticks and n < ctx.th.global_.min_packets:
            return self.insufficient(f"only {n} ticks inside fixed-interval runs", ev, p)
        return self.not_fired("real and chaff sends have the same size", ev, p)
