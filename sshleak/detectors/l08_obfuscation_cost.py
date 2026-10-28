"""L8 Obfuscation cost out of bounds."""

from __future__ import annotations

import numpy as np

from sshleak.analysis.stats import r, sample_factor
from sshleak.detectors.base import Detector, DetectorMeta, DetectorResult, Severity, keystroke_gate


class L8ObfuscationCost(Detector):
    meta = DetectorMeta(
        id="L8",
        title="Obfuscation cost out of bounds",
        short="obfuscation cost",
        severity=Severity.INFO,
        meaning="Keystroke obfuscation costs bandwidth (chaff) and latency (sends wait for the next tick). "
        "This reports when either exceeds the configured bounds.",
        signal="Bytes per second in fixed-interval runs; added latency estimated from the interval "
        "(a keystroke waits for the next tick: mean T/2, p95 0.95T). Keypress times are not visible "
        "passively, so latency is an estimate.",
        min_evidence="Cadence present.",
        statistic="Measured chaff bytes/s; estimated added latency from the measured interval.",
        false_positive_guard="Only runs at the measured interval are counted.",
        fix="Tune ObscureKeystrokeTiming=interval:N (larger = less chaff, more latency).",
        threshold_keys=("L8.*",),
    )

    def run(self, ctx) -> DetectorResult:
        gate = keystroke_gate(ctx)
        if gate:
            return gate
        ia = ctx.interactive
        cad = ia.cadence
        if not cad.present:
            return self.skipped("obfuscation not active (no fixed send interval)")
        t8 = ctx.th.L8
        T = cad.interval_ms
        run = ia.in_run
        # Run duration: sum of in-run gaps (one interval each).
        k = ia.gap_tick
        in_gap = run[k] & run[k - 1]
        seconds = float(ia.gaps[in_gap].sum())
        client_b = float(ia.tick_bytes[run].sum())
        server_b = float((ia.reply_units[run] * (ia.unit or 0)).sum())
        rate = (client_b + server_b) / seconds if seconds > 0 else 0.0
        p95 = 0.95 * T
        ev = {
            "interval_ms": r(T, 2),
            "added_latency_mean_ms_est": r(T / 2, 2),
            "added_latency_p95_ms_est": r(p95, 2),
            "chaff_bytes_per_s": r(rate, 1),
            "run_seconds": r(seconds, 2),
        }
        over = []
        if p95 > t8.max_latency_p95_ms:
            over.append(f"latency p95 {p95:.1f} ms > {t8.max_latency_p95_ms:.0f} ms")
        if rate > t8.max_chaff_bytes_per_s:
            over.append(f"{rate / 1000:.1f} KB/s > {t8.max_chaff_bytes_per_s / 1000:.1f} KB/s")
        if not over:
            return self.not_fired(f"+{p95:.1f} ms p95 (est.), {rate / 1000:.1f} KB/s within bounds", ev)
        conf = 0.9 * sample_factor(int(run.sum()), ctx.th.global_.confidence_n0)
        summary = f"+{p95:.1f} ms p95 (est.), {rate / 1000:.1f} KB/s chaff: " + "; ".join(over)
        return self.fired(conf, summary, ev)
