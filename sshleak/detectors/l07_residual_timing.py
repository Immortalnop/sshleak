"""L7 Residual timing under obfuscation."""

from __future__ import annotations

import numpy as np
from scipy import stats as sps

from sshleak.analysis.stats import bootstrap_ci, confidence, r, rng_for
from sshleak.detectors.base import Detector, DetectorMeta, DetectorResult, Severity, keystroke_gate


def _spearman(x: np.ndarray, y: np.ndarray) -> tuple[float, float]:
    if len(x) < 3 or np.ptp(x) == 0 or np.ptp(y) == 0:
        return 0.0, 1.0
    res = sps.spearmanr(x, y)
    rho, p = float(res.statistic), float(res.pvalue)
    if not np.isfinite(rho):
        return 0.0, 1.0
    return rho, p


class L7ResidualTiming(Detector):
    meta = DetectorMeta(
        id="L7",
        title="Residual timing under obfuscation",
        short="residual timing",
        severity=Severity.MEDIUM,
        meaning="Sends are on a fixed grid, but the small deviation from the grid still depends on what "
        "was sent (size) or on the server's reply, so some timing information survives.",
        signal="Jitter of tick gaps around the interval vs. tick size and vs. reply latency.",
        min_evidence="Cadence present and min_ticks ticks inside fixed-interval runs.",
        statistic="Spearman rank correlation, Bonferroni over the two pairs; bootstrap CI of the stronger rho.",
        false_positive_guard="Only gaps between consecutive ticks inside a run are used; constant inputs "
        "yield rho = 0.",
        fix="Use a larger interval (ObscureKeystrokeTiming=interval:N) and verify the client build.",
        threshold_keys=("L7.*",),
    )

    def run(self, ctx) -> DetectorResult:
        gate = keystroke_gate(ctx)
        if gate:
            return gate
        ia = ctx.interactive
        cad = ia.cadence
        if not cad.present:
            return self.skipped("obfuscation not active (no fixed send interval)")
        t7 = ctx.th.L7
        T = cad.interval_ms / 1000.0
        k = ia.gap_tick
        both = ia.in_run[k] & ia.in_run[k - 1]
        g = ia.gaps[both]
        kk = k[both]
        n = len(g)
        if n < t7.min_ticks:
            return self.insufficient(f"{n} in-run gaps, need {t7.min_ticks}", {"in_run_gaps": n})
        jitter = np.abs(g - np.rint(g / T) * T)
        size = ia.tick_bytes[kk].astype(float)
        lat = ia.reply_latency[kk - 1]
        ok = np.isfinite(lat)
        rho_s, p_s = _spearman(jitter, size)
        rho_l, p_l = _spearman(jitter[ok], lat[ok]) if ok.sum() >= 3 else (0.0, 1.0)
        p = min(1.0, 2 * min(p_s, p_l))
        strongest = ("size", rho_s) if abs(rho_s) >= abs(rho_l) else ("reply_latency", rho_l)
        gl = ctx.th.global_
        ci = None
        if abs(strongest[1]) > 0:
            pair = np.column_stack([jitter, size]) if strongest[0] == "size" else np.column_stack([jitter[ok], lat[ok]])
            ci = bootstrap_ci(pair, lambda a: _spearman(a[:, 0], a[:, 1])[0], min(gl.bootstrap_resamples, 200),
                              rng_for(gl.seed, ctx.meta.flow_id, "L7"))
        ev = {
            "in_run_gaps": n,
            "rho_jitter_vs_size": r(rho_s, 3),
            "rho_jitter_vs_reply_latency": r(rho_l, 3),
            "strongest": strongest[0],
            "rho_ci95": [r(ci[0], 3), r(ci[1], 3)] if ci else None,
            "median_jitter_ms": r(float(np.median(jitter)) * 1000, 3),
        }
        if abs(strongest[1]) >= t7.min_abs_rho and p <= gl.alpha:
            conf = confidence(abs(strongest[1]), n, gl.confidence_n0)
            summary = f"grid jitter tracks {strongest[0].replace('_', ' ')} (rho {strongest[1]:+.2f}, {n} gaps)"
            return self.fired(conf, summary, ev, p)
        return self.not_fired("grid jitter independent of size and reply latency", ev, p)
