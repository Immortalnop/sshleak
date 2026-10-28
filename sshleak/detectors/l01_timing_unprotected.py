"""L1 Keystroke timing unprotected."""

from __future__ import annotations

import numpy as np

from sshleak.analysis.stats import confidence, r
from sshleak.detectors.base import Detector, DetectorMeta, DetectorResult, Severity, keystroke_gate


class L1TimingUnprotected(Detector):
    meta = DetectorMeta(
        id="L1",
        title="Keystroke timing unprotected",
        short="timing exposed",
        severity=Severity.HIGH,
        meaning="Each keystroke leaves the client as its own packet at the moment it is typed, so an "
        "observer sees inter-keystroke timing, which is known to leak typed content.",
        signal="Interactive client-to-server stream of small packets whose gaps are not on a fixed send grid.",
        min_evidence="min_packets client keystroke packets in interactive phases.",
        statistic="Fraction of tick gaps on a k*T grid at the best candidate interval T; one-sided binomial "
        "test that it is below grid_h0_fraction (what an obfuscating client produces).",
        false_positive_guard="Pastes excluded; an ambiguous grid fit is reported as insufficient evidence, not as a leak.",
        fix="Enable ObscureKeystrokeTiming on the client (default on in OpenSSH 9.5+); upgrade to a fixed "
        "OpenSSH (9.8 or later).",
        threshold_keys=("global.min_packets", "cadence.*"),
        cases=("S1", "S2", "S7", "S8"),
    )

    def run(self, ctx) -> DetectorResult:
        gate = keystroke_gate(ctx)
        if gate:
            return gate
        ia = ctx.interactive
        cad = ia.cadence
        ev = {
            "client_packets": ia.n_client,
            "gaps": cad.n,
            "grid_fraction": r(cad.grid_fraction, 3),
            "best_interval_ms": r(cad.interval_ms, 2),
            "median_gap_ms": r(float(np.median(ia.gaps)) * 1000, 2) if len(ia.gaps) else None,
            "pastes_excluded": ia.paste_count,
        }
        if cad.present:
            return self.not_fired(f"fixed send interval of {cad.interval_ms:.1f} ms observed", ev, cad.p_absent)
        if not cad.absent:
            return self.insufficient("send-interval fit is ambiguous", ev, cad.p_absent)
        effect = 1.0 - cad.grid_fraction
        conf = confidence(effect, cad.n, ctx.th.global_.confidence_n0)
        summary = f"{ia.n_client} keystroke packets, no fixed send interval (grid fit {cad.grid_fraction:.0%})"
        return self.fired(conf, summary, ev, cad.p_absent)
