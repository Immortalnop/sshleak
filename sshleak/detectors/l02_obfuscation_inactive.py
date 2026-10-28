"""L2 Obfuscation configured but not active."""

from __future__ import annotations

from sshleak.analysis.stats import confidence, r
from sshleak.detectors.base import Detector, DetectorMeta, DetectorResult, Severity, keystroke_gate


class L2ObfuscationInactive(Detector):
    meta = DetectorMeta(
        id="L2",
        title="Obfuscation configured but not active",
        short="obfuscation off",
        severity=Severity.HIGH,
        meaning="The client is expected to send keystrokes on a fixed interval (by its effective config, "
        "or by the OpenSSH 9.5+ default), but the capture shows no such cadence.",
        signal="Expected ObscureKeystrokeTiming interval vs. the cadence measured in client tick gaps.",
        min_evidence="An expectation (config check or client banner) and min_packets keystroke packets.",
        statistic="Cadence test at the expected interval; one-sided binomial test of grid fraction.",
        false_positive_guard="Without a config check the expectation comes from the version default and "
        "confidence is scaled down; an unknown client version gives insufficient evidence.",
        fix="Check the effective config (ssh -G <host> | grep obscure), the client version, and X11 "
        "forwarding interaction (OpenSSH 10.0 pauses obfuscation after X11 traffic).",
        threshold_keys=("L2.*", "cadence.*"),
        cases=("V3", "V4"),
    )

    def run(self, ctx) -> DetectorResult:
        m = ctx.meta
        t2 = ctx.th.L2
        cfg = m.config
        if cfg is not None and cfg.enabled is False:
            return self.not_fired("ObscureKeystrokeTiming is disabled in the effective client config (L1 covers exposure)")
        if cfg is not None and cfg.enabled:
            expected, source, factor = cfg.interval_ms or t2.default_interval_ms, "client config (ssh -G)", 1.0
        elif m.client_sw is None:
            return self.insufficient("client version unknown and no config check: cannot tell whether obfuscation was expected")
        elif not m.client_sw.is_openssh:
            return self.skipped(f"client implementation {m.client_sw.impl!r}: no known obfuscation default (V5)")
        elif not m.client_sw.at_least(9, 5):
            return self.skipped("client predates ObscureKeystrokeTiming (see L11)")
        else:
            expected, source, factor = t2.default_interval_ms, "OpenSSH 9.5+ default", t2.default_expectation_factor
        gate = keystroke_gate(ctx)
        if gate:
            return gate
        ia = ctx.interactive
        cad = ia.cadence
        ev = {
            "expected_interval_ms": r(expected, 2),
            "expectation_source": source,
            "observed_interval_ms": r(cad.interval_ms, 2),
            "grid_fraction": r(cad.grid_fraction, 3),
            "client_packets": ia.n_client,
        }
        if cad.present:
            tol = max(ctx.th.cadence.tolerance_abs_ms, ctx.th.cadence.tolerance_rel * expected)
            if abs(cad.interval_ms - expected) <= tol:
                return self.not_fired(f"active at the expected {expected:.0f} ms interval", ev, cad.p_absent)
            ev["interval_mismatch"] = True
            return self.not_fired(
                f"active at {cad.interval_ms:.1f} ms, not the expected {expected:.0f} ms (interval set elsewhere)",
                ev, cad.p_absent,
            )
        if not cad.absent:
            return self.insufficient("send-interval fit is ambiguous", ev, cad.p_absent)
        conf = confidence(1.0 - cad.grid_fraction, cad.n, ctx.th.global_.confidence_n0) * factor
        summary = f"expected {expected:.0f} ms cadence ({source}); none in {ia.n_client} keystroke packets"
        return self.fired(conf, summary, ev, cad.p_absent)
