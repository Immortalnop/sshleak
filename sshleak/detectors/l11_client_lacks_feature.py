"""L11 Client lacks the feature."""

from __future__ import annotations

from sshleak.detectors.base import Detector, DetectorMeta, DetectorResult, Severity


class L11ClientLacksFeature(Detector):
    meta = DetectorMeta(
        id="L11",
        title="Client lacks the feature",
        short="client too old",
        severity=Severity.MEDIUM,
        meaning="The client predates ObscureKeystrokeTiming (OpenSSH 9.5), so it cannot hide keystroke timing.",
        signal="Client identification string (cleartext banner).",
        min_evidence="Client banner seen (not a late-join flow) and an OpenSSH client.",
        statistic="Version comparison against 9.5.",
        false_positive_guard="Unknown or non-OpenSSH implementations are skipped, not judged (V5).",
        fix="Upgrade the client to OpenSSH 9.8 or later.",
        timing=False,
        cases=("V1", "V5", "F5"),
    )

    def run(self, ctx) -> DetectorResult:
        sw = ctx.meta.client_sw
        if sw is None:
            return self.skipped("client version unknown (late-join: banner not captured)")
        if not sw.is_openssh:
            return self.skipped(f"client implementation {sw.raw!r} unknown to this check (V5)")
        ev = {"client_software": sw.raw, "version": f"{sw.version[0]}.{sw.version[1]}"}
        if sw.at_least(9, 5):
            return self.not_fired("client is OpenSSH 9.5 or later", ev)
        return self.fired(0.95, f"client {sw.raw} predates ObscureKeystrokeTiming (9.5)", ev)
