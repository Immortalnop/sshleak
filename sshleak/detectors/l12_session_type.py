"""L12 Session type exposed."""

from __future__ import annotations

from sshleak.detectors.base import Detector, DetectorMeta, DetectorResult, Severity


class L12SessionType(Detector):
    meta = DetectorMeta(
        id="L12",
        title="Session type exposed",
        short="session type",
        severity=Severity.INFO,
        meaning="Packet sizes and gaps reveal what the session is: shell, scp/sftp transfer, tunnel or a "
        "remote command.",
        signal="Share of interactive, bulk and mixed phases; request pattern in bulk phases.",
        min_evidence="Some traffic after authentication.",
        statistic="Phase-share classification with a confidence from the dominant share.",
        false_positive_guard="Low-confidence classifications are reported as insufficient evidence.",
        fix="Not fixable by timing options; document it.",
        threshold_keys=("L12.*",),
        cases=("S3", "S5", "S8"),
    )

    def run(self, ctx) -> DetectorResult:
        st = ctx.session
        ev = {"session_type": st.kind, "phase_shares": st.shares, "basis": st.evidence}
        if st.kind == "unknown" or st.confidence < ctx.th.L12.min_confidence:
            return self.insufficient("session shape not clear enough to classify", ev)
        caps = ("mixed_traffic",) if st.kind == "tunnel/forward" else ()
        return self.fired(st.confidence, f"looks like {st.kind} ({st.evidence})", ev, None, caps)
