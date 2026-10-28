"""L9 Compression on interactive session."""

from __future__ import annotations

from sshleak.detectors.base import Detector, DetectorMeta, DetectorResult, Severity


class L9Compression(Detector):
    meta = DetectorMeta(
        id="L9",
        title="Compression on interactive session",
        short="compression on",
        severity=Severity.MEDIUM,
        meaning="With compression the encrypted size follows how compressible the content is, which "
        "leaks content on top of timing.",
        signal="Compression algorithm negotiated in the cleartext KEXINIT exchange.",
        min_evidence="Both KEXINIT messages seen (not a late-join flow) and an interactive phase.",
        statistic="RFC 4253 7.1 negotiation of the compression name-lists.",
        false_positive_guard="Only fires when an interactive phase exists; file transfers are not flagged.",
        fix="Disable compression for interactive use (no -C; Compression no).",
        timing=False,
        cases=("V6", "F5"),
    )

    def run(self, ctx) -> DetectorResult:
        neg = ctx.meta.negotiated
        if neg is None:
            return self.skipped("negotiated algorithms unknown (late-join or handshake not captured)")
        comp = sorted({c for c in (neg.comp_c2s, neg.comp_s2c) if c and c != "none"})
        ev = {"compression_c2s": neg.comp_c2s, "compression_s2c": neg.comp_s2c}
        if not comp:
            return self.not_fired("no compression negotiated", ev)
        if not any(s.kind == "interactive" for s in ctx.segments):
            return self.not_fired("compression negotiated, but no interactive phase", ev)
        return self.fired(0.95, f"{', '.join(comp)} negotiated on an interactive session", ev)
