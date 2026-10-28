"""Run detectors on a flow, correct for multiple testing, cap confidence, score."""

from __future__ import annotations

from dataclasses import dataclass

from sshleak.analysis.stats import holm, r
from sshleak.detectors.base import SEVERITY_RANK, Detector, DetectorResult, Severity, Status
from sshleak.detectors.context import FlowContext
from sshleak.findings.report import CheckModel, FindingModel
from sshleak.thresholds import Thresholds


@dataclass
class FlowOutcome:
    findings: list[FindingModel]
    checks: list[CheckModel]
    results: dict[str, DetectorResult]
    score: float | None


def _clean(value):
    """Round floats recursively so output is stable."""
    if isinstance(value, float):
        return r(value, 4)
    if isinstance(value, dict):
        return {str(k): _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    return value


def evaluate(ctx: FlowContext, detectors: list[Detector], only: set[str] | None) -> FlowOutcome:
    th = ctx.th
    results: dict[str, DetectorResult] = {}
    for det in detectors:
        if only and det.meta.id not in only:
            continue
        results[det.meta.id] = det.run(ctx)

    # Holm across every statistical test run on this flow.
    pvals = {k: v.p_value for k, v in results.items() if v.p_value is not None and v.status in (Status.FIRED, Status.NOT_FIRED)}
    adjusted = holm(pvals) if pvals else {}
    alpha = th.global_.alpha
    for k, res in results.items():
        if k in adjusted:
            res.p_value = adjusted[k]
            if res.status is Status.FIRED and adjusted[k] > alpha:
                res.status = Status.INSUFFICIENT
                res.reason = f"not significant after Holm correction across {len(adjusted)} tests"

    caps = th.confidence_caps.model_dump()
    by_id = {d.meta.id: d for d in detectors}
    findings: list[FindingModel] = []
    checks: list[CheckModel] = []
    for k, res in results.items():
        meta = by_id[k].meta
        checks.append(CheckModel(id=k, status=res.status.value, reason=res.reason))
        if res.status is not Status.FIRED:
            continue
        applied: list[str] = []
        conf = res.confidence
        keys = list(res.caps)
        if meta.timing:
            keys += list(ctx.meta.degraded)
        elif "truncated_input" in ctx.meta.degraded:
            keys.append("truncated_input")
        for key in dict.fromkeys(keys):
            cap = caps.get(key)
            if cap is not None and conf > cap:
                conf = cap
            reason = ctx.meta.degraded.get(key) or key.replace("_", " ")
            applied.append(reason)
        findings.append(
            FindingModel(
                id=k,
                title=meta.title,
                severity=meta.severity.value,
                confidence=round(conf, 3),
                p_value=r(res.p_value, 6) if res.p_value is not None else None,
                summary=res.summary,
                evidence=_clean(res.evidence),
                fix=meta.fix,
                degraded=applied,
            )
        )
    findings.sort(key=lambda f: (-SEVERITY_RANK[Severity(f.severity)], -f.confidence, f.id))
    return FlowOutcome(findings, checks, results, score_flow(findings, th))


def score_flow(findings: list[FindingModel], th: Thresholds) -> float:
    """Decision (Phase 5): 100 = no leaks; subtract weight x confidence per finding, floor 0."""
    w = th.score.model_dump()
    total = 100.0 - sum(w[f.severity] * f.confidence for f in findings)
    return round(max(0.0, total), 1)
