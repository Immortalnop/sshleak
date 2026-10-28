"""Detector plugin interface.

A detector declares its inputs, minimum evidence, statistic, threshold keys and
false-positive guard, and returns fired / not_fired / insufficient_evidence /
skipped (never a bare boolean). `skipped` means the check does not apply to
this flow (e.g. no interactive phase), and the reason is always reported.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sshleak.detectors.context import FlowContext


class Status(str, Enum):
    FIRED = "fired"
    NOT_FIRED = "not_fired"
    INSUFFICIENT = "insufficient_evidence"
    SKIPPED = "skipped"


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    INFO = "info"


SEVERITY_RANK = {Severity.INFO: 0, Severity.MEDIUM: 1, Severity.HIGH: 2}


@dataclass(frozen=True)
class DetectorMeta:
    id: str
    title: str
    short: str  # few words for the table
    severity: Severity
    meaning: str
    signal: str
    min_evidence: str
    statistic: str
    false_positive_guard: str
    fix: str
    threshold_keys: tuple[str, ...] = ()
    timing: bool = True  # timing-based: degraded capture lowers its confidence
    cases: tuple[str, ...] = ()


@dataclass
class DetectorResult:
    status: Status
    confidence: float = 0.0
    p_value: float | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    reason: str | None = None
    caps: tuple[str, ...] = ()  # extra confidence caps that apply to this result


class Detector:
    meta: DetectorMeta

    def run(self, ctx: FlowContext) -> DetectorResult:  # pragma: no cover - interface
        raise NotImplementedError

    # helpers
    @staticmethod
    def fired(confidence: float, summary: str, evidence: dict, p_value: float | None = None, caps=()) -> DetectorResult:
        return DetectorResult(Status.FIRED, confidence, p_value, evidence, summary, None, tuple(caps))

    @staticmethod
    def not_fired(reason: str, evidence: dict | None = None, p_value: float | None = None) -> DetectorResult:
        return DetectorResult(Status.NOT_FIRED, 0.0, p_value, evidence or {}, "", reason)

    @staticmethod
    def insufficient(reason: str, evidence: dict | None = None, p_value: float | None = None) -> DetectorResult:
        return DetectorResult(Status.INSUFFICIENT, 0.0, p_value, evidence or {}, "", reason)

    @staticmethod
    def skipped(reason: str) -> DetectorResult:
        return DetectorResult(Status.SKIPPED, 0.0, None, {}, "", reason)


def keystroke_gate(ctx: FlowContext) -> DetectorResult | None:
    """Common minimum-evidence rule for keystroke detectors (cases S1, S2, S8)."""
    if not any(s.kind == "interactive" for s in ctx.segments):
        kinds = sorted({s.kind for s in ctx.segments} - {"handshake", "auth"})
        what = ", ".join(kinds) if kinds else "no traffic after authentication"
        return Detector.skipped(f"no interactive phase ({what})")
    ia = ctx.interactive
    need = ctx.th.global_.min_packets
    if ia.n_client < need:
        return Detector.insufficient(
            f"{ia.n_client} client keystroke packets in interactive phases, need {need}",
            {"client_packets": ia.n_client, "min_packets": need},
        )
    return None
