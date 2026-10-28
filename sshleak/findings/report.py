"""Versioned report schema (Pydantic). Same input + thresholds -> identical JSON."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FindingModel(_M):
    id: str
    title: str
    severity: str
    confidence: float
    p_value: float | None = None
    summary: str
    evidence: dict[str, Any]
    fix: str
    degraded: list[str] = []


class CheckModel(_M):
    id: str
    status: str
    reason: str | None = None


class PhaseModel(_M):
    kind: str
    start_s: float
    end_s: float
    client_packets: int
    server_packets: int


class ProcessModel(_M):
    name: str
    pid: int | None
    own: bool
    cmdline: list[str] = []


class FlowModel(_M):
    id: str
    client: str
    server: str
    ip_version: int
    identified_by: str
    role_source: str
    late_join: bool
    client_software: str | None = None
    server_software: str | None = None
    negotiated: dict[str, Any] | None = None
    client_process: ProcessModel | None = None
    server_process: ProcessModel | None = None
    config: dict[str, Any] | None = None
    config_note: str | None = None
    packets: int
    bytes: int
    duration_s: float
    retransmits: int
    reordered: int
    phases: list[PhaseModel]
    session_type: str | None = None
    degraded: list[str] = []
    linked_to: list[str] = []
    score: float | None = None
    findings: list[FindingModel] = []
    checks: list[CheckModel] = []


class CaptureModel(_M):
    mode: str
    source: str
    ts_source: str
    ts_resolution_ns: int | None = None
    snaplen: int | None = None
    frames: int = 0
    tcp_packets: int = 0
    drops: int | None = None
    truncated: bool = False
    truncation_reason: str | None = None
    offload_warning: str | None = None
    interrupted: bool = False
    clock_steps: int = 0
    relative_timestamps: bool = False
    loopback_duplicates_dropped: int = 0
    flows_evicted: int = 0
    notes: list[str] = []


class SummaryModel(_M):
    score: float | None
    partial: bool
    findings: dict[str, int]
    checks_skipped: int
    checks_insufficient: int
    flows_analysed: int
    flows_hidden: int
    flows_not_ssh: int
    fail_on: str
    exit_code: int


class Report(_M):
    schema_version: str
    tool: dict[str, str]
    thresholds: dict[str, Any]
    environment: dict[str, Any]
    capture: CaptureModel
    flows: list[FlowModel]
    summary: SummaryModel
    run: dict[str, Any] | None = None  # wall-clock facts; live mode only (keeps pcap output deterministic)
