"""Everything a detector may read about one flow. No payload bytes."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property

from sshleak.analysis.interactive import Interactive, analyse
from sshleak.analysis.session import SessionType, classify
from sshleak.config.client import ClientConfig
from sshleak.discovery.sockets import ProcInfo
from sshleak.flows.tracker import Endpoint, FlowView
from sshleak.kex import KexInit, Negotiated
from sshleak.phases.segmenter import Segment
from sshleak.thresholds import Thresholds
from sshleak.versions import Software


@dataclass
class FlowMeta:
    flow_id: str
    client: Endpoint
    server: Endpoint
    client_sw: Software | None = None
    server_sw: Software | None = None
    client_kex: KexInit | None = None
    server_kex: KexInit | None = None
    negotiated: Negotiated | None = None
    late_join: bool = False
    identified_by: str = "banner"
    client_proc: ProcInfo | None = None
    server_proc: ProcInfo | None = None
    process_info_available: bool = False
    config: ClientConfig | None = None
    config_note: str | None = None
    degraded: dict[str, str] = field(default_factory=dict)  # cap key -> human reason


@dataclass
class FlowContext:
    meta: FlowMeta
    view: FlowView
    segments: list[Segment]
    th: Thresholds

    @cached_property
    def interactive(self) -> Interactive:
        return analyse(self.view, self.segments, self.th)

    @cached_property
    def session(self) -> SessionType:
        return classify(self.view, self.segments, self.th.phases.small_packet_max_bytes)
