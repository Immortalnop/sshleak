"""The scan pipeline: frames -> decode -> flows -> phases -> detectors -> report.

The same code runs on a live capture, a saved pcap or lab-generated traffic;
detectors never know which.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field

import numpy as np
import psutil

from sshleak import SCHEMA_VERSION, __version__
from sshleak.capture.decode import DecodeStats, decode
from sshleak.capture.pcapfile import RawFrame
from sshleak.capture.sources import CaptureInfo
from sshleak.config.client import ConfigSkip, check_client
from sshleak.detectors.base import SEVERITY_RANK, Detector, Severity, Status
from sshleak.detectors.context import FlowContext, FlowMeta
from sshleak.detectors.registry import load_detectors
from sshleak.discovery.sockets import ProcInfo, SocketSnapshot, redact_cmdline
from sshleak.env import Virtualisation
from sshleak.exitcodes import ExitCode
from sshleak.findings.engine import evaluate
from sshleak.findings.report import (
    CaptureModel,
    FlowModel,
    PhaseModel,
    ProcessModel,
    Report,
    SummaryModel,
)
from sshleak.flows.tracker import FlowState, FlowTracker, Limits
from sshleak.kex import negotiate
from sshleak.phases.segmenter import segment
from sshleak.thresholds import Thresholds
from sshleak.versions import parse_software

FAIL_ON = ("high", "medium", "info", "none")
RELATIVE_TS_LIMIT_NS = 10**18  # before 2001-09-09: timestamps are relative (case C7)


@dataclass
class ScanOptions:
    mode: str = "pcap"  # live | pcap | lab
    only: set[str] | None = None
    min_packets: int | None = None
    redact: bool = True
    config_check: bool = False
    all_users: bool = False
    flow_filter: str | None = None
    target_nets: tuple | None = None
    fail_on: str = "high"
    virtualisation: Virtualisation = field(default_factory=lambda: Virtualisation(None))


@dataclass
class FlowAnalysis:
    flow: FlowState
    model: FlowModel
    ctx: FlowContext | None


def shape_identifies_ssh(flow: FlowState, th: Thresholds) -> bool:
    """Late-join fallback (G2): encrypted OpenSSH segment lengths are multiples of 4."""
    sh = th.shape
    ln = np.frombuffer(flow.ln, dtype=np.int32)
    if len(ln) < sh.min_segments:
        return False
    frac = float((ln % sh.modulus == 0).mean())
    return frac >= sh.min_fraction and float(np.median(ln)) <= sh.max_small_bytes


def _limits(th: Thresholds) -> tuple[Limits, str | None]:
    lim = Limits(
        max_records_per_flow=th.limits.max_records_per_flow,
        max_flows=th.limits.max_flows,
        clock_step_tolerance_ns=int(th.limits.clock_step_tolerance_ms * 1e6),
    )
    try:
        avail_mb = psutil.virtual_memory().available / 2**20
    except Exception:  # pragma: no cover - psutil always works on Linux
        avail_mb = float("inf")
    if avail_mb < th.limits.low_memory_mb:  # E6
        lim.max_records_per_flow //= 2
        lim.max_flows = max(1, lim.max_flows // 2)
        return lim, f"low memory ({avail_mb:.0f} MB free): per-flow and flow caps halved"
    return lim, None


class Pipeline:
    def __init__(self, th: Thresholds, opts: ScanOptions, detectors: list[Detector] | None = None):
        self.th = th.with_min_packets(opts.min_packets)
        self.opts = opts
        self.detectors = detectors if detectors is not None else load_detectors()
        limits, self.memory_note = _limits(self.th)
        self.tracker = FlowTracker(limits)
        self.decode_stats = DecodeStats()
        self.frames = 0
        self.first_ts: int | None = None
        self.snapshot: SocketSnapshot | None = None

    # -- ingestion ---------------------------------------------------------
    def ingest(self, frame: RawFrame) -> None:
        self.frames += 1
        if self.first_ts is None:
            self.first_ts = frame.ts_ns
        dec = decode(frame, self.decode_stats)
        if dec is not None:
            pkt, head = dec
            self.tracker.add(pkt, head)

    def add_snapshot(self, snap: SocketSnapshot) -> None:
        if self.snapshot is None:
            self.snapshot = snap
        else:
            self.snapshot.merge(snap)

    # -- analysis ----------------------------------------------------------
    def _proc_model(self, p: ProcInfo | None) -> ProcessModel | None:
        if p is None:
            return None
        return ProcessModel(name=p.name, pid=p.pid, own=p.owned_by_me(), cmdline=redact_cmdline(p, self.opts.redact))

    def _matches_filter(self, flow: FlowState, fid: str) -> bool:
        f = self.opts.flow_filter
        if not f:
            return True
        if f == fid:
            return True
        a = f"{flow.a[0]}:{flow.a[1]}"
        b = f"{flow.b[0]}:{flow.b[1]}"
        return f in (f"{a}-{b}", f"{b}-{a}")

    def _in_targets(self, flow: FlowState) -> bool:
        nets = self.opts.target_nets
        if not nets:
            return True
        for ip in (flow.a[0], flow.b[0]):
            addr = ipaddress.ip_address(ip)
            if any(addr.version == n.version and addr in n for n in nets):
                return True
        return False

    def analyse_flows(self, capture: CaptureInfo) -> tuple[list[FlowAnalysis], int, int]:
        th = self.th
        snap = self.snapshot
        owners = snap.owners if snap else {}
        listening = snap.listening if snap else None
        owner_names = snap.owner_names() if snap else None
        out: list[FlowAnalysis] = []
        hidden = not_ssh = 0
        cap_degraded: dict[str, str] = {}
        if capture.drops:
            cap_degraded["capture_drops"] = f"{capture.drops} packets dropped in capture"
        if capture.truncated:
            cap_degraded["truncated_input"] = f"input truncated ({capture.truncation_reason})"
        if capture.offload_warning:
            cap_degraded["offload"] = "segmentation offload may merge packets"
        if self.opts.mode == "live" and self.opts.virtualisation.virtualised:
            cap_degraded["virtualised"] = f"captured on {self.opts.virtualisation.kind}: timer resolution limited"
        euid = os.geteuid()
        for flow in self.tracker.all_flows():
            if flow.data_packets == 0:
                continue
            fid = f"f{flow.order}"
            if not self._matches_filter(flow, fid) or not self._in_targets(flow):
                continue
            status = flow.ssh_status()
            ident = "banner"
            if status == "not_ssh":
                not_ssh += 1
                continue
            if status == "unknown":
                proc_named = any(
                    owners.get(ep) is not None and (owners[ep].is_ssh_client or owners[ep].is_ssh_server)
                    for ep in (flow.a, flow.b)
                )
                if proc_named:
                    ident = "process"
                elif flow.late_join and shape_identifies_ssh(flow, th):
                    ident = "shape"
                else:
                    not_ssh += 1
                    continue
            cside, role_src = flow.resolve_client(listening, owner_names)
            client = flow.a if cside == "a" else flow.b
            server = flow.b if cside == "a" else flow.a
            cproc, sproc = owners.get(client), owners.get(server)
            if snap is not None and not self.opts.all_users:
                owner = cproc if cproc is not None and cproc.uid is not None else sproc
                if owner is None or owner.uid != euid:
                    hidden += 1
                    continue
            meta = FlowMeta(flow_id=fid, client=client, server=server, late_join=flow.late_join, identified_by=ident)
            meta.client_proc, meta.server_proc = cproc, sproc
            meta.process_info_available = snap is not None
            chs, shs = flow.hs[cside], flow.hs["b" if cside == "a" else "a"]
            if chs.banner:
                meta.client_sw = parse_software(chs.banner.software)
            if shs.banner:
                meta.server_sw = parse_software(shs.banner.software)
            meta.client_kex, meta.server_kex = chs.kexinit, shs.kexinit
            if chs.kexinit and shs.kexinit:
                meta.negotiated = negotiate(chs.kexinit, shs.kexinit)
            meta.degraded = dict(cap_degraded)
            if flow.late_join:
                meta.degraded["late_join"] = "flow started before the scan (late-join)"
            if ident == "shape":
                meta.degraded["shape_identified"] = "identified as SSH by packet-size shape only"
            if self.opts.config_check:
                if cproc is None:
                    meta.config_note = "client process not found on this host"
                else:
                    try:
                        meta.config = check_client(cproc)
                    except ConfigSkip as e:
                        meta.config_note = str(e)
            view = flow.view(cside, int(th.limits.clock_step_window_s * 1e9))
            if view.clock_steps:
                meta.degraded["clock_step"] = f"clock step during capture ({view.dropped_for_steps} records dropped)"
            segs, seg_stats = segment(view, th, late_join=flow.late_join)
            ctx = FlowContext(meta, view, segs, th)
            if any(s.kind == "mixed" for s in segs):
                mixed = sum(s.duration for s in segs if s.kind == "mixed")
                act = sum(s.duration for s in segs if s.kind in ("interactive", "bulk", "mixed"))
                if act > 0 and mixed / act >= 0.2:
                    meta.degraded["mixed_traffic"] = "mixed (forwarded) traffic in session"
            outcome = evaluate(ctx, self.detectors, self.opts.only)
            phases = []
            for s in segs:
                dd = view.direction[s.i0 : s.i1]
                phases.append(PhaseModel(kind=s.kind, start_s=round(s.t0, 3), end_s=round(s.t1, 3),
                                         client_packets=int((dd == 0).sum()), server_packets=int((dd == 1).sum())))
            neg = meta.negotiated
            model = FlowModel(
                id=fid,
                client=f"{client[0]}:{client[1]}" if ":" not in client[0] else f"[{client[0]}]:{client[1]}",
                server=f"{server[0]}:{server[1]}" if ":" not in server[0] else f"[{server[0]}]:{server[1]}",
                ip_version=6 if ":" in client[0] else 4,
                identified_by=ident,
                role_source=role_src,
                late_join=flow.late_join,
                client_software=chs.banner.software if chs.banner else None,
                server_software=shs.banner.software if shs.banner else None,
                negotiated={k: getattr(neg, k) for k in neg.__slots__} if neg else None,
                client_process=self._proc_model(cproc),
                server_process=self._proc_model(sproc),
                config=(meta.config.options | {"enabled": meta.config.enabled, "interval_ms": meta.config.interval_ms})
                if meta.config else None,
                config_note=meta.config_note,
                packets=flow.data_packets,
                bytes=flow.data_bytes,
                duration_s=round((flow.last_ts - flow.first_ts) / 1e9, 3),
                retransmits=flow.retransmits,
                reordered=flow.reordered,
                phases=phases,
                session_type=ctx.session.kind,
                degraded=sorted(meta.degraded.values()),
                score=outcome.score,
                findings=outcome.findings,
                checks=outcome.checks,
            )
            if seg_stats.rekey_events:
                model.degraded.append(f"{seg_stats.rekey_events} rekey window(s) excluded")
            out.append(FlowAnalysis(flow, model, ctx))
        self._link_reconnects(out)
        return out, hidden, not_ssh

    @staticmethod
    def _link_reconnects(flows: list[FlowAnalysis]) -> None:
        """F7: a client process that reconnects on a new port links its flows."""
        by_pid: dict[int, list[str]] = {}
        for fa in flows:
            p = fa.ctx.meta.client_proc if fa.ctx else None
            if p is not None:
                prev = by_pid.setdefault(p.pid, [])
                fa.model.linked_to = list(prev)
                prev.append(fa.model.id)

    def report(self, capture: CaptureInfo, run: dict | None = None) -> Report:
        flows, hidden, not_ssh = self.analyse_flows(capture)
        models = [f.model for f in flows]
        counts = {"high": 0, "medium": 0, "info": 0}
        skipped = insufficient = 0
        for m in models:
            for f in m.findings:
                counts[f.severity] += 1
            for c in m.checks:
                skipped += c.status == Status.SKIPPED.value
                insufficient += c.status == Status.INSUFFICIENT.value
        scores = [m.score for m in models if m.score is not None]
        code = self.exit_code(models)
        notes = list(capture.notes)
        if self.memory_note:
            notes.append(self.memory_note)
        if self.decode_stats.unsupported_linktypes:
            notes.append(f"unsupported link types skipped: {sorted(self.decode_stats.unsupported_linktypes)}")
        if self.tracker.stats.evicted:
            notes.append(f"{self.tracker.stats.evicted} flows evicted at the flow cap (use --flow to focus)")
        cap = CaptureModel(
            mode=capture.mode,
            source=capture.label,
            ts_source=capture.ts_source,
            ts_resolution_ns=capture.ts_resolution_ns,
            snaplen=capture.snaplen,
            frames=self.frames,
            tcp_packets=self.decode_stats.decoded,
            drops=capture.drops,
            truncated=capture.truncated,
            truncation_reason=capture.truncation_reason,
            offload_warning=capture.offload_warning,
            interrupted=capture.interrupted,
            clock_steps=self.tracker.stats.clock_steps,
            relative_timestamps=self.first_ts is not None and self.first_ts < RELATIVE_TS_LIMIT_NS,
            loopback_duplicates_dropped=self.decode_stats.loopback_duplicates,
            flows_evicted=self.tracker.stats.evicted,
            notes=notes,
        )
        virt = self.opts.virtualisation
        env = {
            "virtualisation": virt.kind if self.opts.mode == "live" else None,
            "confidence_cap": self.th.confidence_caps.virtualised if self.opts.mode == "live" and virt.virtualised else None,
        }
        return Report(
            schema_version=SCHEMA_VERSION,
            tool={"name": "sshleak", "version": __version__},
            thresholds={"version": self.th.version, "sha256": self.th.sha256, "calibrated": self.th.calibrated},
            environment=env,
            capture=cap,
            flows=models,
            summary=SummaryModel(
                score=min(scores) if scores else None,
                partial=skipped + insufficient > 0,
                findings=counts,
                checks_skipped=skipped,
                checks_insufficient=insufficient,
                flows_analysed=len(models),
                flows_hidden=hidden,
                flows_not_ssh=not_ssh,
                fail_on=self.opts.fail_on,
                exit_code=int(code),
            ),
            run=run,
        )

    def exit_code(self, models: list[FlowModel]) -> ExitCode:
        fail_on = self.opts.fail_on
        if fail_on != "none":
            need = SEVERITY_RANK[Severity(fail_on)]
            if any(SEVERITY_RANK[Severity(f.severity)] >= need for m in models for f in m.findings):
                return ExitCode.FINDINGS
        if self.opts.only and models:
            for det_id in self.opts.only:
                statuses = {c.status for m in models for c in m.checks if c.id == det_id}
                if not statuses & {Status.FIRED.value, Status.NOT_FIRED.value}:
                    return ExitCode.INSUFFICIENT
        return ExitCode.CLEAN
