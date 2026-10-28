"""Report formatters: table, json, jsonl, sarif. All are pure functions of the report."""

from __future__ import annotations

import io
import json
import os
import sys
from importlib.metadata import entry_points
from typing import Callable

from rich.console import Console
from rich.markup import escape

from sshleak.detectors.registry import load_detectors
from sshleak.findings.report import Report

SEV_LABEL = {"high": "HIGH", "medium": "MED ", "info": "INFO"}
SEV_STYLE = {"high": "bold red", "medium": "yellow", "info": "cyan"}


def dumps(obj) -> str:
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def to_json(report: Report) -> str:
    return dumps(report.model_dump(mode="json"))


def to_jsonl(report: Report) -> str:
    data = report.model_dump(mode="json")
    lines = []
    for flow in data["flows"]:
        findings = flow.pop("findings")
        lines.append({"type": "flow", **flow})
        for f in findings:
            lines.append({"type": "finding", "flow": flow["id"], **f})
    lines.append({"type": "summary", **data["summary"], "schema_version": data["schema_version"]})
    return "".join(json.dumps(x, sort_keys=True, ensure_ascii=False) + "\n" for x in lines)


def to_sarif(report: Report) -> str:
    level = {"high": "error", "medium": "warning", "info": "note"}
    rules = []
    for d in load_detectors(include_plugins=False):
        m = d.meta
        rules.append({
            "id": m.id,
            "name": m.title.replace(" ", ""),
            "shortDescription": {"text": m.title},
            "fullDescription": {"text": m.meaning},
            "help": {"text": f"{m.meaning}\nFix: {m.fix}"},
            "defaultConfiguration": {"level": level[m.severity.value]},
        })
    results = []
    src = report.capture.source
    for flow in report.flows:
        for f in flow.findings:
            results.append({
                "ruleId": f.id,
                "level": level[f.severity],
                "message": {"text": f"{f.title}: {f.summary}. Fix: {f.fix}"},
                "locations": [{
                    "logicalLocations": [{
                        "name": f"{flow.client} -> {flow.server}",
                        "fullyQualifiedName": f"{report.capture.mode}:{src}/{flow.id}",
                        "kind": "resource",
                    }]
                }],
                "properties": {"confidence": f.confidence, "flow": flow.id, "evidence": f.evidence,
                               "degraded": f.degraded},
            })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "sshleak", "version": report.tool["version"],
                                "informationUri": "https://example.invalid/sshleak", "rules": rules}},
            "results": results,
            "properties": {"schema_version": report.schema_version, "score": report.summary.score},
        }],
    }
    return dumps(sarif)


def make_console(file=None, *, record: bool = False) -> Console:
    stream = file or sys.stdout
    tty = hasattr(stream, "isatty") and stream.isatty()
    no_color = not tty or "NO_COLOR" in os.environ
    return Console(file=stream, no_color=no_color, highlight=False, emoji=False, soft_wrap=True,
                   force_terminal=tty and not no_color, record=record, width=100 if not tty else None)


def to_table(report: Report, *, verbose: bool = False, color: bool | None = None) -> str:
    shorts = {d.meta.id: d.meta.short for d in load_detectors()}
    buf = io.StringIO()
    con = Console(file=buf, no_color=not color, highlight=False, emoji=False, soft_wrap=True,
                  force_terminal=bool(color), width=100)
    cap = report.capture
    con.print(f"sshleak {report.tool['version']}  {cap.mode}: {escape(cap.source)}  "
              f"thresholds {report.thresholds['version']}{'' if report.thresholds['calibrated'] else ' (provisional)'}")
    for note in ([cap.offload_warning] if cap.offload_warning else []) + cap.notes:
        con.print(f"  note: {escape(note)}")
    if cap.truncated:
        con.print(f"  note: input truncated ({escape(cap.truncation_reason or '')}); analysed the valid prefix")
    if cap.drops:
        con.print(f"  note: {cap.drops} packets dropped during capture")
    if cap.interrupted:
        con.print("  note: interrupted; partial results")
    if not report.flows:
        msg = "No SSH flows found"
        if report.summary.flows_hidden:
            msg += f" ({report.summary.flows_hidden} owned by other users hidden)"
        con.print(msg + ".")
    for flow in report.flows:
        cs = flow.client_software or "?"
        ss = flow.server_software or "?"
        tag = " late-join" if flow.late_join else ""
        con.print("")
        con.print(f" {flow.id}  {flow.client} -> {flow.server}  client {escape(cs)}  server {escape(ss)}  "
                  f"{flow.packets:,} pkts  {flow.session_type or ''}{tag}")
        if flow.degraded:
            con.print(f"  degraded: {escape('; '.join(flow.degraded))}")
        if not flow.findings:
            con.print("  no findings")
        for f in flow.findings:
            style = SEV_STYLE[f.severity] if color else ""
            label = SEV_LABEL[f.severity]
            short = shorts.get(f.id, f.title)
            line = f"  {label}  {f.id:<4} {short:<18} conf {f.confidence:.2f}   {escape(f.summary)}"
            con.print(f"[{style}]{line}[/{style}]" if style else line)
            con.print(f"        fix: {escape(f.fix)}")
        not_run = [c for c in flow.checks if c.status in ("skipped", "insufficient_evidence")]
        if verbose:
            for c in flow.checks:
                con.print(f"        {c.id:<4} {c.status:<22} {escape(c.reason or '')}")
        elif not_run:
            con.print(f"  checks not concluded: " + ", ".join(f"{c.id} ({c.status.replace('_evidence', '')})" for c in not_run))
        con.print(f"  score {flow.score:.0f}/100")
    s = report.summary
    nf = sum(s.findings.values())
    hidden = f", {s.flows_hidden} hidden (other users)" if s.flows_hidden else ""
    score = f"Score {s.score:.0f}/100" if s.score is not None else "Score n/a"
    con.print("")
    con.print(f"{score}  ({nf} findings, {s.checks_skipped} checks skipped, {s.checks_insufficient} insufficient; "
              f"{s.flows_analysed} flows{hidden})")
    return buf.getvalue()


FORMATTERS: dict[str, Callable[[Report], str]] = {
    "table": to_table,
    "json": to_json,
    "jsonl": to_jsonl,
    "sarif": to_sarif,
}


def formatter(name: str) -> Callable[[Report], str]:
    if name in FORMATTERS:
        return FORMATTERS[name]
    for ep in entry_points(group="sshleak.formatters"):
        if ep.name == name:
            return ep.load()
    raise KeyError(name)
