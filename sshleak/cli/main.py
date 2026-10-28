"""sshleak command line."""

from __future__ import annotations

import datetime as dt
import os
import sys
import time
import traceback
from enum import Enum
from pathlib import Path
from typing import Optional

import click
import typer

from sshleak import __version__
from sshleak.errors import EnvironmentProblem, SafetyRefusal, SshleakError
from sshleak.exitcodes import ExitCode

app = typer.Typer(add_completion=False, pretty_exceptions_enable=False, no_args_is_help=True,
                  help="Passive, local detector for SSH keystroke timing and size leaks.")
lab_app = typer.Typer(no_args_is_help=True, help="Labelled traffic for calibration and tests (synthetic and Docker).")
app.add_typer(lab_app, name="lab")

LEGAL = ("sshleak captures packet metadata. Capturing other people's traffic without authorisation can be "
         "illegal. Only scan hosts and networks you own or have written permission to test.")


class Fmt(str, Enum):
    table = "table"
    json = "json"
    jsonl = "jsonl"
    sarif = "sarif"


class FailOn(str, Enum):
    high = "high"
    medium = "medium"
    info = "info"
    none = "none"


def _err(msg: str) -> None:
    typer.echo(msg, err=True)


def _first_run_notice() -> None:
    from sshleak.guard.guard import audit_log_path

    marker = audit_log_path().parent / "first-run-acknowledged"
    if marker.exists():
        return
    _err(f"notice: {LEGAL}")
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(dt.date.today().isoformat() + "\n")
    except OSError:
        pass


def _parse_only(only: Optional[str]) -> set[str] | None:
    if not only:
        return None
    from sshleak.detectors.registry import detector_ids

    ids = {x.strip().upper() for x in only.split(",") if x.strip()}
    known = set(detector_ids())
    bad = sorted(ids - known)
    if bad:
        raise EnvironmentProblem(f"unknown check id(s) in --only: {', '.join(bad)} (known: {', '.join(sorted(known))})")
    return ids


def _emit(report, fmt: Fmt, verbose: bool) -> None:
    from sshleak.output.formats import formatter, to_table

    if fmt is Fmt.table:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        sys.stdout.write(to_table(report, verbose=verbose, color=color))
    else:
        sys.stdout.write(formatter(fmt.value)(report))
    sys.stdout.flush()


def _build(*, pcap, iface, target, duration, flow, only, min_packets, redact, config_check, thresholds,
           fail_on, allow_nonlocal, scope, all_users, port):
    """Shared setup for scan / ci / watch / flows. Returns (pipeline, source, approved|None)."""
    from sshleak import thresholds as thr
    from sshleak.capture.sources import PcapSource, TcpdumpSource
    from sshleak.env import detect_virtualisation
    from sshleak.guard.guard import CaptureRequest, approve, parse_targets
    from sshleak.pipeline import Pipeline, ScanOptions

    th = thr.load(thresholds)
    opts = ScanOptions(only=_parse_only(only), min_packets=min_packets, redact=redact, config_check=config_check,
                       all_users=all_users, flow_filter=flow, fail_on=fail_on.value)
    if pcap:
        if iface is not None or allow_nonlocal or scope:
            raise EnvironmentProblem("--pcap reads a saved capture; do not combine it with --iface/--allow-nonlocal/--scope")
        if config_check:
            raise EnvironmentProblem("--config-check needs a live scan (it reads the local client process)")
        opts.mode = "pcap"
        opts.target_nets = parse_targets(target) if target else None
        return Pipeline(th, opts), PcapSource(pcap, redact=redact), None
    req = CaptureRequest(iface=iface or "lo", targets=target or ["127.0.0.1", "::1"],
                         allow_nonlocal=allow_nonlocal, scope_path=scope, all_users=all_users, ports=port or [])
    approved = approve(req)
    _first_run_notice()
    opts.mode = "live"
    opts.virtualisation = detect_virtualisation()
    return Pipeline(th, opts), TcpdumpSource(approved.iface, approved.bpf, duration=duration), approved


def _scan(fmt: Fmt, verbose: bool, **kw) -> int:
    from sshleak.discovery.sockets import snapshot

    pipeline, source, approved = _build(**kw)
    started = dt.datetime.now(dt.timezone.utc)
    t0 = time.monotonic()
    if approved is not None:
        pipeline.add_snapshot(snapshot())
    try:
        for frame in source.frames():
            if frame is not None:
                pipeline.ingest(frame)
    except KeyboardInterrupt:  # E5: partial results, clean shutdown
        source.stop()
        info = source.info()
        info.interrupted = True
    else:
        info = source.info()
    run = None
    if approved is not None:
        pipeline.add_snapshot(snapshot())
        run = {"started_at": started.isoformat(timespec="seconds"), "duration_s": round(time.monotonic() - t0, 2),
               "iface": approved.iface, "bpf": approved.bpf, "nonlocal": approved.nonlocal_}
    report = pipeline.report(info, run)
    _emit(report, fmt, verbose)
    return report.summary.exit_code


# ------------------------------------------------------------------ options
PcapOpt = typer.Option(None, "--pcap", help="Analyse a saved pcap/pcapng instead of capturing.")
IfaceOpt = typer.Option(None, "--iface", help="Capture interface (default lo).")
TargetOpt = typer.Option(None, "--target", help="Target address or network (repeatable; default 127.0.0.1 and ::1).")
DurationOpt = typer.Option(30.0, "--duration", min=0.5, help="Seconds to capture.")
FlowOpt = typer.Option(None, "--flow", help="Only this flow (id like f2, or ip:port-ip:port).")
OnlyOpt = typer.Option(None, "--only", help="Comma-separated check ids, e.g. L1,L3.")
MinPktOpt = typer.Option(None, "--min-packets", min=1, help="Override the minimum keystroke packets.")
FormatOpt = typer.Option(Fmt.table, "--format", help="Output format.")
RedactOpt = typer.Option(True, "--redact/--no-redact", help="Omit command lines and file paths (default on).")
ConfigOpt = typer.Option(False, "--config-check", help="Read the local client's effective ssh config (ssh -G).")
ThreshOpt = typer.Option(None, "--thresholds", help="Thresholds TOML (default: shipped file).")
NonlocalOpt = typer.Option(False, "--allow-nonlocal", help="Permit a non-loopback interface or target (needs --scope).")
ScopeOpt = typer.Option(None, "--scope", help="Scope file: owner, signed_off_by, expires, interfaces, targets.")
AllUsersOpt = typer.Option(False, "--all-users", help="Analyse other users' flows (root only).")
PortOpt = typer.Option(None, "--port", help="Restrict capture to this TCP port (repeatable).")
VerboseOpt = typer.Option(False, "--verbose", "-v", help="Show every check's status and reason.")


@app.command()
def scan(
    pcap: Optional[Path] = PcapOpt, iface: Optional[str] = IfaceOpt, target: Optional[list[str]] = TargetOpt,
    duration: float = DurationOpt, flow: Optional[str] = FlowOpt, only: Optional[str] = OnlyOpt,
    min_packets: Optional[int] = MinPktOpt, format: Fmt = FormatOpt, redact: bool = RedactOpt,
    config_check: bool = ConfigOpt, thresholds: Optional[Path] = ThreshOpt,
    fail_on: FailOn = typer.Option(FailOn.high, "--fail-on", help="Exit 1 at or above this severity."),
    allow_nonlocal: bool = NonlocalOpt, scope: Optional[Path] = ScopeOpt, all_users: bool = AllUsersOpt,
    port: Optional[list[int]] = PortOpt, verbose: bool = VerboseOpt,
) -> int:
    """One-shot passive scan of live flows (default: loopback for 30 s), or of a saved capture."""
    return _scan(format, verbose, pcap=pcap, iface=iface, target=target, duration=duration, flow=flow, only=only,
                 min_packets=min_packets, redact=redact, config_check=config_check, thresholds=thresholds,
                 fail_on=fail_on, allow_nonlocal=allow_nonlocal, scope=str(scope) if scope else None,
                 all_users=all_users, port=port)


@app.command()
def ci(
    pcap: Optional[Path] = PcapOpt, iface: Optional[str] = IfaceOpt, target: Optional[list[str]] = TargetOpt,
    duration: float = DurationOpt, only: Optional[str] = OnlyOpt, min_packets: Optional[int] = MinPktOpt,
    format: Fmt = typer.Option(Fmt.json, "--format", help="Output format (default json)."),
    thresholds: Optional[Path] = ThreshOpt,
    fail_on: FailOn = typer.Option(FailOn.high, "--fail-on", help="Exit 1 at or above this severity."),
) -> int:
    """Pipeline gate: scan, then exit non-zero at or above --fail-on."""
    return _scan(format, False, pcap=pcap, iface=iface, target=target, duration=duration, flow=None, only=only,
                 min_packets=min_packets, redact=True, config_check=False, thresholds=thresholds, fail_on=fail_on,
                 allow_nonlocal=False, scope=None, all_users=False, port=None)


@app.command()
def watch(
    pcap: Optional[Path] = PcapOpt, iface: Optional[str] = IfaceOpt, target: Optional[list[str]] = TargetOpt,
    duration: Optional[float] = typer.Option(None, "--duration", min=0.5, help="Stop after this many seconds (default: until Ctrl-C)."),
    interval: float = typer.Option(5.0, "--interval", min=0.5, help="Seconds between evaluations."),
    only: Optional[str] = OnlyOpt, min_packets: Optional[int] = MinPktOpt,
    format: str = typer.Option("table", "--format", help="table or jsonl"),
    thresholds: Optional[Path] = ThreshOpt, allow_nonlocal: bool = NonlocalOpt, scope: Optional[Path] = ScopeOpt,
    port: Optional[list[int]] = PortOpt,
) -> int:
    """Continuous: emit a finding the first time evidence is sufficient, then update it."""
    from sshleak.discovery.sockets import snapshot
    from sshleak.watch import Watcher, event_line

    if format not in ("table", "jsonl"):
        raise EnvironmentProblem("watch supports --format table or jsonl")
    pipeline, source, approved = _build(pcap=pcap, iface=iface, target=target, duration=duration, flow=None, only=only,
                                        min_packets=min_packets, redact=True, config_check=False,
                                        thresholds=thresholds, fail_on=FailOn.high, allow_nonlocal=allow_nonlocal,
                                        scope=str(scope) if scope else None, all_users=False, port=port)

    def emit(ev: dict) -> None:
        print(event_line(ev, format), flush=True)

    if approved is not None:
        pipeline.add_snapshot(snapshot())
    w = Watcher(pipeline, emit, interval)
    try:
        report = w.run(source.frames(), source.info, packet_clock=approved is None)
    except KeyboardInterrupt:
        source.stop()
        report = w.evaluate(source.info(), 0.0)
    s = report.summary
    tail = {"type": "summary", "score": s.score, "findings": s.findings, "flows": s.flows_analysed,
            "exit_code": s.exit_code}
    if format == "jsonl":
        print(event_line(tail, "jsonl"))
    else:
        print(f"done: {sum(s.findings.values())} findings in {s.flows_analysed} flows; score "
              f"{'n/a' if s.score is None else f'{s.score:.0f}/100'}")
    return s.exit_code


@app.command()
def flows(
    pcap: Optional[Path] = PcapOpt, iface: Optional[str] = IfaceOpt, target: Optional[list[str]] = TargetOpt,
    duration: float = typer.Option(5.0, "--duration", min=0.5, help="Seconds to capture."),
    format: Fmt = typer.Option(Fmt.table, "--format"), redact: bool = RedactOpt,
) -> int:
    """List discovered SSH flows: ports, versions, process, phase, packets seen."""
    import json

    from sshleak.capture.sources import CaptureInfo
    from sshleak.discovery.sockets import snapshot
    from sshleak.errors import EnvironmentProblem as EP

    rows = []
    try:
        pipeline, source, approved = _build(pcap=pcap, iface=iface, target=target, duration=duration, flow=None,
                                            only="L12", min_packets=None, redact=redact, config_check=False,
                                            thresholds=None, fail_on=FailOn.none, allow_nonlocal=False, scope=None,
                                            all_users=False, port=None)
        if approved is not None:
            pipeline.add_snapshot(snapshot())
        for frame in source.frames():
            if frame is not None:
                pipeline.ingest(frame)
        report = pipeline.report(source.info())
        for f in report.flows:
            rows.append({
                "id": f.id, "client": f.client, "server": f.server, "client_software": f.client_software,
                "server_software": f.server_software, "identified_by": f.identified_by, "late_join": f.late_join,
                "process": (f.client_process.name if f.client_process else None),
                "last_phase": f.phases[-1].kind if f.phases else None, "packets": f.packets,
            })
        hidden = report.summary.flows_hidden
        note = None
    except EP as e:
        if pcap or e.case != "E1":
            raise
        # No capture rights: fall back to the socket table (process-identified flows only).
        snap = snapshot()
        hidden = 0
        note = f"capture unavailable ({e.message}); listing sockets owned by ssh/sshd only"
        for local, remote in snap.established:
            p = snap.owners.get(local)
            if p and (p.is_ssh_client or p.is_ssh_server) and p.owned_by_me():
                rows.append({"id": "-", "client": f"{local[0]}:{local[1]}", "server": f"{remote[0]}:{remote[1]}",
                             "client_software": None, "server_software": None, "identified_by": "process",
                             "late_join": True, "process": p.name, "last_phase": None, "packets": 0})
    if format is Fmt.table:
        if note:
            _err("note: " + note)
        if not rows:
            print("No SSH flows found." + (f" ({hidden} hidden: other users)" if hidden else ""))
        for r in rows:
            print(f"{r['id']:<4} {r['client']:<24} -> {r['server']:<24} {r['client_software'] or '?':<18} "
                  f"{r['server_software'] or '?':<18} {r['identified_by']:<8} {r['process'] or '-':<8} "
                  f"{r['last_phase'] or '-':<12} {r['packets']:>8} pkts" + (" late-join" if r["late_join"] else ""))
    else:
        print(json.dumps({"flows": rows, "hidden": hidden, "note": note}, sort_keys=True, indent=2))
    return 0


@app.command()
def explain(check_id: str = typer.Argument(..., help="Check id, e.g. L3.")) -> int:
    """Print what a finding means, its evidence rule and its fix."""
    from sshleak.detectors.registry import load_detectors

    want = check_id.strip().upper()
    for d in load_detectors():
        m = d.meta
        if m.id == want:
            print(f"{m.id}  {m.title}  [{m.severity.value}]")
            print(f"\nMeaning:   {m.meaning}")
            print(f"Signal:    {m.signal}")
            print(f"Evidence:  {m.min_evidence}")
            print(f"Statistic: {m.statistic}")
            print(f"FP guard:  {m.false_positive_guard}")
            if m.threshold_keys:
                print(f"Thresholds: {', '.join(m.threshold_keys)} (thresholds.toml)")
            if m.cases:
                print(f"Cases:     {', '.join(m.cases)}")
            print(f"\nFix:       {m.fix}")
            return 0
    raise EnvironmentProblem(f"unknown check id {check_id!r}; known: L1-L13")


@app.command()
def doctor() -> int:
    """Check capture rights, kernel, offload, clock, OpenSSH versions and tools."""
    from sshleak.doctor import FAIL, run_checks

    checks = run_checks()
    for c in checks:
        print(f"[{c.status:^4}] {c.name:<17} {c.detail}")
        if c.fix and c.status != "ok":
            for line in c.fix.splitlines():
                print(f"{'':24}{line}")
    return ExitCode.ENVIRONMENT if any(c.status == FAIL for c in checks) else ExitCode.CLEAN


@app.command()
def report(path: Path = typer.Argument(..., help="Saved JSON report."),
           format: Fmt = typer.Option(Fmt.table, "--format")) -> int:
    """Show a saved JSON report (migrates older schema versions, read-only for newer ones)."""
    import json

    from sshleak.output.saved import load_report

    loaded = load_report(str(path))
    if loaded.warning:
        _err("warning: " + loaded.warning)
    if loaded.report is None:
        s = loaded.raw.get("summary", {})
        print(json.dumps({"schema_version": loaded.raw.get("schema_version"), "summary": s}, indent=2, sort_keys=True))
        return 0
    _emit(loaded.report, format, False)
    return 0


@app.command()
def selftest(
    docker: bool = typer.Option(True, "--docker/--no-docker", help="Also run real OpenSSH sessions in Docker."),
    build: bool = typer.Option(False, "--build", help="Build the lab image if it is missing."),
    keep: Optional[Path] = typer.Option(None, "--keep", help="Keep generated captures in this directory."),
) -> int:
    """Run labelled leaky and safe sessions and check every detector's outcome."""
    from sshleak.lab.selftest import run_selftest

    return run_selftest(docker=docker, build=build, keep=keep)


@app.command()
def version() -> int:
    """Print the version."""
    print(f"sshleak {__version__}")
    return 0


# ------------------------------------------------------------------ lab
@lab_app.command("list")
def lab_list() -> int:
    """List synthetic and Docker scenarios."""
    from sshleak.lab.docker_lab import DOCKER_SCENARIOS
    from sshleak.lab.scenarios import catalogue

    for sc in catalogue():
        print(f"synth   {sc.name:<24} {','.join(sc.cases):<16} {sc.description}")
    for sc in DOCKER_SCENARIOS:
        print(f"docker  {sc.name:<24} {','.join(sc.cases):<16} {sc.description}")
    return 0


@lab_app.command("synth")
def lab_synth(name: str = typer.Argument(..., help="Scenario name, or 'all'."),
              out: Path = typer.Option(Path("lab-out"), "--out", help="Output directory.")) -> int:
    """Write synthetic labelled captures (test traffic only)."""
    import json
    from dataclasses import asdict

    from sshleak.lab.scenarios import by_name, catalogue, write_scenario

    scs = catalogue() if name == "all" else [by_name(name)]
    for sc in scs:
        labels = write_scenario(sc, out / f"{sc.name}.pcap")
        (out / f"{sc.name}.labels.json").write_text(json.dumps(
            {"scenario": sc.name, "cases": sc.cases, "expect": sc.expect, "sessions": [asdict(x) for x in labels]},
            indent=2, sort_keys=True) + "\n")
        print(out / f"{sc.name}.pcap")
    return 0


@lab_app.command("build")
def lab_build(no_cache: bool = typer.Option(False, "--no-cache")) -> int:
    """Build the Docker lab image (vanilla OpenSSH builds, SHA256-pinned)."""
    from sshleak.lab.docker_lab import build_image

    build_image(no_cache=no_cache)
    return 0


@lab_app.command("run")
def lab_run(name: str = typer.Argument(..., help="Docker scenario name, or 'all'."),
            out: Path = typer.Option(Path("lab-out"), "--out"),
            seed: int = typer.Option(1, "--seed"), jobs: int = typer.Option(3, "--jobs", min=1)) -> int:
    """Run real OpenSSH sessions in an isolated container and save labelled captures."""
    from sshleak.lab.docker_lab import DOCKER_SCENARIOS, run_many

    scs = DOCKER_SCENARIOS if name == "all" else [s for s in DOCKER_SCENARIOS if s.name == name]
    if not scs:
        raise EnvironmentProblem(f"unknown docker scenario {name!r} (see 'sshleak lab list')")
    for path in run_many(scs, out, seed=seed, jobs=jobs):
        print(path)
    return 0


@lab_app.command("matrix")
def lab_matrix(out: Path = typer.Option(Path("lab-matrix"), "--out"),
               seeds: int = typer.Option(3, "--seeds", min=1), docker: bool = typer.Option(True, "--docker/--no-docker"),
               jobs: int = typer.Option(3, "--jobs", min=1)) -> int:
    """Run the full labelled matrix (synthetic x seeds, plus Docker sessions) and score detectors."""
    from sshleak.lab.calibrate import run_matrix

    return run_matrix(out, seeds=seeds, docker=docker, jobs=jobs)


@lab_app.command("calibrate")
def lab_calibrate(matrix: Path = typer.Option(Path("lab-matrix"), "--matrix"),
                  out: Path = typer.Option(Path("thresholds.candidate.toml"), "--out")) -> int:
    """Fit candidate thresholds from a matrix run (for your acceptance; never applied automatically)."""
    from sshleak.lab.calibrate import fit

    return fit(matrix, out)


# ------------------------------------------------------------------ entry
def run(argv: list[str] | None = None) -> None:
    sys.exit(main(argv))


def main(argv: list[str] | None = None) -> int:
    try:
        rv = app(args=argv, standalone_mode=False, prog_name="sshleak")
    except click.exceptions.UsageError as e:  # invocation errors share exit 3 so 2 always means "insufficient"
        e.show()
        return ExitCode.ENVIRONMENT
    except click.exceptions.Abort:
        _err("aborted")
        return ExitCode.ENVIRONMENT
    except SafetyRefusal as e:
        _err(f"refused{f' ({e.case})' if e.case else ''}: {e.message}")
        if e.fix:
            _err(e.fix)
        return ExitCode.SAFETY
    except SshleakError as e:
        _err(f"error{f' ({e.case})' if e.case else ''}: {e.message}")
        if e.fix:
            _err(e.fix)
        return int(e.exit_code)
    except KeyboardInterrupt:
        _err("interrupted")
        return ExitCode.ENVIRONMENT
    except Exception:  # never silent
        _err("internal error (please report):")
        _err(traceback.format_exc())
        return ExitCode.INTERNAL
    if isinstance(rv, int):
        return int(rv)
    return ExitCode.CLEAN


if __name__ == "__main__":  # pragma: no cover
    run()
