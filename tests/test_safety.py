"""Safety guard (P1-P4) and the payload rules (D2, decision G1)."""

from __future__ import annotations

import datetime as dt
import gc
import types
import json
import re
from pathlib import Path

import pytest

from sshleak.env import iface_is_loopback
from sshleak.errors import SafetyRefusal
from sshleak.guard.guard import CaptureRequest, approve, build_bpf, load_scope, parse_targets
from sshleak.lab.scenarios import by_name, write_scenario
from sshleak.lab.analyse import analyse_file
from sshleak.pipeline import Pipeline, ScanOptions
from sshleak.capture.sources import PcapSource
from tests.conftest import run_cli

SRC = Path(__file__).resolve().parent.parent / "sshleak"


def _nonloopback_iface() -> str | None:
    for p in sorted(Path("/sys/class/net").iterdir()):
        if not iface_is_loopback(p.name):
            return p.name
    return None


def _scope(tmp_path, **over) -> Path:
    vals = {"owner": "Test Lab", "signed_off_by": "tester", "expires": "2099-01-01",
            "interfaces": '["lo"]', "targets": '["192.0.2.0/24"]'} | over
    p = tmp_path / "scope.toml"
    p.write_text("[scope]\n" + "\n".join(
        f'{k} = {v}' if k in ("expires", "interfaces", "targets") else f'{k} = "{v}"' for k, v in vals.items()) + "\n")
    return p


def test_default_loopback_is_allowed():
    ok = approve(CaptureRequest())
    assert ok.iface == "lo" and not ok.nonlocal_
    assert ok.bpf == "tcp and (host 127.0.0.1 or host ::1)"


def test_P1_nonloopback_iface_refused():
    iface = _nonloopback_iface()
    if iface is None:
        pytest.skip("no non-loopback interface on this host")
    with pytest.raises(SafetyRefusal) as e:
        approve(CaptureRequest(iface=iface))
    assert e.value.case == "P1"
    res = run_cli("scan", "--iface", iface, "--duration", "1")
    assert res.code == 4 and "refused" in res.err


def test_P1_nonloopback_target_on_lo_refused():
    with pytest.raises(SafetyRefusal):
        approve(CaptureRequest(targets=["192.0.2.10"]))


def test_P2_scope_missing_refused(tmp_path):
    with pytest.raises(SafetyRefusal) as e:
        approve(CaptureRequest(targets=["192.0.2.10"], allow_nonlocal=True))
    assert e.value.case == "P2"
    with pytest.raises(SafetyRefusal):
        approve(CaptureRequest(targets=["192.0.2.10"], allow_nonlocal=True, scope_path=str(tmp_path / "nope.toml")))


def test_P2_target_not_in_scope_refused(tmp_path):
    scope = _scope(tmp_path)
    with pytest.raises(SafetyRefusal) as e:
        approve(CaptureRequest(targets=["198.51.100.7"], allow_nonlocal=True, scope_path=str(scope)))
    assert "not covered" in e.value.message


def test_P2_invalid_scope_refused(tmp_path):
    p = tmp_path / "scope.toml"
    p.write_text("[scope]\nowner = 'x'\n")
    with pytest.raises(SafetyRefusal):
        load_scope(str(p))


def test_P3_scope_expired_refused(tmp_path):
    scope = _scope(tmp_path, expires="2020-01-01")
    with pytest.raises(SafetyRefusal) as e:
        approve(CaptureRequest(targets=["192.0.2.10"], allow_nonlocal=True, scope_path=str(scope)))
    assert e.value.case == "P3"
    res = run_cli("scan", "--target", "192.0.2.10", "--allow-nonlocal", "--scope", scope, "--duration", "1")
    assert res.code == 4


def test_valid_scope_is_approved_and_audited(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    scope = _scope(tmp_path)
    ok = approve(CaptureRequest(targets=["192.0.2.10"], allow_nonlocal=True, scope_path=str(scope)),
                 today=dt.date(2026, 10, 27))
    assert ok.nonlocal_ and ok.scope.owner == "Test Lab"
    log = (tmp_path / "state" / "sshleak" / "audit.jsonl").read_text().splitlines()
    entry = json.loads(log[-1])
    assert entry["targets"] == ["192.0.2.10/32"] and entry["scope_sha256"] == ok.scope.sha256


def test_P4_no_option_saves_payloads():
    from sshleak.cli.main import app
    import typer.main

    cmd = typer.main.get_command(app)
    names = []

    def walk(c):
        for p in getattr(c, "params", []):
            names.extend(p.opts)
        for sub in getattr(c, "commands", {}).values():
            walk(sub)

    walk(cmd)
    bad = [n for n in names if re.search(r"payload|save|dump|write|--out$", n) and n not in ("--out",)]
    assert not bad, bad
    res = run_cli("scan", "--save-payload", "x.pcap")
    assert res.code == 3  # the option does not exist


def test_bpf_cannot_be_injected():
    with pytest.raises(SafetyRefusal):
        parse_targets(["127.0.0.1 or host 8.8.8.8"])
    assert build_bpf(parse_targets(["::1", "127.0.0.0/8"]), [22]) == "tcp and (host ::1 or net 127.0.0.0/8) and (port 22)"


def test_all_users_requires_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    with pytest.raises(SafetyRefusal):
        approve(CaptureRequest(all_users=True))


MARKER = b"SECRETPAYLOADMARKER!"


def _bytes_reachable(roots) -> list[bytes]:
    seen, found, stack = set(), [], list(roots)
    while stack:
        obj = stack.pop()
        if id(obj) in seen:
            continue
        seen.add(id(obj))
        if isinstance(obj, (bytes, bytearray)):
            found.append(bytes(obj))
            continue
        if isinstance(obj, memoryview):
            found.append(obj.tobytes() if not obj.released else b"")
            continue
        if isinstance(obj, (int, float, str, type(None), bool, type, types.ModuleType, types.FunctionType,
                            types.BuiltinFunctionType, types.MethodType)):
            continue  # code and constants, not data held by the pipeline
        stack.extend(gc.get_referents(obj))
    return found


def test_D2_payload_never_stored(tmp_path, th):
    """Encrypted payload bytes are discarded at parse: nothing reachable from the
    pipeline or the report contains them (decision G1)."""
    path = tmp_path / "marker.pcap"
    write_scenario(by_name("flawed"), path, marker=MARKER)
    pipeline = Pipeline(th, ScanOptions())
    src = PcapSource(path)
    for frame in src.frames():
        pipeline.ingest(frame)
    report = pipeline.report(src.info())
    blobs = _bytes_reachable([pipeline.tracker, report])
    assert not any(MARKER in b for b in blobs)
    assert MARKER.decode() not in report.model_dump_json()
    # banner + algorithm names are kept (G1), nothing else
    flow = pipeline.tracker.all_flows()[0]
    assert all(not h.active and len(h._buf) == 0 for h in flow.hs.values())


def test_D2_no_code_path_logs_payload():
    """Grep: payload views may only be touched by the decoder and the handshake parser."""
    allowed = {"capture/decode.py", "flows/handshake.py", "flows/tracker.py", "pipeline.py"}
    offenders = []
    for py in SRC.rglob("*.py"):
        rel = py.relative_to(SRC).as_posix()
        text = py.read_text()
        if rel.startswith("lab/"):
            continue  # synthetic generator builds its own test payloads
        if re.search(r"\bhead\b\s*[\[\.]", text) and rel not in allowed:
            offenders.append(rel)
        for m in re.finditer(r"(print|log\w*|\.write)\(([^)]*)\)", text):
            if re.search(r"\b(head|payload|_buf|chunk)\b", m.group(2)):
                offenders.append(f"{rel}: {m.group(0)}")
    assert not offenders, offenders


def test_redaction_default_hides_paths(tmp_path, th):
    path = tmp_path / "secret-dir" / "x.pcap"
    write_scenario(by_name("unprotected"), path)
    res = run_cli("scan", "--pcap", path, "--format", "json")
    assert "secret-dir" not in res.out
    res2 = run_cli("scan", "--pcap", path, "--format", "json", "--no-redact")
    assert "secret-dir" in res2.out
