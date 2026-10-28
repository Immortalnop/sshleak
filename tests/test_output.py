"""Output formats, determinism (D8), schema versioning (O2), non-TTY output (O1)."""

from __future__ import annotations

import json

import pytest

from sshleak.output.formats import to_json, to_jsonl, to_sarif, to_table
from sshleak.output.saved import load_report
from tests.conftest import run_cli


def test_D8_same_pcap_same_thresholds_identical_json(scenario_pcap):
    a = run_cli("scan", "--pcap", scenario_pcap("flawed"), "--format", "json")
    b = run_cli("scan", "--pcap", scenario_pcap("flawed"), "--format", "json")
    assert a.out == b.out and a.out.strip()
    data = json.loads(a.out)
    assert "run" not in data or data["run"] is None  # no wall-clock facts for pcap input


def test_json_schema_and_summary(analysed):
    rep, _ = analysed("unprotected")
    data = json.loads(to_json(rep))
    assert data["schema_version"] == "1.0"
    assert data["summary"]["exit_code"] == 1 and data["summary"]["fail_on"] == "high"
    assert data["thresholds"]["calibrated"] is False
    f = data["flows"][0]["findings"][0]
    assert {"id", "severity", "confidence", "evidence", "fix", "summary"} <= set(f)


def test_jsonl_lines(analysed):
    rep, _ = analysed("unprotected")
    lines = [json.loads(x) for x in to_jsonl(rep).splitlines()]
    assert lines[0]["type"] == "flow" and lines[-1]["type"] == "summary"
    assert sum(1 for x in lines if x["type"] == "finding") == len(rep.flows[0].findings)


def test_sarif_structure(analysed):
    rep, _ = analysed("flawed")
    sarif = json.loads(to_sarif(rep))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {f"L{i}" for i in range(1, 14)}
    l3 = next(r for r in run["results"] if r["ruleId"] == "L3")
    assert l3["level"] == "error" and l3["properties"]["confidence"] > 0


def test_O1_table_has_no_color_codes_off_tty(analysed):
    rep, _ = analysed("unprotected")
    out = to_table(rep, color=False)
    assert "\x1b[" not in out and "HIGH  L1" in out and "Score" in out
    cli = run_cli("scan", "--pcap", "/dev/null")  # not a pcap: error path, no colour either
    assert "\x1b[" not in cli.err


def test_O2_report_roundtrip_and_migrations(analysed, tmp_path):
    rep, _ = analysed("unprotected")
    data = json.loads(to_json(rep))
    same = tmp_path / "same.json"
    same.write_text(json.dumps(data))
    loaded = load_report(str(same))
    assert loaded.report is not None and loaded.warning is None and not loaded.read_only

    older = dict(data, schema_version="1.0")
    older["capture"] = {k: v for k, v in data["capture"].items() if k not in ("notes", "flows_evicted")}
    p = tmp_path / "older.json"
    p.write_text(json.dumps(older))
    assert load_report(str(p)).report is not None

    newer = dict(data, schema_version="1.7", future_field={"x": 1})
    newer["summary"] = dict(data["summary"], future_metric=3)
    p = tmp_path / "newer.json"
    p.write_text(json.dumps(newer))
    ld = load_report(str(p))
    assert ld.report is not None and ld.read_only and "newer" in ld.warning

    other = dict(data, schema_version="2.0")
    p = tmp_path / "other.json"
    p.write_text(json.dumps(other))
    ld = load_report(str(p))
    assert ld.report is None and ld.read_only and "major" in ld.warning
    res = run_cli("report", p)
    assert res.code == 0 and "warning" in res.err


def test_report_command_renders_saved(analysed, tmp_path):
    rep, _ = analysed("flawed")
    p = tmp_path / "r.json"
    p.write_text(to_json(rep))
    res = run_cli("report", p)
    assert res.code == 0 and "L3" in res.out


@pytest.mark.parametrize("fmt", ["table", "json", "jsonl", "sarif"])
def test_all_formats_via_cli(scenario_pcap, fmt):
    res = run_cli("scan", "--pcap", scenario_pcap("fixed"), "--format", fmt)
    assert res.code == 0 and res.out
