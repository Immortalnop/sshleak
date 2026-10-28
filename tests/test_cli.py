"""CLI commands and exit codes."""

from __future__ import annotations

import json

import pytest

from tests.conftest import run_cli


def test_exit_codes_fail_on(scenario_pcap):
    p = scenario_pcap("unprotected")  # high + medium findings
    assert run_cli("scan", "--pcap", p).code == 1
    assert run_cli("scan", "--pcap", p, "--fail-on", "none").code == 0
    p2 = scenario_pcap("fixed")  # medium (L6) + info only
    assert run_cli("scan", "--pcap", p2, "--fail-on", "high").code == 0
    assert run_cli("scan", "--pcap", p2, "--fail-on", "medium").code == 1


def test_ci_gate(scenario_pcap):
    res = run_cli("ci", "--pcap", scenario_pcap("flawed"), "--fail-on", "high")
    assert res.code == 1 and json.loads(res.out)["summary"]["findings"]["high"] >= 1
    assert run_cli("ci", "--pcap", scenario_pcap("fixed"), "--fail-on", "high").code == 0


def test_only_filters_checks(scenario_pcap):
    res = run_cli("scan", "--pcap", scenario_pcap("unprotected"), "--only", "L1,L11", "--format", "json")
    ids = {c["id"] for c in json.loads(res.out)["flows"][0]["checks"]}
    assert ids == {"L1", "L11"}
    assert run_cli("scan", "--pcap", scenario_pcap("unprotected"), "--only", "L99").code == 3


def test_min_packets_override(scenario_pcap):
    res = run_cli("scan", "--pcap", scenario_pcap("few_packets"), "--min-packets", "5", "--only", "L1", "--format", "json")
    st = json.loads(res.out)["flows"][0]["checks"][0]["status"]
    assert st != "insufficient_evidence"


def test_usage_error_is_exit_3():
    assert run_cli("scan", "--duration", "-1").code == 3
    assert run_cli("nosuchcommand").code == 3


def test_pcap_and_iface_conflict(scenario_pcap):
    assert run_cli("scan", "--pcap", scenario_pcap("fixed"), "--iface", "lo").code == 3


def test_missing_pcap_exit_3(tmp_path):
    res = run_cli("scan", "--pcap", tmp_path / "nope.pcap")
    assert res.code == 3 and "not found" in res.err


@pytest.mark.parametrize("det", [f"L{i}" for i in range(1, 14)])
def test_explain_every_check(det):
    res = run_cli("explain", det.lower())
    assert res.code == 0 and det in res.out and "Fix:" in res.out and "Statistic:" in res.out


def test_explain_unknown():
    assert run_cli("explain", "L42").code == 3


def test_doctor_runs():
    res = run_cli("doctor")
    assert res.code in (0, 3) and "capture" in res.out and "thresholds" in res.out


def test_flows_command_on_pcap(scenario_pcap):
    res = run_cli("flows", "--pcap", scenario_pcap("flow_ends"), "--format", "json")
    rows = json.loads(res.out)["flows"]
    assert len(rows) == 2 and rows[0]["client_software"] == "OpenSSH_9.4"


def test_watch_emits_new_then_summary(scenario_pcap):
    res = run_cli("watch", "--pcap", scenario_pcap("unprotected"), "--interval", "5", "--format", "jsonl")
    events = [json.loads(x) for x in res.out.splitlines()]
    new = [e for e in events if e.get("event") == "new"]
    assert {e["id"] for e in new} >= {"L1", "L11"}
    assert events[-1]["type"] == "summary"
    # each finding is announced once as new; later lines are updates
    ids = [e["id"] for e in new]
    assert len(ids) == len(set(ids))


def test_version():
    assert run_cli("version").out.startswith("sshleak ")


def test_lab_synth_writes_labels(tmp_path):
    res = run_cli("lab", "synth", "flawed", "--out", tmp_path)
    assert res.code == 0
    labels = json.loads((tmp_path / "flawed.labels.json").read_text())
    assert labels["expect"]["0"]["L3"] == "fired" and labels["sessions"][0]["flawed"] is True


def test_lab_list():
    res = run_cli("lab", "list")
    assert "d_flawed" in res.out and "unprotected" in res.out
