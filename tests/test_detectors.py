"""Detectors L1-L13 against labelled scenarios; session shapes S1-S8; versions V1-V6."""

from __future__ import annotations

import numpy as np
import pytest

from sshleak.analysis.interactive import detect_cadence
from sshleak.lab.analyse import mismatches
from sshleak.lab.scenarios import by_name, catalogue
from tests.conftest import finding, statuses

ALL = [sc.name for sc in catalogue()]


@pytest.mark.parametrize("name", ALL)
def test_scenario_expectations(name, analysed):
    sc = by_name(name)
    rep, _ = analysed(name)
    probs, _ = mismatches(rep, sc.expect, sc.expect_flows)
    assert not probs, probs


def test_every_detector_returns_a_defined_status(analysed):
    rep, _ = analysed("unprotected")
    assert {c.status for c in rep.flows[0].checks} <= {"fired", "not_fired", "insufficient_evidence", "skipped"}
    assert len(rep.flows[0].checks) == 13
    for c in rep.flows[0].checks:
        if c.status != "fired":
            assert c.reason, c.id


# ---- cadence statistic
def test_cadence_found_on_grid(th):
    rng = np.random.default_rng(1)
    gaps = 0.02 * rng.choice([1, 2, 3], 300, p=[0.8, 0.15, 0.05]) + rng.normal(0, 0.0003, 300)
    cad = detect_cadence(gaps, th)
    assert cad.present and abs(cad.interval_ms - 20) < 1


def test_cadence_peak_on_multiple_recovers_interval(th):
    """Even when 2T gaps dominate the histogram, the grid points to T."""
    rng = np.random.default_rng(3)
    gaps = 0.02 * rng.choice([1, 2], 300, p=[0.45, 0.55]) + rng.normal(0, 0.0003, 300)
    cad = detect_cadence(gaps, th)
    assert abs(cad.interval_ms - 20) < 1 and cad.grid_fraction > 0.95


def test_cadence_absent_on_human_typing(th):
    rng = np.random.default_rng(2)
    gaps = np.clip(rng.lognormal(np.log(0.15), 0.4, 300), 0.05, 0.8)
    cad = detect_cadence(gaps, th)
    assert cad.absent and not cad.present


def test_cadence_empty(th):
    cad = detect_cadence(np.zeros(0), th)
    assert cad.n == 0 and cad.ambiguous


# ---- per detector
def test_L1_fires_unprotected_quiet_fixed(analysed):
    assert statuses(analysed("unprotected")[0])["L1"] == "fired"
    assert statuses(analysed("fixed")[0])["L1"] == "not_fired"
    f = finding(analysed("unprotected")[0], "L1")
    assert 0 < f.confidence <= 1 and f.evidence["grid_fraction"] < 0.5


def test_L2_default_off_vs_active(analysed):
    assert statuses(analysed("default_off")[0])["L2"] == "fired"
    f = finding(analysed("default_off")[0], "L2")
    assert f.evidence["expectation_source"] == "OpenSSH 9.5+ default"
    assert statuses(analysed("fixed")[0])["L2"] == "not_fired"


def test_V3_interval_found_from_data(analysed):
    rep, flows = analysed("interval80")
    ia = flows[0].ctx.interactive
    assert abs(ia.cadence.interval_ms - 80) < 2
    check = next(c for c in rep.flows[0].checks if c.id == "L2")
    assert "80" in check.reason and "expected 20" in check.reason


def test_V2_L3_flaw_fires_fixed_does_not(analysed):
    assert statuses(analysed("flawed")[0])["L3"] == "fired"
    assert statuses(analysed("fixed")[0])["L3"] == "not_fired"
    f = finding(analysed("flawed")[0], "L3")
    lo, hi = f.evidence["two_unit_fraction_ci95"]
    assert 0 < lo <= f.evidence["two_unit_fraction"] <= hi


def test_L4_echo_off_runs(analysed):
    plain = finding(analysed("password_plain")[0], "L4")
    assert plain and plain.evidence["no_reply_runs"] >= 1
    simulated = finding(analysed("password_openssh")[0], "L4")
    assert simulated and simulated.evidence["fast_reply_runs"] >= 1
    assert statuses(analysed("no_password")[0])["L4"] == "not_fired"


def test_L5_counts_track_typed_lengths(analysed):
    """Ground truth from the lab: per-command packet counts follow typed length."""
    from sshleak.detectors.l05_keystroke_count import burst_counts

    _, flows = analysed("unprotected")
    ia = flows[0].ctx.interactive
    from sshleak.lab.synth import frames_for

    _, labels = frames_for(by_name("unprotected").sessions[0])
    counts = burst_counts(ia, use_double=False)
    truth = [n + 1 for n in labels.commands]  # characters + Enter
    k = min(len(counts), len(truth))
    r = np.corrcoef(counts[-k:], truth[-k:])[0, 1]
    assert k >= 8 and r > 0.9


def test_L5_masked_under_fixed_obfuscation(analysed):
    assert statuses(analysed("fixed")[0])["L5"] == "not_fired"
    assert statuses(analysed("flawed")[0])["L5"] == "fired"


def test_L6_quantised_confidence_under_obfuscation(analysed):
    raw = finding(analysed("unprotected")[0], "L6")
    obf = finding(analysed("fixed")[0], "L6")
    assert raw and obf and obf.confidence < raw.confidence
    assert obf.evidence["timing_quantum_ms"] == pytest.approx(20, abs=1)


def test_L7_independent_jitter_quiet(analysed):
    assert statuses(analysed("fixed")[0])["L7"] == "not_fired"


def test_L8_cost_bounds(analysed):
    f = finding(analysed("interval80")[0], "L8")
    assert f and f.severity == "info" and f.evidence["added_latency_p95_ms_est"] > 50
    assert statuses(analysed("fixed")[0])["L8"] == "not_fired"


def test_V6_L9_compression(analysed):
    f = finding(analysed("compression")[0], "L9")
    assert f and f.evidence["compression_c2s"] == "zlib@openssh.com"


def test_V6_L10_weak_cipher(analysed):
    f = finding(analysed("weak_cipher")[0], "L10")
    assert f and any("aes128-cbc" in r for r in f.evidence["reasons"])
    assert any("hmac-sha1-96" in r for r in f.evidence["reasons"])


def test_L10_terrapin_without_strict_kex(analysed):
    f = finding(analysed("unprotected")[0], "L10")
    assert f and any("Terrapin" in r for r in f.evidence["reasons"])
    assert statuses(analysed("fixed")[0])["L10"] == "not_fired"


def test_V1_L11_old_client(analysed):
    f = finding(analysed("unprotected")[0], "L11")
    assert f and f.evidence["version"] == "9.4"


def test_V5_unknown_implementation(analysed):
    st = statuses(analysed("unknown_impl")[0])
    assert st["L11"] == "skipped" and st["L2"] == "skipped" and st["L1"] == "fired"


def test_L12_session_types(analysed):
    assert finding(analysed("unprotected")[0], "L12").evidence["session_type"] == "shell"
    assert "scp" in finding(analysed("scp")[0], "L12").evidence["session_type"]
    assert "sftp" in finding(analysed("sftp")[0], "L12").evidence["session_type"]
    assert finding(analysed("forward")[0], "L12").evidence["session_type"] == "tunnel/forward"


def test_L13_skipped_without_process_info(analysed):
    assert statuses(analysed("unprotected")[0])["L13"] == "skipped"


def test_L13_forward_hop_fires():
    from sshleak.detectors.context import FlowMeta
    from sshleak.detectors.l13_observation_hop import L13ObservationHop
    from sshleak.discovery.sockets import ProcInfo

    class Ctx:
        def __init__(self, cli, srv):
            self.meta = FlowMeta("f1", ("127.0.0.1", 5), ("127.0.0.1", 2222), client_proc=cli, server_proc=srv,
                                 process_info_available=True)

    d = L13ObservationHop()
    assert d.run(Ctx(ProcInfo(1, "ssh", 0), ProcInfo(2, "ssh", 0))).status.value == "fired"
    assert d.run(Ctx(ProcInfo(1, "nc", 0), ProcInfo(2, "sshd", 0))).status.value == "fired"
    assert d.run(Ctx(ProcInfo(1, "ssh", 0), ProcInfo(2, "sshd-session", 0))).status.value == "not_fired"


# ---- session shapes
def test_S1_idle_skipped(analysed):
    st = statuses(analysed("idle")[0])
    assert all(st[k] == "skipped" for k in ("L1", "L3", "L4", "L5"))


def test_S2_few_packets_insufficient(analysed):
    st = statuses(analysed("few_packets")[0])
    assert st["L1"] == "insufficient_evidence"


def test_S2_exit_2_when_requested(scenario_pcap):
    from tests.conftest import run_cli

    res = run_cli("scan", "--pcap", scenario_pcap("few_packets"), "--only", "L1")
    assert res.code == 2


def test_S3_bulk_only(analysed):
    rep, _ = analysed("scp")
    kinds = {p.kind for p in rep.flows[0].phases}
    assert "bulk" in kinds and "interactive" not in kinds


def test_S4_interactive_then_bulk_segmented(analysed):
    rep, _ = analysed("interactive_then_bulk")
    kinds = [p.kind for p in rep.flows[0].phases]
    assert "interactive" in kinds and "bulk" in kinds
    assert kinds.index("interactive") < kinds.index("bulk")


def test_S5_forward_degraded(analysed):
    rep, _ = analysed("forward")
    assert any("mixed" in d for d in rep.flows[0].degraded)


def test_S6_redraw_lowers_confidence(analysed):
    rep, flows = analysed("tmux")
    ia = flows[0].ctx.interactive
    assert ia.server_noise_ratio > 0.3
    l5 = finding(rep, "L5")
    if l5 is not None:
        assert l5.confidence <= 0.6 and l5.degraded


def test_S7_pastes_excluded(analysed):
    rep, flows = analysed("paste")
    assert flows[0].ctx.interactive.paste_count == 2
    assert finding(rep, "L1").evidence["pastes_excluded"] == 2


def test_S8_no_pty_skips_keystroke_detectors(analysed):
    rep, _ = analysed("exec")
    st = statuses(rep)
    assert st["L1"] == "skipped" and "no interactive phase" in next(c.reason for c in rep.flows[0].checks if c.id == "L1")


def test_holm_demotes_borderline(th):
    from sshleak.analysis.stats import holm

    adj = holm({"a": 0.004, "b": 0.009, "c": 0.5})
    assert adj["a"] == pytest.approx(0.012) and adj["b"] == pytest.approx(0.018) and adj["c"] == 0.5


def test_score_formula(th):
    from sshleak.findings.engine import score_flow
    from sshleak.findings.report import FindingModel

    f = lambda sev, c: FindingModel(id="X", title="t", severity=sev, confidence=c, summary="", evidence={}, fix="")
    assert score_flow([], th) == 100
    assert score_flow([f("high", 1.0), f("medium", 0.5), f("info", 1.0)], th) == pytest.approx(100 - 30 - 6 - 2)
    assert score_flow([f("high", 1.0)] * 5, th) == 0
