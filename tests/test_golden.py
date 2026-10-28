"""Golden captures in the repo (synthetic or self-generated in the isolated lab only)."""

from __future__ import annotations

import json

import pytest

from sshleak.lab.analyse import analyse_file, mismatches
from tests.conftest import GOLDEN

CAPTURES = sorted(GOLDEN.glob("*.pcap"))


@pytest.mark.parametrize("pcap", CAPTURES, ids=[p.stem for p in CAPTURES])
def test_golden_capture_matches_labels(pcap, th):
    labels = json.loads(pcap.with_suffix(".labels.json").read_text())
    expect = labels["expect"]
    if "0" in expect:  # synthetic label files are keyed by session index
        expect = {int(k): v for k, v in expect.items()}
    else:
        expect = {0: expect}
    report, _ = analyse_file(pcap, th)
    probs, _ = mismatches(report, expect)
    assert not probs, probs


def test_V2_real_flawed_build_fires_fixed_build_does_not(th):
    flawed, _ = analyse_file(GOLDEN / "real_d_flawed.pcap", th)
    fixed, _ = analyse_file(GOLDEN / "real_d_fixed_106.pcap", th)
    assert {c.id: c.status for c in flawed.flows[0].checks}["L3"] == "fired"
    assert {c.id: c.status for c in fixed.flows[0].checks}["L3"] == "not_fired"
    assert flawed.flows[0].client_software == "OpenSSH_9.6"


def test_real_old_server_disables_obfuscation(th):
    """Observed in the lab: a 10.6 client to a 9.4 server (no ping@openssh.com) sends no chaff."""
    rep, flows = analyse_file(GOLDEN / "real_d_old_server.pcap", th)
    assert not flows[0].ctx.interactive.cadence.present
    st = {c.id: c.status for c in rep.flows[0].checks}
    assert st["L1"] == "fired" and st["L2"] == "fired"
