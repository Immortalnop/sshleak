"""Real OpenSSH builds in the isolated Docker lab (pytest -m docker)."""

from __future__ import annotations

import json

import pytest

from sshleak.lab.analyse import analyse_file, mismatches
from sshleak.lab.docker_lab import DOCKER_SCENARIOS, docker_available, image_present, run_many

pytestmark = pytest.mark.docker


@pytest.fixture(scope="module")
def lab_runs(tmp_path_factory):
    if not (docker_available() and image_present()):
        pytest.skip("docker or the sshleak-lab image is unavailable (sshleak lab build)")
    out = tmp_path_factory.mktemp("lab")
    return run_many(DOCKER_SCENARIOS, out, seed=11, jobs=4)


def test_docker_scenarios_match_labels(lab_runs, th):
    failures = {}
    for path in lab_runs:
        labels = json.loads(path.with_suffix(".labels.json").read_text())
        rep, _ = analyse_file(path, th)
        probs, _ = mismatches(rep, {0: labels["expect"]})
        if probs:
            failures[path.stem] = probs
    assert not failures, failures


def test_lab_labels_are_verified_by_config(lab_runs):
    """Labels say what the client was configured to do: checked with the client's own ssh -G."""
    by = {p.stem: json.loads(p.with_suffix(".labels.json").read_text()) for p in lab_runs}
    assert by["d_off_106"]["effective_obscurekeystroketiming"] == "no"
    assert by["d_interval80"]["effective_obscurekeystroketiming"] in ("interval:80", "80")
    assert by["d_unprotected"]["effective_obscurekeystroketiming"] is None  # 9.4 lacks the option
    assert "OpenSSH_9.6p1" in by["d_flawed"]["client_version"]
