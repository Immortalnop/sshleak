from __future__ import annotations

import io
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from sshleak import thresholds
from sshleak.lab.analyse import analyse_file
from sshleak.lab.scenarios import by_name, write_scenario

GOLDEN = Path(__file__).parent / "golden"


@pytest.fixture(scope="session")
def th():
    return thresholds.load()


@pytest.fixture(scope="session")
def scenario_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("scenarios")


@pytest.fixture(scope="session")
def scenario_pcap(scenario_dir):
    cache: dict[str, Path] = {}

    def make(name: str) -> Path:
        if name not in cache:
            path = scenario_dir / f"{name}.pcap"
            write_scenario(by_name(name), path)
            cache[name] = path
        return cache[name]

    return make


@pytest.fixture(scope="session")
def analysed(scenario_pcap, th):
    cache: dict = {}

    def get(name: str):
        if name not in cache:
            cache[name] = analyse_file(scenario_pcap(name), th)
        return cache[name]

    return get


def statuses(report, flow: int = 0) -> dict[str, str]:
    return {c.id: c.status for c in report.flows[flow].checks}


def finding(report, det: str, flow: int = 0):
    return next((f for f in report.flows[flow].findings if f.id == det), None)


class CliResult:
    def __init__(self, code: int, out: str, err: str):
        self.code, self.out, self.err = code, out, err


def run_cli(*args: str) -> CliResult:
    from sshleak.cli.main import main

    out, err = io.StringIO(), io.StringIO()
    old = sys.stdout
    with redirect_stdout(out), redirect_stderr(err):
        code = main([str(a) for a in args])
    sys.stdout = old
    return CliResult(int(code), out.getvalue(), err.getvalue())
