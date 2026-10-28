"""`sshleak selftest`: every detector must fire on known-leaky traffic and stay
quiet on known-safe traffic (synthetic scenarios + real OpenSSH builds in Docker)."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from sshleak import thresholds
from sshleak.errors import EnvironmentProblem
from sshleak.exitcodes import ExitCode
from sshleak.lab.analyse import analyse_file, mismatches
from sshleak.lab.docker_lab import DOCKER_SCENARIOS, build_image, docker_available, image_present, run_many
from sshleak.lab.scenarios import catalogue, write_scenario


def run_selftest(*, docker: bool = True, build: bool = False, keep: Path | None = None) -> int:
    th = thresholds.load()
    work = Path(keep) if keep else Path(tempfile.mkdtemp(prefix="sshleak-selftest-"))
    work.mkdir(parents=True, exist_ok=True)
    rows: list[tuple[str, str, bool, str]] = []
    try:
        for sc in catalogue():
            path = work / "synth" / f"{sc.name}.pcap"
            write_scenario(sc, path)
            report, _ = analyse_file(path, th)
            probs, _ = mismatches(report, sc.expect, sc.expect_flows)
            rows.append(("synth", sc.name, not probs, "; ".join(probs)))
        docker_note = None
        if docker:
            if not docker_available():
                docker_note = "docker unavailable: real-OpenSSH checks not run (synthetic only)"
            elif not image_present() and not build:
                docker_note = "lab image not built: run 'sshleak lab build' or 'sshleak selftest --build'"
            else:
                if not image_present():
                    build_image()
                out = work / "docker"
                for path in run_many(DOCKER_SCENARIOS, out):
                    labels = json.loads(path.with_suffix(".labels.json").read_text())
                    report, _ = analyse_file(path, th)
                    probs, observed = mismatches(report, {0: labels["expect"]}, None)
                    obs = ", ".join(f"{k}={v}" for k, v in sorted(observed.items()))
                    rows.append(("docker", path.stem, not probs, "; ".join(probs) + (f" [observed {obs}]" if obs else "")))
    finally:
        if keep is None:
            shutil.rmtree(work, ignore_errors=True)
    width = max(len(r[1]) for r in rows)
    for src, name, ok, detail in rows:
        print(f"{'PASS' if ok else 'FAIL'}  {src:<6} {name:<{width}}  {detail}")
    failed = sum(not r[2] for r in rows)
    if docker and docker_note:
        print(f"note: {docker_note}")
    print(f"selftest: {len(rows) - failed}/{len(rows)} scenarios passed"
          f"{'' if not keep else f'; captures kept in {work}'}")
    return ExitCode.CLEAN if failed == 0 else ExitCode.FINDINGS


__all__ = ["run_selftest", "EnvironmentProblem"]
