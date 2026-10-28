"""Calibration matrix (Phase 9): run every labelled scenario across seeds, score
detectors against labels, and propose thresholds for acceptance.

Proposed thresholds are written to a separate file and never applied
automatically (plan rule: thresholds are accepted by the owner).
"""

from __future__ import annotations

import json
import re
import tomllib
from collections import defaultdict
from pathlib import Path

import numpy as np

from sshleak import thresholds
from sshleak.detectors.registry import load_detectors
from sshleak.exitcodes import ExitCode
from sshleak.lab.analyse import OBSERVE, analyse_file
from sshleak.lab.docker_lab import DOCKER_SCENARIOS, docker_available, image_present, run_many
from sshleak.lab.scenarios import catalogue, write_scenario


def flow_stats(fa) -> dict:
    ctx = fa.ctx
    ia = ctx.interactive
    cad = ia.cadence
    dets = {d.meta.id: d for d in load_detectors(include_plugins=False)}
    stats = {
        "n_client": ia.n_client,
        "cadence_present": cad.present,
        "grid_fraction": cad.grid_fraction,
        "peak_fraction": cad.peak_fraction,
        "interval_ms": cad.interval_ms,
        "echo_rate": float((ia.reply_count > 0).mean()) if ia.n_ticks else None,
        "server_noise_ratio": ia.server_noise_ratio,
    }
    if cad.present and ia.in_run.any():
        stats["two_unit_fraction"] = float((ia.tick_units[ia.in_run] == 2).mean())
    for det_id in ("L4", "L7"):
        res = dets[det_id].run(ctx)
        for k in ("rho_jitter_vs_size", "rho_jitter_vs_reply_latency", "no_reply_runs", "fast_reply_runs",
                  "min_window_latency_ratio"):
            if k in res.evidence:
                stats[k] = res.evidence[k]
    return stats


def _record(source: str, name: str, variant: int, report, flows, expect: dict,
            password: list[bool] | None = None) -> list[dict]:
    out = []
    for i, (model, fa) in enumerate(zip(report.flows, flows)):
        out.append({
            "source": source, "scenario": name, "variant": variant, "flow": i,
            "expect": expect.get(i, {}),
            "password_typed": bool(password[i]) if password and i < len(password) else False,
            "status": {c.id: c.status for c in model.checks},
            "stats": flow_stats(fa) if fa.ctx else {},
        })
    return out


def run_matrix(out: Path, *, seeds: int = 3, docker: bool = True, jobs: int = 3) -> int:
    th = thresholds.load()
    out.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    for v in range(seeds):
        for sc in catalogue(v):
            path = out / "synth" / str(v) / f"{sc.name}.pcap"
            labels = write_scenario(sc, path)
            report, flows = analyse_file(path, th)
            records += _record("synth", sc.name, v, report, flows, sc.expect,
                               [lab.password_runs > 0 for lab in labels])
    note = None
    if docker:
        if docker_available() and image_present():
            for v in range(seeds):
                for path in run_many(DOCKER_SCENARIOS, out / "docker" / str(v), seed=v + 1, jobs=jobs):
                    labels = json.loads(path.with_suffix(".labels.json").read_text())
                    report, flows = analyse_file(path, th)
                    records += _record("docker", path.stem, v, report, flows[:1], {0: labels["expect"]},
                                       [bool(labels["password_windows_ns"])])[:1]
        else:
            note = "docker lab unavailable or image not built: matrix is synthetic only"
    (out / "matrix.json").write_text(json.dumps({"thresholds": th.version, "records": records}, indent=2,
                                                sort_keys=True, default=float) + "\n")
    table = score(records)
    lines = ["| Detector | Fire cases | Recall | Quiet cases | False positives | Observed (unlabelled) |",
             "| --- | --- | --- | --- | --- | --- |"]
    for det, s in table.items():
        rec = f"{s['tp'] / s['pos']:.0%}" if s["pos"] else "n/a"
        fpr = f"{s['fp'] / s['neg']:.1%}" if s["neg"] else "n/a"
        obs = ", ".join(f"{k}:{v}" for k, v in sorted(s["observed"].items())) or "-"
        lines.append(f"| {det} | {s['pos']} | {rec} | {s['neg']} | {fpr} ({s['fp']}) | {obs} |")
    summary = "\n".join(lines) + "\n"
    (out / "summary.md").write_text(summary + (f"\n{note}\n" if note else ""))
    print(summary)
    if note:
        print("note:", note)
    return ExitCode.CLEAN


def score(records: list[dict]) -> dict:
    table: dict = defaultdict(lambda: {"pos": 0, "tp": 0, "neg": 0, "fp": 0, "observed": defaultdict(int)})
    for rec in records:
        for det, want in rec["expect"].items():
            got = rec["status"].get(det)
            s = table[det]
            if want == OBSERVE:
                s["observed"][got] += 1
            elif want == "fired":
                s["pos"] += 1
                s["tp"] += got == "fired"
            elif want == "not_fired":
                s["neg"] += 1
                s["fp"] += got == "fired"
    order = sorted(table, key=lambda k: int(k[1:]))
    return {k: {**table[k], "observed": dict(table[k]["observed"])} for k in order}


def _split(pos: list[float], neg: list[float], higher_is_pos: bool) -> tuple[float | None, str]:
    if not pos or not neg:
        return None, "not enough labelled flows"
    if higher_is_pos:
        lo, hi = max(neg), min(pos)
    else:
        lo, hi = max(pos), min(neg)
    if lo >= hi:
        return None, f"classes overlap (max {lo:.3f} >= min {hi:.3f}); no separating value"
    return round((lo + hi) / 2, 3), f"separates {lo:.3f} | {hi:.3f}"


def fit(matrix: Path, out: Path) -> int:
    data = json.loads((matrix / "matrix.json").read_text())
    recs = data["records"]
    grid_obf = [r["stats"]["grid_fraction"] for r in recs if r["expect"].get("L1") == "not_fired" and r["stats"]]
    grid_raw = [r["stats"]["grid_fraction"] for r in recs if r["expect"].get("L1") == "fired" and r["stats"]]
    peak_obf = [r["stats"]["peak_fraction"] for r in recs if r["expect"].get("L1") == "not_fired" and r["stats"]]
    peak_raw = [r["stats"]["peak_fraction"] for r in recs if r["expect"].get("L1") == "fired" and r["stats"]]
    two_flaw = [r["stats"]["two_unit_fraction"] for r in recs if r["expect"].get("L3") == "fired" and "two_unit_fraction" in r["stats"]]
    two_fix = [r["stats"]["two_unit_fraction"] for r in recs if r["expect"].get("L3") == "not_fired" and "two_unit_fraction" in r["stats"]]
    rhos = [abs(r["stats"].get(k) or 0) for r in recs if r["stats"].get("cadence_present")
            for k in ("rho_jitter_vs_size", "rho_jitter_vs_reply_latency")]
    lat_pw = [r["stats"]["min_window_latency_ratio"] for r in recs if r["password_typed"]
              and r["stats"].get("min_window_latency_ratio") is not None and not r["stats"].get("cadence_present")]
    lat_no = [r["stats"]["min_window_latency_ratio"] for r in recs if not r["password_typed"]
              and r["stats"].get("min_window_latency_ratio") is not None and not r["stats"].get("cadence_present")]
    proposals = {
        ("L4", "latency_ratio_max"): _split(lat_pw, lat_no, False),
        ("cadence", "grid_min_fraction"): _split(grid_obf, grid_raw, True),
        ("cadence", "peak_min_fraction"): _split(peak_obf, peak_raw, True),
        ("L3", "min_double_fraction"): _split(two_flaw, two_fix, True),
    }
    if rhos:
        proposals[("L7", "min_abs_rho")] = (round(max(0.3, float(np.max(rhos)) + 0.05), 3),
                                            f"max |rho| on labelled flows {max(rhos):.3f} + 0.05")
    current = thresholds.default_path().read_text()
    cur = tomllib.loads(current)
    text = current
    print("| Threshold | Current | Proposed | Basis |\n| --- | --- | --- | --- |")
    for (sec, key), (val, basis) in proposals.items():
        print(f"| {sec}.{key} | {cur[sec][key]} | {val if val is not None else '(keep)'} | {basis} |")
        if val is None:
            continue
        pattern = re.compile(rf"(\[{re.escape(sec)}\][^\[]*?\n{re.escape(key)}\s*=\s*)([0-9.]+)", re.S)
        text = pattern.sub(lambda m: m.group(1) + str(val), text, count=1)
    text = text.replace('version = "', 'version = "candidate-from-matrix+', 1)
    header = ("# CANDIDATE thresholds proposed by `sshleak lab calibrate`. NOT ACTIVE.\n"
              "# Review, record the decision in docs/decisions.md, then copy over thresholds.toml\n"
              "# and set calibrated = true. Never loosen a value only to make a run green.\n")
    out.write_text(header + text)
    print(f"\nwrote {out}")
    return ExitCode.CLEAN
