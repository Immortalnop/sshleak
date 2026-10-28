"""Read saved JSON reports across schema versions (case O2).

Same major, older or equal minor: validated (missing newer fields take defaults).
Same major, newer minor: read-only with a warning (unknown fields ignored).
Different major: read-only summary with a warning; nothing is re-interpreted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from pydantic import ValidationError

from sshleak import SCHEMA_VERSION
from sshleak.errors import EnvironmentProblem
from sshleak.findings.report import Report


@dataclass
class Loaded:
    report: Report | None
    raw: dict
    warning: str | None
    read_only: bool


def _ver(v: str) -> tuple[int, int]:
    major, _, minor = str(v).partition(".")
    return int(major), int(minor or 0)


def _strip_unknown(model, data):
    """Drop keys a model does not know (for newer-minor reports)."""
    if isinstance(data, dict) and hasattr(model, "model_fields"):
        out = {}
        for k, v in data.items():
            if k in model.model_fields:
                ann = model.model_fields[k].annotation
                sub = getattr(ann, "__args__", (ann,))
                target = next((a for a in sub if hasattr(a, "model_fields")), None)
                if target is None:
                    inner = [getattr(a, "__args__", ()) for a in sub]
                    target = next((x for group in inner for x in group if hasattr(x, "model_fields")), None)
                if target is not None and isinstance(v, list):
                    out[k] = [_strip_unknown(target, i) for i in v]
                elif target is not None:
                    out[k] = _strip_unknown(target, v)
                else:
                    out[k] = v
        return out
    return data


def load_report(path: str) -> Loaded:
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except OSError as e:
        raise EnvironmentProblem(f"cannot read report: {e.strerror}") from None
    except json.JSONDecodeError as e:
        raise EnvironmentProblem(f"report is not JSON: {e}") from None
    if not isinstance(raw, dict) or "schema_version" not in raw:
        raise EnvironmentProblem("not an sshleak report (no schema_version)")
    try:
        theirs = _ver(raw["schema_version"])
    except ValueError:
        raise EnvironmentProblem(f"unrecognised schema_version {raw['schema_version']!r}") from None
    ours = _ver(SCHEMA_VERSION)
    if theirs[0] != ours[0]:
        return Loaded(None, raw, f"report schema {raw['schema_version']} has a different major version than "
                                 f"{SCHEMA_VERSION}; shown read-only", True)
    try:
        if theirs[1] > ours[1]:
            rep = Report.model_validate(_strip_unknown(Report, raw))
            return Loaded(rep, raw, f"report schema {raw['schema_version']} is newer than {SCHEMA_VERSION}; "
                                    "unknown fields ignored, shown read-only", True)
        rep = Report.model_validate(raw)
    except ValidationError as e:
        return Loaded(None, raw, f"report does not match schema {raw['schema_version']}: "
                                 f"{e.error_count()} errors; shown read-only", True)
    note = None if theirs == ours else f"migrated report schema {raw['schema_version']} -> {SCHEMA_VERSION}"
    rep.schema_version = SCHEMA_VERSION
    return Loaded(rep, raw, note, False)
