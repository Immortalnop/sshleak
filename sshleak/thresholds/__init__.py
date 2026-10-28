"""Load and validate thresholds.toml (strict: unknown or missing keys are errors)."""

from __future__ import annotations

import hashlib
import tomllib
from importlib import resources
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sshleak.errors import EnvironmentProblem


class _S(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Global(_S):
    min_packets: int = Field(ge=1)
    alpha: float = Field(gt=0, lt=1)
    confidence_n0: float = Field(gt=0)
    bootstrap_resamples: int = Field(ge=0)
    seed: int


class LimitsT(_S):
    max_records_per_flow: int = Field(ge=1000)
    max_flows: int = Field(ge=1)
    clock_step_tolerance_ms: float = Field(gt=0)
    clock_step_window_s: float = Field(ge=0)
    low_memory_mb: int = Field(ge=0)


class Phases(_S):
    auth_end_gap_s: float
    auth_max_packets: int
    auth_max_s: float
    window_s: float = Field(gt=0)
    small_packet_max_bytes: int
    bulk_bytes_per_s: float
    bulk_segment_min_bytes: int
    bulk_min_bytes: int
    mixed_min_client_large: int
    rekey_min_bytes: int
    rekey_pair_window_s: float


class Ticks(_S):
    merge_window_ms: float
    paste_min_units: int
    max_run_gap_s: float


class CadenceT(_S):
    min_interval_ms: float
    max_interval_ms: float
    bin_ms: float = Field(gt=0)
    tolerance_abs_ms: float
    tolerance_rel: float
    grid_min_fraction: float
    peak_min_fraction: float
    grid_h0_fraction: float


class Echo(_S):
    window_factor: float
    window_min_ms: float
    window_max_ms: float
    response_window_s: float


class Shape(_S):
    min_segments: int
    modulus: int
    min_fraction: float
    max_small_bytes: int
    confidence: float


class Empty(_S):
    pass


class L2T(_S):
    default_interval_ms: float
    default_expectation_factor: float


class L3T(_S):
    min_double_ticks: int
    min_double_fraction: float
    noise_fraction: float


class L4T(_S):
    min_run: int
    min_echo_rate: float
    min_latency_run: int
    latency_ratio_max: float
    redraw_noise_max: float


class L5T(_S):
    min_bursts: int
    burst_gap_s: float
    enter_output_min_units: float


class L6T(_S):
    min_events: int
    obfuscated_confidence_factor: float


class L7T(_S):
    min_ticks: int
    min_abs_rho: float


class L8T(_S):
    max_latency_p95_ms: float
    max_chaff_bytes_per_s: float


class L12T(_S):
    min_confidence: float


class Caps(_S):
    virtualised: float
    capture_drops: float
    late_join: float
    shape_identified: float
    mixed_traffic: float
    redraw_noise: float
    offload: float
    clock_step: float
    truncated_input: float


class Score(_S):
    high: float
    medium: float
    info: float


class Thresholds(_S):
    schema_: int = Field(alias="schema")
    version: str
    calibrated: bool
    global_: Global = Field(alias="global")
    limits: LimitsT
    phases: Phases
    ticks: Ticks
    cadence: CadenceT
    echo: Echo
    shape: Shape
    L1: Empty
    L2: L2T
    L3: L3T
    L4: L4T
    L5: L5T
    L6: L6T
    L7: L7T
    L8: L8T
    L12: L12T
    confidence_caps: Caps
    score: Score
    sha256: str = ""

    def with_min_packets(self, n: int | None) -> Thresholds:
        if n is None:
            return self
        return self.model_copy(update={"global_": self.global_.model_copy(update={"min_packets": n})})


def default_path() -> Path:
    return Path(str(resources.files("sshleak.thresholds") / "thresholds.toml"))


def load(path: str | Path | None = None) -> Thresholds:
    p = Path(path) if path else default_path()
    try:
        raw = p.read_bytes()
    except OSError as e:
        raise EnvironmentProblem(f"cannot read thresholds file {p.name}: {e.strerror}") from None
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise EnvironmentProblem(f"thresholds file {p.name} is not valid TOML: {e}") from None
    data["sha256"] = hashlib.sha256(raw).hexdigest()
    try:
        th = Thresholds.model_validate(data)
    except ValidationError as e:
        raise EnvironmentProblem(f"thresholds file {p.name} is invalid:\n{e}") from None
    if th.schema_ != 1:
        raise EnvironmentProblem(f"thresholds schema {th.schema_} is not supported (expected 1)")
    return th
