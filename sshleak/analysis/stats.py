"""Statistics helpers: binomial tests, Holm correction, bootstrap CIs, confidence."""

from __future__ import annotations

import math
import zlib

import numpy as np
from scipy import stats as sps


def binom_greater(k: int, n: int, p: float) -> float:
    if n == 0:
        return 1.0
    return float(sps.binomtest(int(k), int(n), min(max(p, 1e-12), 1.0), alternative="greater").pvalue)


def binom_less(k: int, n: int, p: float) -> float:
    if n == 0:
        return 1.0
    return float(sps.binomtest(int(k), int(n), min(max(p, 1e-12), 1.0), alternative="less").pvalue)


def holm(pvalues: dict[str, float]) -> dict[str, float]:
    """Holm-Bonferroni adjusted p-values (monotone)."""
    items = sorted(pvalues.items(), key=lambda kv: (kv[1], kv[0]))
    m = len(items)
    out: dict[str, float] = {}
    running = 0.0
    for i, (key, p) in enumerate(items):
        adj = min(1.0, (m - i) * p)
        running = max(running, adj)
        out[key] = running
    return out


def sample_factor(n: float, n0: float) -> float:
    return 1.0 - math.exp(-max(n, 0.0) / n0)


def confidence(effect: float, n: float, n0: float) -> float:
    return float(min(1.0, max(0.0, effect)) * sample_factor(n, n0))


def rng_for(seed: int, *labels: str) -> np.random.Generator:
    """Deterministic RNG per (seed, flow, detector) so reports are reproducible."""
    mix = zlib.crc32("|".join(labels).encode()) ^ (seed & 0xFFFFFFFF)
    return np.random.default_rng(mix)


def bootstrap_ci(
    values: np.ndarray, stat, resamples: int, rng: np.random.Generator, level: float = 0.95
) -> tuple[float, float] | None:
    if resamples <= 0 or len(values) < 5:
        return None
    n = len(values)
    idx = rng.integers(0, n, size=(resamples, n))
    boots = np.array([stat(values[row]) for row in idx])
    lo, hi = np.quantile(boots, [(1 - level) / 2, 1 - (1 - level) / 2])
    return float(lo), float(hi)


def r(x: float | None, nd: int = 4) -> float | None:
    """Round for stable report output."""
    if x is None or (isinstance(x, float) and (math.isnan(x) or math.isinf(x))):
        return None
    return round(float(x), nd)
