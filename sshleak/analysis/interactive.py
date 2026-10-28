"""Shared analysis of interactive phases: send ticks, cadence, replies, Enter events.

Terms:
  unit   - the most common small client segment size (one SSH packet, e.g. 36 B)
  tick   - client segments sent together (within merge_window); one keystroke or
           one chaff send, or both when the 9.5-9.7 client flaw is present
  cadence- a fixed send interval T (ObscureKeystrokeTiming) seen in tick gaps
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from sshleak.analysis.stats import binom_greater, binom_less
from sshleak.flows.tracker import FlowView
from sshleak.phases.segmenter import Segment
from sshleak.thresholds import Thresholds


@dataclass
class Cadence:
    n: int
    interval_ms: float | None = None
    tolerance_ms: float | None = None
    grid_fraction: float = 0.0
    peak_fraction: float = 0.0
    p_present: float = 1.0
    p_absent: float = 1.0
    present: bool = False
    absent: bool = False

    @property
    def ambiguous(self) -> bool:
        return not self.present and not self.absent


def detect_cadence(gaps_s: np.ndarray, th: Thresholds) -> Cadence:
    c = th.cadence
    alpha = th.global_.alpha
    g = np.asarray(gaps_s, dtype=float) * 1000.0
    n = len(g)
    if n == 0:
        return Cadence(n=0)
    in_range = g[(g >= c.min_interval_ms) & (g <= c.max_interval_ms)]
    if len(in_range) == 0:
        p_absent = binom_less(0, n, c.grid_h0_fraction)
        return Cadence(n=n, p_absent=p_absent, absent=p_absent <= alpha)
    edges = np.arange(c.min_interval_ms, c.max_interval_ms + c.bin_ms, c.bin_ms)
    hist, _ = np.histogram(in_range, bins=edges)
    peak = int(np.argmax(hist))
    centre = (edges[peak] + edges[peak + 1]) / 2
    tol = max(c.tolerance_abs_ms, c.tolerance_rel * centre)
    near = in_range[np.abs(in_range - centre) <= tol]
    T0 = float(np.median(near)) if len(near) else centre

    def grid_hits(T: float) -> tuple[int, float]:
        tol_t = max(c.tolerance_abs_ms, c.tolerance_rel * T)
        k = np.rint(g / T)
        return int(((k >= 1) & (np.abs(g - k * T) <= tol_t)).sum()), tol_t

    # The histogram peak may sit on a multiple of the true interval (missed or merged
    # sends); prefer the largest sub-multiple T0/k that puts the gaps on its grid.
    T = T0
    for k_div in (1, 2, 3, 4):
        cand = T0 / k_div
        if cand < c.min_interval_ms:
            break
        if grid_hits(cand)[0] / n >= c.grid_min_fraction:
            T = cand
            break
    hits, tol = grid_hits(T)
    grid = hits / n
    peak_frac = float((np.abs(g - T) <= tol).mean())
    p0 = min(1.0, 2 * tol / T)
    p_present = binom_greater(hits, n, p0)
    p_absent = binom_less(hits, n, c.grid_h0_fraction)
    present = grid >= c.grid_min_fraction and peak_frac >= c.peak_min_fraction and p_present <= alpha
    absent = not present and p_absent <= alpha
    return Cadence(n, T, tol, grid, peak_frac, p_present, p_absent, present, absent)


@dataclass
class Interactive:
    n_client: int = 0
    unit: int | None = None
    paste_count: int = 0
    tick_t: np.ndarray = field(default_factory=lambda: np.zeros(0))
    tick_bytes: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.int64))
    tick_units: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.int64))
    tick_nseg: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.int64))
    tick_seg: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.int64))
    gaps: np.ndarray = field(default_factory=lambda: np.zeros(0))
    gap_tick: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.int64))
    cadence: Cadence = field(default_factory=lambda: Cadence(n=0))
    in_run: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=bool))
    echo_window_s: float = 0.0
    reply_units: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.int64))
    reply_count: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.int64))
    reply_latency: np.ndarray = field(default_factory=lambda: np.zeros(0))
    server_t: np.ndarray = field(default_factory=lambda: np.zeros(0))
    server_size: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.int64))
    server_noise_ratio: float = 0.0
    interactive_seconds: float = 0.0
    events: list[EnterEvent] = field(default_factory=list)

    @property
    def n_ticks(self) -> int:
        return len(self.tick_t)


@dataclass(frozen=True)
class EnterEvent:
    tick: int  # index of the Enter tick
    burst_start: int  # first tick of the typing burst that ended in this Enter
    response_bytes: int
    pause_s: float  # time from the previous tick to Enter


def _mode(values: np.ndarray) -> int | None:
    if len(values) == 0:
        return None
    vals, counts = np.unique(values, return_counts=True)
    return int(vals[np.argmax(counts)])  # ties -> smallest size (np.unique is sorted)


def analyse(view: FlowView, segments: list[Segment], th: Thresholds) -> Interactive:
    inter = [s for s in segments if s.kind == "interactive"]
    out = Interactive()
    if not inter or len(view) == 0:
        return out
    t, d, s = view.t, view.direction, view.size
    seg_id = np.full(len(t), -1, dtype=np.int64)
    for k, sg in enumerate(inter):
        seg_id[sg.i0 : sg.i1] = k
    out.interactive_seconds = float(sum(sg.duration for sg in inter))
    in_int = seg_id >= 0
    cmask = in_int & (d == 0)
    small = s <= th.phases.small_packet_max_bytes
    unit = _mode(s[cmask & small])
    out.unit = unit
    if unit is None:
        return out
    paste = cmask & (s >= th.ticks.paste_min_units * unit)
    out.paste_count = int(paste.sum())
    keys = cmask & ~paste
    ct, cs, cseg = t[keys], s[keys].astype(np.int64), seg_id[keys]
    out.n_client = int(len(ct))
    sv = in_int & (d == 1)
    out.server_t, out.server_size = t[sv], s[sv].astype(np.int64)
    if len(ct) == 0:
        return out

    # Ticks: client segments sent together.
    merge = th.ticks.merge_window_ms / 1000.0
    new = np.ones(len(ct), dtype=bool)
    new[1:] = (np.diff(ct) > merge) | (cseg[1:] != cseg[:-1])
    tick_idx = np.cumsum(new) - 1
    nt = int(tick_idx[-1]) + 1
    out.tick_t = ct[new]
    out.tick_seg = cseg[new]
    out.tick_bytes = np.bincount(tick_idx, weights=cs, minlength=nt).astype(np.int64)
    out.tick_nseg = np.bincount(tick_idx, minlength=nt).astype(np.int64)
    out.tick_units = np.maximum(1, np.rint(out.tick_bytes / unit)).astype(np.int64)

    # Gaps inside typing runs.
    gaps = np.diff(out.tick_t)
    same = (out.tick_seg[1:] == out.tick_seg[:-1]) & (gaps < th.ticks.max_run_gap_s)
    out.gaps = gaps[same]
    out.gap_tick = np.flatnonzero(same) + 1
    out.cadence = detect_cadence(out.gaps, th)

    # Ticks that belong to a fixed-interval run.
    in_run = np.zeros(nt, dtype=bool)
    cad = out.cadence
    if cad.present and cad.interval_ms:
        T, tol = cad.interval_ms / 1000.0, cad.tolerance_ms / 1000.0
        one = same & (np.abs(gaps - T) <= tol)
        in_run[1:] |= one
        in_run[:-1] |= one
    out.in_run = in_run

    # Server replies per tick.
    st, ss = out.server_t, out.server_size
    nxt = np.append(out.tick_t[1:], np.inf)
    max_w = th.echo.window_max_ms / 1000.0
    lo = np.searchsorted(st, out.tick_t, side="right")
    first = np.where(lo < len(st), st[np.minimum(lo, len(st) - 1)] if len(st) else np.inf, np.inf)
    lat0 = first - out.tick_t
    ok = (lat0 <= max_w) & (first < nxt)
    if ok.any():
        med = float(np.median(lat0[ok]))
        w = min(max(th.echo.window_factor * med, th.echo.window_min_ms / 1000.0), max_w)
    else:
        w = th.echo.window_min_ms / 1000.0
    out.echo_window_s = w
    end = np.minimum(out.tick_t + w, nxt)
    hi = np.searchsorted(st, end, side="right")
    su = np.maximum(1, np.rint(ss / unit)).astype(np.int64) if len(ss) else np.zeros(0, dtype=np.int64)
    cum = np.concatenate([[0], np.cumsum(su)])
    out.reply_units = cum[hi] - cum[lo]
    out.reply_count = hi - lo
    out.reply_latency = np.where(hi > lo, lat0, np.nan)

    # Server packets not explained by a recent tick (e.g. tmux redraw, S6).
    if len(st):
        prev = np.searchsorted(out.tick_t, st, side="right") - 1
        expl = (prev >= 0) & (st - out.tick_t[np.maximum(prev, 0)] <= w)
        out.server_noise_ratio = float(1.0 - expl.mean())

    out.events = _enter_events(out, th)
    return out


def _enter_events(ia: Interactive, th: Thresholds) -> list[EnterEvent]:
    """Enter = a tick followed by server output: a packet larger than one echo unit
    (a 2-unit packet is an echo+pong pair, not output)."""
    unit = ia.unit or 1
    ss = ia.server_size
    big = (ss > th.L5.enter_output_min_units * unit) & (ss != 2 * unit)
    bt, bs = ia.server_t[big], ia.server_size[big]
    if len(bt) == 0 or ia.n_ticks == 0:
        return []
    # Group big server packets into responses.
    starts = np.ones(len(bt), dtype=bool)
    starts[1:] = np.diff(bt) > 0.2
    resp_id = np.cumsum(starts) - 1
    resp_t = bt[starts]
    resp_bytes = np.bincount(resp_id, weights=bs)
    events: list[EnterEvent] = []
    last_enter = -1
    for rt, rb in zip(resp_t, resp_bytes):
        k = int(np.searchsorted(ia.tick_t, rt, side="left")) - 1
        if k < 0 or k <= last_enter or rt - ia.tick_t[k] > th.echo.response_window_s:
            continue
        # Burst: ticks since the previous Enter, cut at long pauses.
        b0 = last_enter + 1
        if k > b0:
            gaps = np.diff(ia.tick_t[b0 : k + 1])
            long = np.flatnonzero(gaps > th.L5.burst_gap_s)
            if len(long):
                b0 = b0 + int(long[-1]) + 1
        pause = float(ia.tick_t[k] - ia.tick_t[k - 1]) if k > 0 else 0.0
        events.append(EnterEvent(k, b0, int(rb), pause))
        last_enter = k
    return events
