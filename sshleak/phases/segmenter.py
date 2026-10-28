"""Split a flow into handshake, auth, interactive, bulk, mixed, idle and rekey phases.

Works on metadata only (time, direction, size): no decryption.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from sshleak.flows.tracker import FlowView
from sshleak.thresholds import Thresholds

KINDS = ("handshake", "auth", "interactive", "bulk", "mixed", "idle", "rekey")


@dataclass(frozen=True)
class Segment:
    kind: str
    i0: int  # first record index (inclusive)
    i1: int  # last record index (exclusive)
    t0: float  # seconds since first record
    t1: float

    @property
    def n(self) -> int:
        return self.i1 - self.i0

    @property
    def duration(self) -> float:
        return self.t1 - self.t0


@dataclass
class SegmentStats:
    rekey_events: int = 0
    paste_pairs: int = 0


def _auth_end(t: np.ndarray, start: int, ph) -> int:
    n = len(t)
    if start >= n:
        return n
    limit = min(n, start + ph.auth_max_packets)
    for k in range(start + 1, limit):
        if t[k] - t[k - 1] >= ph.auth_end_gap_s or t[k] - t[start] >= ph.auth_max_s:
            return k
    return limit


def segment(view: FlowView, th: Thresholds, *, late_join: bool) -> tuple[list[Segment], SegmentStats]:
    ph = th.phases
    t = view.t
    d = view.direction
    s = view.size
    n = len(t)
    segs: list[Segment] = []
    stats = SegmentStats()
    if n == 0:
        return segs, stats
    pos = 0
    if not late_join:
        if view.hs_end:
            end = min(view.hs_end, n)
            segs.append(Segment("handshake", 0, end, float(t[0]), float(t[end - 1])))
            pos = end
        a_end = _auth_end(t, pos, ph)
        if a_end > pos:
            segs.append(Segment("auth", pos, a_end, float(t[pos]), float(t[a_end - 1])))
            pos = a_end
    if pos >= n:
        return segs, stats

    rt, rd, rs = t[pos:], d[pos:], s[pos:]
    w = np.floor((rt - rt[0]) / ph.window_s).astype(np.int64)
    nw = int(w[-1]) + 1
    client = rd == 0
    small = rs <= ph.small_packet_max_bytes
    cbytes = np.bincount(w[client], weights=rs[client], minlength=nw)
    sbytes = np.bincount(w[~client], weights=rs[~client], minlength=nw)
    csmall = np.bincount(w[client & small], minlength=nw)
    clarge = np.bincount(w[client & ~small], minlength=nw)
    total = np.bincount(w, minlength=nw)
    maxseg = np.zeros(nw)
    np.maximum.at(maxseg, w, rs)

    kinds = np.empty(nw, dtype=object)
    for i in range(nw):
        if total[i] == 0:
            kinds[i] = "idle"
        elif max(cbytes[i], sbytes[i]) / ph.window_s >= ph.bulk_bytes_per_s or (
            maxseg[i] >= ph.bulk_segment_min_bytes and cbytes[i] + sbytes[i] >= ph.bulk_min_bytes
        ):
            kinds[i] = "bulk"
        elif clarge[i] >= ph.mixed_min_client_large and csmall[i] < clarge[i]:
            kinds[i] = "mixed"
        elif csmall[i] >= 2:
            kinds[i] = "interactive"
        elif csmall[i] == 1 or (csmall[i] == 0 and 0 < clarge[i] < ph.mixed_min_client_large):
            kinds[i] = "maybe"  # a lone keystroke or a paste: interactive only next to typing
        else:
            kinds[i] = "idle"
    reach = 2  # windows: a lone keystroke or paste counts when typing is this close
    for i in range(nw):
        if kinds[i] == "maybe":
            near = any(kinds[j] == "interactive" for j in range(max(0, i - reach), min(nw, i + reach + 1)) if j != i)
            kinds[i] = "interactive" if near else "idle"

    # C5 rekey: a large client packet paired with a large server packet outside typing.
    big_c = np.flatnonzero(client & (rs >= ph.rekey_min_bytes))
    big_s_t = rt[(~client) & (rs >= ph.rekey_min_bytes)]
    for i in big_c:
        j = np.searchsorted(big_s_t, rt[i] - ph.rekey_pair_window_s)
        if j < len(big_s_t) and abs(big_s_t[j] - rt[i]) <= ph.rekey_pair_window_s:
            wi = int(w[i])
            if kinds[wi] in ("bulk",):
                continue
            if kinds[wi] == "interactive":
                stats.paste_pairs += 1  # S7: handled as a paste by the tick builder
                continue
            stats.rekey_events += 1
            kinds[wi] = "rekey"

    # Merge equal neighbouring windows into segments (record index ranges).
    starts = np.searchsorted(w, np.arange(nw), side="left") + pos
    i = 0
    while i < nw:
        j = i
        while j + 1 < nw and kinds[j + 1] == kinds[i]:
            j += 1
        i0, i1 = int(starts[i]), int(starts[j + 1]) if j + 1 < nw else n
        if i1 > i0:
            segs.append(Segment(str(kinds[i]), i0, i1, float(t[i0]), float(t[i1 - 1])))
        i = j + 1
    return segs, stats
