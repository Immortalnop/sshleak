"""Session type from traffic shape (finding L12): shell, file transfer, tunnel, exec."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from sshleak.flows.tracker import FlowView
from sshleak.phases.segmenter import Segment


@dataclass(frozen=True)
class SessionType:
    kind: str  # shell | file-transfer (scp) | file-transfer (sftp) | tunnel/forward | remote-command | unknown
    confidence: float
    shares: dict[str, float]
    evidence: str


def classify(view: FlowView, segments: list[Segment], small_max: int) -> SessionType:
    body = [s for s in segments if s.kind not in ("handshake", "auth", "rekey")]
    dur = {k: 0.0 for k in ("interactive", "bulk", "mixed", "idle")}
    nrec = {k: 0 for k in dur}
    for s in body:
        dur[s.kind] = dur.get(s.kind, 0.0) + max(s.duration, 0.0)
        nrec[s.kind] = nrec.get(s.kind, 0) + s.n
    active = dur["interactive"] + dur["bulk"] + dur["mixed"]
    shares = {k: round(v / active, 3) if active > 0 else 0.0 for k, v in dur.items() if k != "idle"}
    if not body or sum(nrec.values()) == 0:
        return SessionType("unknown", 0.0, shares, "no traffic after authentication")
    d, s = view.direction, view.size
    if nrec["bulk"] > 0 and shares.get("bulk", 0) >= 0.5:
        idx = np.concatenate([np.arange(sg.i0, sg.i1) for sg in body if sg.kind == "bulk"])
        cb = int(s[idx][d[idx] == 0].sum())
        sb = int(s[idx][d[idx] == 1].sum())
        heavy_dir = 0 if cb > sb else 1
        light = idx[d[idx] != heavy_dir]
        heavy_bytes = max(cb, sb)
        # sftp pipelines read/write requests: many small-to-medium packets from the
        # light side per 32 KiB moved; scp only sends occasional window adjusts.
        req = int(((s[light] > 40) & (s[light] <= small_max * 2)).sum())
        per_chunk = req / max(1.0, heavy_bytes / 32768)
        kind = "file-transfer (sftp)" if per_chunk >= 0.5 else "file-transfer (scp)"
        direction = "upload" if heavy_dir == 0 else "download"
        conf = min(0.9, 0.5 + shares["bulk"] * 0.4)
        return SessionType(kind, round(conf, 3), shares, f"{direction}, {heavy_bytes} bytes bulk, {req} requests")
    if shares.get("mixed", 0) >= 0.4:
        return SessionType("tunnel/forward", round(0.4 + 0.4 * shares["mixed"], 3), shares,
                           "bidirectional medium-size bursts without keystroke pattern")
    if shares.get("interactive", 0) >= 0.5:
        return SessionType("shell", round(min(0.95, 0.5 + 0.45 * shares["interactive"]), 3), shares,
                           "small client packets with small replies close behind")
    if nrec["interactive"] == 0 and nrec["mixed"] == 0:
        return SessionType("remote-command", 0.6, shares, "no typing; server output only (no pty)")
    return SessionType("unknown", 0.3, shares, "mixed shape")
