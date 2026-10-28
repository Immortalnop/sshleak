"""Per-flow metadata records: time (ns), direction, TCP payload length.

Records never hold payload bytes. Retransmits are dropped, reordered segments
that fill a sequence hole are kept (case C4), memory per flow is capped with a
rolling window, and the number of flows is capped with eviction (case F4).
"""

from __future__ import annotations

from array import array
from dataclasses import dataclass, field

import numpy as np

from sshleak.capture.decode import ACK, FIN, RST, SYN, Packet
from sshleak.flows.handshake import SideHandshake, seq_lt

Endpoint = tuple[str, int]
SSH_SERVER_PROCS = frozenset({"sshd", "sshd-session", "sshd-auth", "dropbear"})
SSH_CLIENT_PROCS = frozenset({"ssh", "dbclient"})


@dataclass
class Limits:
    max_records_per_flow: int = 100_000
    max_flows: int = 512
    clock_step_tolerance_ns: int = 5_000_000
    max_holes: int = 32


def _other(side: str) -> str:
    return "b" if side == "a" else "a"


class FlowState:
    def __init__(self, a: Endpoint, b: Endpoint, order: int, ts_ns: int, started_with_syn: bool):
        self.a, self.b = a, b
        self.order = order
        self.first_ts = ts_ns
        self.last_ts = ts_ns
        self.started_with_syn = started_with_syn
        self.syn_from: str | None = None
        self.hs = {"a": SideHandshake(), "b": SideHandshake()}
        self.ts = array("q")
        self.ln = array("i")
        self.fa = array("b")
        self.base = 0  # records trimmed from the front
        self.hs_done_idx: int | None = None  # absolute record index where both sides went encrypted
        self.step_idx: list[int] = []
        self.next_seq: dict[str, int | None] = {"a": None, "b": None}
        self.holes: dict[str, list[tuple[int, int]]] = {"a": [], "b": []}
        self.retransmits = 0
        self.reordered = 0
        self.seq_gaps = 0
        self.pure_acks = 0
        self.closed = False
        self.data_packets = 0
        self.data_bytes = 0

    # -- identification ----------------------------------------------------
    @property
    def key_str(self) -> str:
        return f"{self.a[0]}:{self.a[1]}-{self.b[0]}:{self.b[1]}"

    def banner_seen(self) -> bool:
        return any(h.banner is not None for h in self.hs.values())

    @property
    def late_join(self) -> bool:
        return not self.started_with_syn and not self.banner_seen()

    def ssh_status(self) -> str:
        """'ssh' (banner), 'not_ssh' (banner mismatch) or 'unknown' (late-join / no data)."""
        if self.banner_seen():
            return "ssh"
        if self.started_with_syn:
            failures = [h.failure for h in self.hs.values() if h.failure]
            if any(f in ("not ssh", "malformed identification line", "no identification line") for f in failures):
                return "not_ssh"
        return "unknown"

    def resolve_client(
        self,
        listening: set[Endpoint] | None = None,
        owners: dict[Endpoint, str] | None = None,
    ) -> tuple[str, str]:
        """Return (client side 'a'|'b', how it was decided)."""
        if self.syn_from:
            return self.syn_from, "syn"
        for side in ("a", "b"):
            k = self.hs[side].kexinit
            hint = k.role_hint if k else None
            if hint == "client":
                return side, "kexinit"
            if hint == "server":
                return _other(side), "kexinit"
        ends = {"a": self.a, "b": self.b}
        if listening:
            la, lb = self.a in listening, self.b in listening
            if la != lb:
                return ("b" if la else "a"), "listening socket"
        if owners:
            for side in ("a", "b"):
                if owners.get(ends[side]) in SSH_SERVER_PROCS:
                    return _other(side), "process"
        pa, pb = self.a[1], self.b[1]
        if pa == 22 or pb == 22:
            return ("b" if pa == 22 else "a"), "port"
        return ("b" if pa < pb else "a"), "port"

    # -- ingestion -----------------------------------------------------------
    def _seq_check(self, side: str, seq: int, length: int) -> int:
        """Return the number of new payload bytes in this segment (0 = retransmit)."""
        nxt = self.next_seq[side]
        end = (seq + length) & 0xFFFFFFFF
        if nxt is None:
            self.next_seq[side] = end
            return length
        if seq == nxt:
            self.next_seq[side] = end
            return length
        if seq_lt(nxt, seq):  # jump ahead: a hole (lost in capture or reordered)
            holes = self.holes[side]
            holes.append((nxt, seq))
            if len(holes) > 32:
                del holes[0]
            self.seq_gaps += 1
            self.next_seq[side] = end
            return length
        # seq < nxt: either fills a hole (reordering) or is a retransmit
        holes = self.holes[side]
        for i, (h0, h1) in enumerate(holes):
            if not seq_lt(seq, h0) and seq_lt(seq, h1):
                del holes[i]
                self.reordered += 1
                self.seq_gaps -= 1
                return length
        if seq_lt(nxt, end):  # partial overlap: keep the new tail only
            self.next_seq[side] = end
            self.retransmits += 1
            return (end - nxt) & 0xFFFFFFFF
        self.retransmits += 1
        return 0

    def add(self, pkt: Packet, head: memoryview, side: str, limits: Limits) -> None:
        if pkt.flags & SYN and not pkt.flags & ACK:
            self.syn_from = side
        if pkt.flags & (FIN | RST):
            self.closed = True
        if pkt.ts_ns < self.last_ts - limits.clock_step_tolerance_ns:
            self.step_idx.append(self.base + len(self.ts))
        self.last_ts = max(self.last_ts, pkt.ts_ns)
        if pkt.payload_len == 0:
            if not pkt.flags & (SYN | FIN | RST):
                self.pure_acks += 1
            return
        new_len = self._seq_check(side, pkt.seq, pkt.payload_len)
        hs = self.hs[side]
        if hs.active:
            if self.syn_from is not None and hs.is_client is None:
                hs.is_client = side == self.syn_from
            hs.feed(pkt.seq, pkt.payload_len, head, first_data_late=not self.started_with_syn)
        if new_len == 0:
            return
        self.ts.append(pkt.ts_ns)
        self.ln.append(new_len)
        self.fa.append(1 if side == "a" else 0)
        self.data_packets += 1
        self.data_bytes += new_len
        if self.hs_done_idx is None and self.started_with_syn and not any(h.active for h in self.hs.values()):
            self.hs_done_idx = self.base + len(self.ts)
        cap = limits.max_records_per_flow
        if len(self.ts) > cap + cap // 4:
            cut = len(self.ts) - cap
            del self.ts[:cut], self.ln[:cut], self.fa[:cut]
            self.base += cut

    # -- analysis view -------------------------------------------------------
    def view(self, client_side: str, step_window_ns: int = 1_000_000_000) -> FlowView:
        ts = np.frombuffer(self.ts, dtype=np.int64).copy()
        size = np.frombuffer(self.ln, dtype=np.int32).copy()
        from_a = np.frombuffer(self.fa, dtype=np.int8)
        direction = (from_a == 0).astype(np.int8) if client_side == "a" else from_a.astype(np.int8)
        # direction: 0 = client->server, 1 = server->client
        keep = np.ones(len(ts), dtype=bool)
        steps = [i - self.base for i in self.step_idx if i - self.base > 0]
        for i in steps:  # C3: drop a window around each clock step, re-base what follows
            if i >= len(ts):
                continue
            before, after = ts[i - 1], ts[i]
            keep &= ~((ts >= before - step_window_ns) & (np.arange(len(ts)) < i))
            keep &= ~((ts <= after + step_window_ns) & (np.arange(len(ts)) >= i))
            ts[i:] += (before - after) + 10 * step_window_ns
        hs_end = None
        if self.hs_done_idx is not None and self.hs_done_idx - self.base > 0:
            hs_end = int(np.count_nonzero(keep[: self.hs_done_idx - self.base]))
        ts, direction, size = ts[keep], direction[keep], size[keep]
        order = np.argsort(ts, kind="stable")
        return FlowView(
            ts_ns=ts[order],
            direction=direction[order],
            size=size[order],
            hs_end=hs_end,
            clock_steps=len(steps),
            dropped_for_steps=int(np.count_nonzero(~keep)),
        )


@dataclass
class FlowView:
    ts_ns: np.ndarray
    direction: np.ndarray
    size: np.ndarray
    hs_end: int | None
    clock_steps: int = 0
    dropped_for_steps: int = 0

    def __len__(self) -> int:
        return len(self.ts_ns)

    @property
    def t(self) -> np.ndarray:
        """Seconds since the first record."""
        if len(self.ts_ns) == 0:
            return np.zeros(0)
        return (self.ts_ns - self.ts_ns[0]) / 1e9


@dataclass
class TrackerStats:
    evicted: int = 0
    clock_steps: int = 0
    packets: int = 0


class FlowTracker:
    def __init__(self, limits: Limits | None = None):
        self.limits = limits or Limits()
        self.flows: dict[tuple[Endpoint, Endpoint], FlowState] = {}
        self.finished: list[FlowState] = []
        self._order = 0
        self._last_ts: int | None = None
        self.stats = TrackerStats()
        self.clock_step_times: list[int] = []

    def add(self, pkt: Packet, head: memoryview) -> None:
        self.stats.packets += 1
        if self._last_ts is not None and pkt.ts_ns < self._last_ts - self.limits.clock_step_tolerance_ns:
            self.stats.clock_steps += 1
            self.clock_step_times.append(pkt.ts_ns)
        self._last_ts = pkt.ts_ns if self._last_ts is None else max(self._last_ts, pkt.ts_ns)
        src: Endpoint = (pkt.src, pkt.sport)
        dst: Endpoint = (pkt.dst, pkt.dport)
        a, b = (src, dst) if src <= dst else (dst, src)
        key = (a, b)
        syn = bool(pkt.flags & SYN) and not pkt.flags & ACK
        flow = self.flows.get(key)
        if flow is not None and syn and flow.closed:
            self.finished.append(self.flows.pop(key))  # 4-tuple reused for a new connection
            flow = None
        if flow is None:
            if len(self.flows) >= self.limits.max_flows:
                self._evict()
            self._order += 1
            flow = FlowState(a, b, self._order, pkt.ts_ns, started_with_syn=syn)
            self.flows[key] = flow
        flow.add(pkt, head, "a" if src == a else "b", self.limits)

    def _evict(self) -> None:
        """Evict closed or non-SSH flows first, then the least recently active."""
        def rank(item: tuple) -> tuple:
            f = item[1]
            status = f.ssh_status()
            return (0 if f.closed else 1, 0 if status == "not_ssh" else 1, f.last_ts)

        victim = min(self.flows.items(), key=rank)[0]
        del self.flows[victim]
        self.stats.evicted += 1

    def all_flows(self) -> list[FlowState]:
        return sorted([*self.finished, *self.flows.values()], key=lambda f: f.order)
