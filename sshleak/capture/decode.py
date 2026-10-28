"""Link / IP / TCP header decoding.

``decode`` returns header metadata plus a memoryview of whatever TCP payload
bytes were captured. Only the handshake parser may look at that view, and it
must not keep it (plan decision G1).
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from sshleak.capture.pcapfile import RawFrame

# link types
LT_NULL, LT_EN10MB, LT_RAW, LT_LOOP, LT_SLL, LT_IPV4, LT_IPV6, LT_SLL2 = 0, 1, 101, 108, 113, 228, 229, 276
LT_RAW_ALT = (12, 14)
SUPPORTED_LINKTYPES = frozenset({LT_NULL, LT_EN10MB, LT_RAW, LT_LOOP, LT_SLL, LT_IPV4, LT_IPV6, LT_SLL2, *LT_RAW_ALT})

ARPHRD_LOOPBACK = 772
PACKET_OUTGOING = 4

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

_IPV6_EXT = {0, 43, 60, 51, 135}  # hop-by-hop, routing, dest opts, AH, mobility
_U16 = struct.Struct(">H")


@dataclass(slots=True)
class Packet:
    ts_ns: int
    src: str
    dst: str
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    payload_len: int
    ipv: int


@dataclass
class DecodeStats:
    decoded: int = 0
    non_tcp: int = 0
    fragments: int = 0
    malformed: int = 0
    loopback_duplicates: int = 0
    unsupported_link: int = 0
    unsupported_linktypes: set[int] = field(default_factory=set)


def _link(frame: RawFrame, stats: DecodeStats) -> tuple[int, int] | None:
    """Return (ip_offset, ethertype-ish version hint 0/4/6) or None to drop."""
    d = frame.data
    lt = frame.linktype
    if lt == LT_EN10MB:
        if len(d) < 14:
            return None
        off, etype = 14, _U16.unpack_from(d, 12)[0]
        for _ in range(2):  # 802.1Q / QinQ
            if etype in (0x8100, 0x88A8) and len(d) >= off + 4:
                etype = _U16.unpack_from(d, off + 2)[0]
                off += 4
        if etype == 0x0800:
            return off, 4
        if etype == 0x86DD:
            return off, 6
        return None
    if lt in (LT_RAW, *LT_RAW_ALT):
        return 0, 0
    if lt == LT_IPV4:
        return 0, 4
    if lt == LT_IPV6:
        return 0, 6
    if lt in (LT_NULL, LT_LOOP):
        if len(d) < 4:
            return None
        le, be = struct.unpack_from("<I", d)[0], struct.unpack_from(">I", d)[0]
        fam = be if lt == LT_LOOP else (le if le < 256 else be)
        if fam == 2:
            return 4, 4
        if fam in (10, 24, 28, 30):
            return 4, 6
        return None
    if lt == LT_SLL:
        if len(d) < 16:
            return None
        pkttype, hatype = struct.unpack_from(">HH", d, 0)
        proto = _U16.unpack_from(d, 14)[0]
        if pkttype == PACKET_OUTGOING and hatype == ARPHRD_LOOPBACK:
            stats.loopback_duplicates += 1  # G3: loopback seen twice on raw sockets
            return None
        return (16, 4) if proto == 0x0800 else (16, 6) if proto == 0x86DD else None
    if lt == LT_SLL2:
        if len(d) < 20:
            return None
        proto = _U16.unpack_from(d, 0)[0]
        hatype = _U16.unpack_from(d, 8)[0]
        pkttype = d[10]
        if pkttype == PACKET_OUTGOING and hatype == ARPHRD_LOOPBACK:
            stats.loopback_duplicates += 1
            return None
        return (20, 4) if proto == 0x0800 else (20, 6) if proto == 0x86DD else None
    stats.unsupported_link += 1
    stats.unsupported_linktypes.add(lt)
    return None


def decode(frame: RawFrame, stats: DecodeStats) -> tuple[Packet, memoryview] | None:
    link = _link(frame, stats)
    if link is None:
        stats.non_tcp += 1
        return None
    off, ver = link
    d = frame.data
    if len(d) <= off:
        stats.malformed += 1
        return None
    if ver == 0:
        ver = d[off] >> 4
    try:
        if ver == 4:
            vihl = d[off]
            ihl = (vihl & 0x0F) * 4
            if vihl >> 4 != 4 or ihl < 20 or len(d) < off + 20:
                stats.malformed += 1
                return None
            total = _U16.unpack_from(d, off + 2)[0]
            frag = _U16.unpack_from(d, off + 6)[0]
            if frag & 0x3FFF:  # MF set or offset != 0
                stats.fragments += 1
                return None
            if d[off + 9] != 6:
                stats.non_tcp += 1
                return None
            src = socket.inet_ntop(socket.AF_INET, d[off + 12 : off + 16])
            dst = socket.inet_ntop(socket.AF_INET, d[off + 16 : off + 20])
            if total == 0:  # TSO capture may zero the field; fall back to the wire length
                total = frame.orig_len - off
            ip_payload = total - ihl
            tcp_off = off + ihl
        elif ver == 6:
            if len(d) < off + 40:
                stats.malformed += 1
                return None
            plen = _U16.unpack_from(d, off + 4)[0]
            nh = d[off + 6]
            src = socket.inet_ntop(socket.AF_INET6, d[off + 8 : off + 24])
            dst = socket.inet_ntop(socket.AF_INET6, d[off + 24 : off + 40])
            p = off + 40
            ip_payload = plen
            for _ in range(8):
                if nh == 44:  # fragment header
                    if len(d) < p + 8:
                        raise IndexError
                    if _U16.unpack_from(d, p + 2)[0] & 0xFFF9:
                        stats.fragments += 1
                        return None
                    nh = d[p]
                    ip_payload -= 8
                    p += 8
                elif nh in _IPV6_EXT:
                    if len(d) < p + 2:
                        raise IndexError
                    hl = (d[p + 1] + 2) * 4 if nh == 51 else (d[p + 1] + 1) * 8
                    nh = d[p]
                    ip_payload -= hl
                    p += hl
                else:
                    break
            if nh != 6:
                stats.non_tcp += 1
                return None
            if plen == 0:  # jumbogram / TSO
                ip_payload = frame.orig_len - p
            tcp_off = p
        else:
            stats.malformed += 1
            return None
        if len(d) < tcp_off + 20:
            stats.malformed += 1
            return None
        sport, dport, seq, ack, doff_flags = struct.unpack_from(">HHIIH", d, tcp_off)
        thl = (doff_flags >> 12) * 4
        if thl < 20:
            stats.malformed += 1
            return None
        payload_len = ip_payload - thl
        if payload_len < 0:
            stats.malformed += 1
            return None
        start = tcp_off + thl
        captured = max(0, min(payload_len, len(d) - start))
        stats.decoded += 1
        pkt = Packet(frame.ts_ns, src, dst, sport, dport, seq, ack, doff_flags & 0x3F, payload_len, ver)
        return pkt, memoryview(d)[start : start + captured]
    except (IndexError, struct.error, ValueError):
        stats.malformed += 1
        return None
