"""Streaming pcap / pcapng reader (own parser, see plan decision G12).

Reads from any binary stream, including a pipe from tcpdump. A short read or
a malformed block stops the iteration, keeps every frame read so far and
records the reason in ``ReaderStats`` (case C6). Nothing here writes anything.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import BinaryIO, Iterator

MAX_FRAME = 262_144
MAX_BLOCK = 16 * 1024 * 1024

_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000),  # little endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1000),
    b"\x4d\x3c\xb2\xa1": ("<", 1),  # nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1),
}
_SHB = b"\x0a\x0d\x0d\x0a"
_BOM_LE = b"\x4d\x3c\x2b\x1a"
_BOM_BE = b"\x1a\x2b\x3c\x4d"

BT_IDB, BT_OPB, BT_SPB, BT_ISB, BT_EPB = 1, 2, 3, 5, 6


@dataclass(slots=True)
class RawFrame:
    ts_ns: int
    linktype: int
    data: bytes
    orig_len: int


@dataclass
class ReaderStats:
    format: str = "unknown"
    frames: int = 0
    truncated: bool = False
    truncation_reason: str | None = None
    ts_resolution_ns: int | None = None
    if_drops: int | None = None
    skipped_blocks: int = 0
    snaplen: int | None = None
    linktypes: set[int] = field(default_factory=set)


class CaptureFormatError(Exception):
    pass


@dataclass(slots=True)
class _Iface:
    linktype: int
    snaplen: int
    tsresol: int = 6  # if_tsresol raw byte; default 10^-6
    tsoffset_s: int = 0

    def to_ns(self, ticks: int) -> int:
        v = self.tsresol
        if v & 0x80:
            ns = (ticks * 1_000_000_000) >> (v & 0x7F)
        elif v <= 9:
            ns = ticks * 10 ** (9 - v)
        else:
            ns = ticks // 10 ** (v - 9)
        return ns + self.tsoffset_s * 1_000_000_000

    def resolution_ns(self) -> int:
        v = self.tsresol
        if v & 0x80:
            return max(1, 1_000_000_000 >> (v & 0x7F))
        return 10 ** (9 - v) if v <= 9 else 1


class CaptureReader:
    """Iterate frames from a pcap or pcapng stream."""

    def __init__(self, stream: BinaryIO, *, max_frame: int = MAX_FRAME):
        self._s = stream
        self._max_frame = max_frame
        self.stats = ReaderStats()

    # -- helpers -----------------------------------------------------------
    def _read(self, n: int) -> bytes:
        chunks = []
        got = 0
        while got < n:
            b = self._s.read(n - got)
            if not b:
                break
            chunks.append(b)
            got += len(b)
        return b"".join(chunks)

    def _truncate(self, reason: str) -> None:
        self.stats.truncated = True
        self.stats.truncation_reason = reason

    # -- entry -------------------------------------------------------------
    def __iter__(self) -> Iterator[RawFrame]:
        head = self._read(4)
        if len(head) == 0:
            self._truncate("empty input")
            return
        if len(head) < 4:
            self._truncate("short file header")
            return
        if head in _PCAP_MAGIC:
            yield from self._pcap(head)
        elif head == _SHB:
            yield from self._pcapng()
        else:
            raise CaptureFormatError("not a pcap or pcapng file")

    # -- classic pcap ------------------------------------------------------
    def _pcap(self, magic: bytes) -> Iterator[RawFrame]:
        endian, mult = _PCAP_MAGIC[magic]
        rest = self._read(20)
        if len(rest) < 20:
            self._truncate("short pcap header")
            return
        _vmaj, _vmin, _zone, _sig, snaplen, network = struct.unpack(endian + "HHiIII", rest)
        linktype = network & 0x0FFFFFFF
        self.stats.format = "pcap"
        self.stats.snaplen = snaplen
        self.stats.ts_resolution_ns = mult
        self.stats.linktypes.add(linktype)
        rec = struct.Struct(endian + "IIII")
        while True:
            hdr = self._read(16)
            if not hdr:
                return
            if len(hdr) < 16:
                self._truncate("short record header")
                return
            sec, frac, incl, orig = rec.unpack(hdr)
            if incl > self._max_frame:
                self._truncate(f"record length {incl} exceeds limit")
                return
            data = self._read(incl)
            if len(data) < incl:
                self._truncate("short record body")
                return
            self.stats.frames += 1
            yield RawFrame(sec * 1_000_000_000 + frac * mult, linktype, data, orig)

    # -- pcapng ------------------------------------------------------------
    def _pcapng(self) -> Iterator[RawFrame]:
        self.stats.format = "pcapng"
        endian = self._section_header()
        if endian is None:
            return
        ifaces: list[_Iface] = []
        while True:
            hdr = self._read(8)
            if not hdr:
                return
            if len(hdr) < 8:
                self._truncate("short block header")
                return
            if hdr[:4] == _SHB:
                endian = self._section_header(hdr[4:8])
                if endian is None:
                    return
                ifaces = []
                continue
            btype, blen = struct.unpack(endian + "II", hdr)
            if blen < 12 or blen % 4 or blen > MAX_BLOCK:
                self._truncate(f"bad block length {blen}")
                return
            body = self._read(blen - 12)
            trailer = self._read(4)
            if len(body) < blen - 12 or len(trailer) < 4:
                self._truncate("short block body")
                return
            if struct.unpack(endian + "I", trailer)[0] != blen:
                self._truncate("block length trailer mismatch")
                return
            try:
                frame = self._block(endian, btype, body, ifaces)
            except (struct.error, IndexError):
                self._truncate("malformed block")
                return
            if frame is not None:
                self.stats.frames += 1
                yield frame

    def _section_header(self, raw_len: bytes | None = None) -> str | None:
        if raw_len is None:
            raw_len = self._read(4)
        bom = self._read(4)
        if len(raw_len) < 4 or len(bom) < 4:
            self._truncate("short section header")
            return None
        if bom == _BOM_LE:
            endian = "<"
        elif bom == _BOM_BE:
            endian = ">"
        else:
            self._truncate("bad byte-order magic")
            return None
        (blen,) = struct.unpack(endian + "I", raw_len)
        if blen < 28 or blen % 4 or blen > MAX_BLOCK:
            self._truncate("bad section header length")
            return None
        rest = self._read(blen - 12)
        if len(rest) < blen - 12:
            self._truncate("short section header")
            return None
        return endian

    @staticmethod
    def _options(endian: str, raw: bytes) -> Iterator[tuple[int, bytes]]:
        off = 0
        while off + 4 <= len(raw):
            code, ln = struct.unpack_from(endian + "HH", raw, off)
            off += 4
            if code == 0:
                return
            yield code, raw[off : off + ln]
            off += (ln + 3) & ~3

    def _block(self, endian: str, btype: int, body: bytes, ifaces: list[_Iface]) -> RawFrame | None:
        if btype == BT_IDB:
            linktype, _res, snaplen = struct.unpack_from(endian + "HHI", body, 0)
            iface = _Iface(linktype, snaplen)
            for code, val in self._options(endian, body[8:]):
                if code == 9 and val:
                    iface.tsresol = val[0]
                elif code == 14 and len(val) == 8:
                    iface.tsoffset_s = struct.unpack(endian + "q", val)[0]
            ifaces.append(iface)
            self.stats.linktypes.add(linktype)
            self.stats.snaplen = snaplen
            res = iface.resolution_ns()
            cur = self.stats.ts_resolution_ns
            self.stats.ts_resolution_ns = res if cur is None else max(cur, res)
            return None
        if btype in (BT_EPB, BT_OPB):
            if btype == BT_EPB:
                if_id, tsh, tsl, caplen, origlen = struct.unpack_from(endian + "IIIII", body, 0)
                off = 20
            else:
                if_id, _drops, tsh, tsl, caplen, origlen = struct.unpack_from(endian + "HHIIII", body, 0)
                off = 20
            if if_id >= len(ifaces) or caplen > self._max_frame or off + caplen > len(body):
                raise IndexError("bad packet block")
            iface = ifaces[if_id]
            data = body[off : off + caplen]
            return RawFrame(iface.to_ns((tsh << 32) | tsl), iface.linktype, data, origlen)
        if btype == BT_ISB:
            for code, val in self._options(endian, body[12:]):
                if code == 5 and len(val) == 8:  # isb_ifdrop
                    drops = struct.unpack(endian + "Q", val)[0]
                    self.stats.if_drops = (self.stats.if_drops or 0) + drops
            return None
        # SPB has no timestamp; name resolution, custom blocks etc. carry nothing we use.
        self.stats.skipped_blocks += 1
        return None
