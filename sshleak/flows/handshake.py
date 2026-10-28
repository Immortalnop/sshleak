"""Per-direction parser for the cleartext part of an SSH connection.

Decision G1: payload bytes of the banner and the cleartext binary packets up to
NEWKEYS pass through a bounded buffer here, are parsed for the software
version and algorithm names, and are dropped. Once a direction has sent
NEWKEYS (or the parse fails) this parser refuses further bytes, so encrypted
payload never enters it.
"""

from __future__ import annotations

import struct

from sshleak.kex import MSG_KEXINIT, MSG_NEWKEYS, KexInit, KexParseError, parse_kexinit
from sshleak.versions import Banner, parse_banner

MAX_BUFFER = 65_536
MAX_PRE_BANNER_LINES = 32
MAX_CLEAR_PACKET = 35_000

_U32 = struct.Struct(">I")


def seq_lt(a: int, b: int) -> bool:
    return ((a - b) & 0xFFFFFFFF) > 0x7FFFFFFF


class SideHandshake:
    """State machine for one direction: banner -> binary -> encrypted (or failed)."""

    __slots__ = ("is_client", "state", "banner", "kexinit", "failure", "_buf", "_next", "_lines", "late")

    def __init__(self, is_client: bool | None = None):
        self.is_client = is_client
        self.state = "banner"
        self.banner: Banner | None = None
        self.kexinit: KexInit | None = None
        self.failure: str | None = None
        self._buf = bytearray()
        self._next: int | None = None
        self._lines = 0
        self.late = False

    @property
    def active(self) -> bool:
        return self.state in ("banner", "binary")

    def _fail(self, reason: str) -> None:
        self.state = "failed"
        self.failure = reason
        self._buf = bytearray()  # drop any held bytes immediately

    def _finish(self) -> None:
        self.state = "encrypted"
        self._buf = bytearray()

    def feed(self, seq: int, payload_len: int, head: memoryview, *, first_data_late: bool = False) -> None:
        """Consume one TCP segment's captured payload for this direction."""
        if not self.active or payload_len == 0:
            return
        if self._next is None:
            if first_data_late and bytes(head[:4]) != b"SSH-":
                # Joined mid-stream: never buffer encrypted bytes looking for a banner.
                self.late = True
                self._fail("late-join")
                return
            self._next = seq
        offset = 0
        if seq != self._next:
            if seq_lt(seq, self._next):
                end = (seq + payload_len) & 0xFFFFFFFF
                if not seq_lt(self._next, end):
                    return  # pure retransmit
                offset = (self._next - seq) & 0xFFFFFFFF
            else:
                self._fail("gap in cleartext handshake")
                return
        chunk = head[offset:]
        self._buf += chunk
        self._next = (seq + payload_len) & 0xFFFFFFFF
        snap_short = len(head) < payload_len
        if len(self._buf) > MAX_BUFFER:
            self._fail("handshake buffer limit")
            return
        self._parse()
        if snap_short and self.active:
            self._fail("cleartext segment longer than snaplen")

    def _parse(self) -> None:
        while self.state == "banner":
            idx = self._buf.find(b"\n")
            if idx < 0:
                if len(self._buf) > 8192:
                    self._fail("no identification line")
                return
            line = bytes(self._buf[:idx]).rstrip(b"\r")
            del self._buf[: idx + 1]
            if line.startswith(b"SSH-"):
                banner = parse_banner(line)
                if banner is None:
                    self._fail("malformed identification line")
                    return
                self.banner = banner
                self.state = "binary"
            else:
                # RFC 4253 allows other lines before the server banner, never from the client.
                self._lines += 1
                if self.is_client or self._lines > MAX_PRE_BANNER_LINES:
                    self._fail("not ssh")
                    return
        while self.state == "binary" and len(self._buf) >= 5:
            (plen,) = _U32.unpack_from(self._buf, 0)
            if plen < 5 or plen > MAX_CLEAR_PACKET:
                self._fail("bad cleartext packet length")
                return
            if len(self._buf) < 4 + plen:
                return
            padlen = self._buf[4]
            if padlen + 1 >= plen:
                self._fail("bad padding length")
                return
            payload = memoryview(self._buf)[5 : 4 + plen - padlen]
            code = payload[0]
            try:
                if code == MSG_KEXINIT and self.kexinit is None:
                    self.kexinit = parse_kexinit(payload)
            except KexParseError as e:
                payload.release()
                self._fail(f"bad KEXINIT: {e}")
                return
            payload.release()
            del self._buf[: 4 + plen]
            if code == MSG_NEWKEYS:
                self._finish()
                return
