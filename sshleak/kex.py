"""KEXINIT parsing and RFC 4253 7.1 algorithm negotiation (cleartext names only)."""

from __future__ import annotations

import struct
from dataclasses import dataclass

MSG_KEXINIT = 20
MSG_NEWKEYS = 21
MAX_NAMELIST = 8192

AEAD_CIPHERS = frozenset(
    {"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"}
)
PSEUDO_PREFIXES = ("ext-info-", "kex-strict-")
STRICT_CLIENT = "kex-strict-c-v00@openssh.com"
STRICT_SERVER = "kex-strict-s-v00@openssh.com"
IMPLICIT_MAC = "<implicit>"


@dataclass(frozen=True, slots=True)
class KexInit:
    kex: tuple[str, ...]
    hostkey: tuple[str, ...]
    enc_c2s: tuple[str, ...]
    enc_s2c: tuple[str, ...]
    mac_c2s: tuple[str, ...]
    mac_s2c: tuple[str, ...]
    comp_c2s: tuple[str, ...]
    comp_s2c: tuple[str, ...]

    @property
    def role_hint(self) -> str | None:
        """'client' or 'server' from the ext-info / strict-kex markers, if present."""
        names = set(self.kex)
        if "ext-info-c" in names or STRICT_CLIENT in names:
            return "client"
        if "ext-info-s" in names or STRICT_SERVER in names:
            return "server"
        return None


class KexParseError(ValueError):
    pass


def parse_kexinit(payload: bytes | memoryview) -> KexInit:
    """Parse an SSH_MSG_KEXINIT payload (starting at the message code)."""
    buf = bytes(payload)
    if not buf or buf[0] != MSG_KEXINIT:
        raise KexParseError("not a KEXINIT")
    off = 17  # code + 16-byte cookie
    lists: list[tuple[str, ...]] = []
    for _ in range(10):
        if off + 4 > len(buf):
            raise KexParseError("short name-list header")
        (n,) = struct.unpack_from(">I", buf, off)
        off += 4
        if n > MAX_NAMELIST or off + n > len(buf):
            raise KexParseError("name-list too long")
        raw = buf[off : off + n]
        off += n
        if any(b < 0x21 or b > 0x7E for b in raw):
            raise KexParseError("name-list has non-printable bytes")
        text = raw.decode("ascii")
        lists.append(tuple(x for x in text.split(",") if x))
    if off + 5 > len(buf):
        raise KexParseError("short KEXINIT trailer")
    return KexInit(*lists[:8])


@dataclass(frozen=True, slots=True)
class Negotiated:
    kex: str | None
    hostkey: str | None
    enc_c2s: str | None
    enc_s2c: str | None
    mac_c2s: str | None
    mac_s2c: str | None
    comp_c2s: str | None
    comp_s2c: str | None
    strict_kex: bool


def _first_match(client: tuple[str, ...], server: tuple[str, ...]) -> str | None:
    offered = set(server)
    for name in client:
        if name.startswith(PSEUDO_PREFIXES):
            continue
        if name in offered:
            return name
    return None


def negotiate(client: KexInit, server: KexInit) -> Negotiated:
    enc_c2s = _first_match(client.enc_c2s, server.enc_c2s)
    enc_s2c = _first_match(client.enc_s2c, server.enc_s2c)
    mac_c2s = IMPLICIT_MAC if enc_c2s in AEAD_CIPHERS else _first_match(client.mac_c2s, server.mac_c2s)
    mac_s2c = IMPLICIT_MAC if enc_s2c in AEAD_CIPHERS else _first_match(client.mac_s2c, server.mac_s2c)
    return Negotiated(
        kex=_first_match(client.kex, server.kex),
        hostkey=_first_match(client.hostkey, server.hostkey),
        enc_c2s=enc_c2s,
        enc_s2c=enc_s2c,
        mac_c2s=mac_c2s,
        mac_s2c=mac_s2c,
        comp_c2s=_first_match(client.comp_c2s, server.comp_c2s),
        comp_s2c=_first_match(client.comp_s2c, server.comp_s2c),
        strict_kex=STRICT_CLIENT in client.kex and STRICT_SERVER in server.kex,
    )


def build_kexinit_payload(k: KexInit, cookie: bytes = b"\x00" * 16) -> bytes:
    """Encode a KEXINIT payload. Used by the synthetic lab generator and tests."""
    out = bytearray([MSG_KEXINIT]) + cookie
    for lst in (k.kex, k.hostkey, k.enc_c2s, k.enc_s2c, k.mac_c2s, k.mac_s2c, k.comp_c2s, k.comp_s2c, (), ()):
        raw = ",".join(lst).encode("ascii")
        out += struct.pack(">I", len(raw)) + raw
    out += b"\x00" + b"\x00\x00\x00\x00"
    return bytes(out)
