"""SSH banner and software-version parsing (cleartext identification strings only)."""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_BANNER = 255  # RFC 4253 4.2

_OPENSSH = re.compile(r"^OpenSSH(?:_for_Windows)?_(\d+)\.(\d+)(?:p(\d+))?")
_IMPLS = (
    ("dropbear", re.compile(r"^dropbear[_-]?(\d+)\.(\d+)", re.I)),
    ("libssh", re.compile(r"^libssh[_-]?(\d+)\.(\d+)", re.I)),
    ("putty", re.compile(r"^PuTTY", re.I)),
    ("paramiko", re.compile(r"^paramiko[_-]?(\d+)\.(\d+)", re.I)),
    ("go", re.compile(r"^Go$", re.I)),
    ("asyncssh", re.compile(r"^AsyncSSH[_-]?(\d+)\.(\d+)", re.I)),
)


@dataclass(frozen=True, slots=True)
class Banner:
    proto: str
    software: str
    comments: str | None

    @property
    def line(self) -> str:
        base = f"SSH-{self.proto}-{self.software}"
        return f"{base} {self.comments}" if self.comments else base


@dataclass(frozen=True, slots=True)
class Software:
    raw: str
    impl: str  # openssh | dropbear | libssh | putty | paramiko | go | asyncssh | other
    version: tuple[int, int] | None

    @property
    def is_openssh(self) -> bool:
        return self.impl == "openssh" and self.version is not None

    def at_least(self, major: int, minor: int) -> bool | None:
        """None when the version cannot be compared (unknown implementation)."""
        if not self.is_openssh:
            return None
        return self.version >= (major, minor)


def parse_banner(line: bytes) -> Banner | None:
    """Parse an identification line (without CR LF). Returns None if not SSH-2."""
    if len(line) > MAX_BANNER or not line.startswith(b"SSH-"):
        return None
    try:
        text = line.decode("ascii")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 0x20 or ord(c) > 0x7E for c in text):
        return None
    rest = text[4:]
    proto, sep, tail = rest.partition("-")
    if not sep or proto not in ("2.0", "1.99"):
        return None
    software, _, comments = tail.partition(" ")
    if not software:
        return None
    return Banner(proto=proto, software=software, comments=comments or None)


def parse_software(software: str) -> Software:
    m = _OPENSSH.match(software)
    if m:
        return Software(software, "openssh", (int(m.group(1)), int(m.group(2))))
    for impl, rx in _IMPLS:
        m = rx.match(software)
        if m:
            ver = (int(m.group(1)), int(m.group(2))) if m.groups() else None
            return Software(software, impl, ver)
    return Software(software, "other", None)
