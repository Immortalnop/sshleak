"""Live TCP socket discovery and socket -> process mapping (psutil, /proc).

Only runs at scan time (decision G2): nothing is collected before a scan.
Command lines are redacted unless the caller asks otherwise.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import psutil

from sshleak.flows.tracker import SSH_CLIENT_PROCS, SSH_SERVER_PROCS, Endpoint

REDACTED = "[redacted]"


@dataclass(frozen=True)
class ProcInfo:
    pid: int
    name: str
    uid: int | None
    cmdline: tuple[str, ...] = ()
    exe: str | None = None

    @property
    def is_ssh_client(self) -> bool:
        return self.name in SSH_CLIENT_PROCS

    @property
    def is_ssh_server(self) -> bool:
        return self.name in SSH_SERVER_PROCS

    def owned_by_me(self) -> bool:
        return self.uid is not None and self.uid == os.geteuid()


@dataclass
class SocketSnapshot:
    """What the host's socket table says at scan start (and later refreshes)."""

    listening: set[Endpoint] = field(default_factory=set)
    owners: dict[Endpoint, ProcInfo] = field(default_factory=dict)
    established: list[tuple[Endpoint, Endpoint]] = field(default_factory=list)
    unreadable_sockets: int = 0

    def owner_names(self) -> dict[Endpoint, str]:
        return {ep: p.name for ep, p in self.owners.items()}

    def merge(self, other: SocketSnapshot) -> None:
        self.listening |= other.listening
        self.owners.update(other.owners)
        seen = set(self.established)
        self.established.extend(e for e in other.established if e not in seen)


def _norm_ip(ip: str) -> str:
    if ip.startswith("::ffff:") and "." in ip:
        return ip[7:]
    return ip


def _proc(pid: int, cache: dict[int, ProcInfo | None]) -> ProcInfo | None:
    if pid in cache:
        return cache[pid]
    info: ProcInfo | None
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            name = p.name()
            try:
                uid = p.uids().real
            except psutil.Error:
                uid = None
            try:
                cmd = tuple(p.cmdline())
            except psutil.Error:
                cmd = ()
            try:
                exe = p.exe() or None
            except psutil.Error:
                exe = None
        info = ProcInfo(pid, name, uid, cmd, exe)
    except psutil.Error:
        info = None
    cache[pid] = info
    return info


def snapshot() -> SocketSnapshot:
    snap = SocketSnapshot()
    cache: dict[int, ProcInfo | None] = {}
    try:
        conns = psutil.net_connections(kind="tcp")
    except (psutil.Error, OSError):
        return snap
    for c in conns:
        if not c.laddr:
            continue
        local: Endpoint = (_norm_ip(c.laddr.ip), c.laddr.port)
        if c.status == psutil.CONN_LISTEN:
            snap.listening.add(local)
            if local[0] in ("0.0.0.0", "::"):
                snap.listening.add(("127.0.0.1", local[1]) if local[0] == "0.0.0.0" else ("::1", local[1]))
                if local[0] == "::":
                    snap.listening.add(("127.0.0.1", local[1]))
        if c.pid:
            info = _proc(c.pid, cache)
            if info is not None:
                snap.owners[local] = info
        else:
            snap.unreadable_sockets += 1
        if c.status == psutil.CONN_ESTABLISHED and c.raddr:
            remote: Endpoint = (_norm_ip(c.raddr.ip), c.raddr.port)
            snap.established.append((local, remote))
    return snap


def redact_cmdline(info: ProcInfo, redact: bool) -> list[str]:
    if not info.cmdline:
        return []
    if redact:
        return [os.path.basename(info.cmdline[0]), REDACTED] if len(info.cmdline) > 1 else [os.path.basename(info.cmdline[0])]
    return list(info.cmdline)
