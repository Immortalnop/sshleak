"""Safety guard: runs before any capture starts (cases P1-P4).

Loopback interfaces and loopback targets are allowed by default. Anything else
needs --allow-nonlocal plus a valid, unexpired scope file that lists the
interface and every target, and the run is appended to an audit log.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from sshleak.env import iface_exists, iface_is_loopback
from sshleak.errors import EnvironmentProblem, SafetyRefusal

DEFAULT_TARGETS = ("127.0.0.1", "::1")
IpNet = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Scope:
    owner: str
    signed_off_by: str
    expires: dt.date
    interfaces: tuple[str, ...]
    targets: tuple[IpNet, ...]
    path: str
    sha256: str


@dataclass
class CaptureRequest:
    iface: str = "lo"
    targets: list[str] = field(default_factory=lambda: list(DEFAULT_TARGETS))
    allow_nonlocal: bool = False
    scope_path: str | None = None
    all_users: bool = False
    ports: list[int] = field(default_factory=list)


@dataclass(frozen=True)
class Approved:
    iface: str
    targets: tuple[IpNet, ...]
    nonlocal_: bool
    scope: Scope | None
    all_users: bool
    bpf: str


def parse_targets(values: list[str]) -> tuple[IpNet, ...]:
    nets: list[IpNet] = []
    for v in values:
        try:
            nets.append(ipaddress.ip_network(v.strip(), strict=False))
        except ValueError:
            raise SafetyRefusal(f"target {v!r} is not an IP address or network", case="P2") from None
    return tuple(nets)


def _is_loopback_net(net: IpNet) -> bool:
    return net.is_loopback or (isinstance(net, ipaddress.IPv6Network) and net.network_address == ipaddress.IPv6Address("::1"))


def load_scope(path: str, *, today: dt.date | None = None) -> Scope:
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError:
        raise SafetyRefusal(f"scope file {path!r} is missing or unreadable", case="P2") from None
    try:
        data = tomllib.loads(raw.decode("utf-8"))["scope"]
        owner = str(data["owner"]).strip()
        signed = str(data["signed_off_by"]).strip()
        expires = data["expires"]
        ifaces = tuple(str(x) for x in data["interfaces"])
        targets = parse_targets([str(x) for x in data["targets"]])
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise SafetyRefusal(
            f"scope file {path!r} is invalid ({e.__class__.__name__}: {e}); "
            "it needs [scope] owner, signed_off_by, expires (date), interfaces, targets",
            case="P2",
        ) from None
    if isinstance(expires, dt.datetime):
        expires = expires.date()
    if not isinstance(expires, dt.date):
        raise SafetyRefusal("scope 'expires' must be a TOML date, e.g. 2026-12-31", case="P2")
    if not owner or not signed or not ifaces or not targets:
        raise SafetyRefusal("scope file has empty owner, signed_off_by, interfaces or targets", case="P2")
    if expires < (today or dt.date.today()):
        raise SafetyRefusal(f"scope file expired on {expires.isoformat()}", case="P3")
    return Scope(owner, signed, expires, ifaces, targets, str(p.resolve()), hashlib.sha256(raw).hexdigest())


def build_bpf(targets: tuple[IpNet, ...], ports: list[int]) -> str:
    """Filter text is built only from validated addresses and integer ports."""
    parts = []
    for net in targets:
        if net.num_addresses == 1:
            parts.append(f"host {net.network_address}")
        else:
            parts.append(f"net {net.with_prefixlen}")
    expr = "tcp and (" + " or ".join(parts) + ")"
    if ports:
        expr += " and (" + " or ".join(f"port {int(p)}" for p in ports) + ")"
    return expr


def audit_log_path() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return Path(base) / "sshleak" / "audit.jsonl"


def _audit(approved: Approved) -> None:
    path = audit_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "time": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "uid": os.geteuid(),
        "iface": approved.iface,
        "targets": [str(t) for t in approved.targets],
        "scope_file": approved.scope.path if approved.scope else None,
        "scope_sha256": approved.scope.sha256 if approved.scope else None,
        "scope_owner": approved.scope.owner if approved.scope else None,
    }
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")


def approve(req: CaptureRequest, *, today: dt.date | None = None) -> Approved:
    if not iface_exists(req.iface):
        raise EnvironmentProblem(f"interface {req.iface!r} does not exist", case="E3")
    for p in req.ports:
        if not 0 < p < 65536:
            raise SafetyRefusal(f"port {p} out of range")
    targets = parse_targets(req.targets or list(DEFAULT_TARGETS))
    if req.all_users and os.geteuid() != 0:
        raise SafetyRefusal("--all-users requires running as root", case="P2")
    local_iface = iface_is_loopback(req.iface)
    local_targets = all(_is_loopback_net(t) for t in targets)
    if local_iface and local_targets:
        return Approved(req.iface, targets, False, None, req.all_users, build_bpf(targets, req.ports))
    if not req.allow_nonlocal:
        what = f"interface {req.iface!r}" if not local_iface else "non-loopback targets"
        raise SafetyRefusal(
            f"{what} need --allow-nonlocal and a scope file (--scope)",
            fix="only scan networks and hosts you own or have written permission to test",
            case="P1",
        )
    if not req.scope_path:
        raise SafetyRefusal("--allow-nonlocal requires --scope FILE", case="P2")
    scope = load_scope(req.scope_path, today=today)
    if req.iface not in scope.interfaces:
        raise SafetyRefusal(f"interface {req.iface!r} is not listed in the scope file", case="P2")
    for t in targets:
        if not _is_loopback_net(t) and not any(t.version == s.version and t.subnet_of(s) for s in scope.targets):
            raise SafetyRefusal(f"target {t} is not covered by the scope file", case="P2")
    approved = Approved(req.iface, targets, True, scope, req.all_users, build_bpf(targets, req.ports))
    _audit(approved)
    return approved
