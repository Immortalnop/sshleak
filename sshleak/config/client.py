"""Effective client configuration for a live flow (--config-check, Phase 7).

Maps the flow's client process to its command line, then asks the same ssh
binary for its effective configuration with ``ssh -G`` (prints config, never
connects). Only runs for processes owned by the current user (case V4): a
config of another user is never evaluated, because Match exec blocks would run
as us.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field

from sshleak.discovery.sockets import ProcInfo

# ssh(1) flags that take an argument (OpenSSH 8.x-10.x).
_ARG_FLAGS = set("BbcDEeFIiJLlmOoPpQRSWw")
_FLAG_FLAGS = set("46AaCfGgKkMNnqsTtVvXxYy")
# Options that must not be passed to `ssh -G` (they only matter when connecting).
_DROP = {"E", "y", "N", "f", "G", "V", "v", "q", "T", "t", "n", "s"}


@dataclass(frozen=True)
class ClientConfig:
    obscure_raw: str | None  # value of obscurekeystroketiming, None when the client lacks it
    enabled: bool | None
    interval_ms: float | None
    compression: bool | None
    proxyjump: str | None
    source: str
    options: dict[str, str] = field(default_factory=dict)


class ConfigSkip(Exception):
    """Config check could not run; the message is reported as the reason."""


def parse_ssh_cmdline(argv: list[str]) -> tuple[list[str], str | None]:
    """Split an ssh command line into (option args usable with -G, destination)."""
    opts: list[str] = []
    dest: str | None = None
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--":
            if i + 1 < len(argv):
                dest = argv[i + 1]
            break
        if a.startswith("-") and len(a) > 1:
            j = 1
            while j < len(a):
                ch = a[j]
                if ch in _ARG_FLAGS:
                    val = a[j + 1 :] if j + 1 < len(a) else (argv[i + 1] if i + 1 < len(argv) else "")
                    if j + 1 >= len(a):
                        i += 1
                    if ch not in _DROP:
                        opts += [f"-{ch}", val]
                    break
                if ch in _FLAG_FLAGS:
                    if ch not in _DROP:
                        opts.append(f"-{ch}")
                    j += 1
                    continue
                j += 1  # unknown flag letter: ignore
            i += 1
            continue
        dest = a
        break
    return opts, dest


def _parse_g(output: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in output.splitlines():
        key, _, val = line.strip().partition(" ")
        if key and key not in out:
            out[key.lower()] = val.strip()
    return out


def interpret(options: dict[str, str]) -> ClientConfig:
    raw = options.get("obscurekeystroketiming")
    enabled: bool | None
    interval: float | None = None
    if raw is None:
        enabled = None
    else:
        low = raw.lower()
        m = re.fullmatch(r"interval:(\d+)", low)
        if low in ("no", "false"):
            enabled = False
        elif m:
            enabled = True
            interval = float(m.group(1))
        elif low in ("yes", "true"):
            enabled = True
            interval = 20.0
        else:
            enabled = None
    comp = options.get("compression")
    return ClientConfig(
        obscure_raw=raw,
        enabled=enabled,
        interval_ms=interval,
        compression=None if comp is None else comp.lower() == "yes",
        proxyjump=options.get("proxyjump") if options.get("proxyjump", "none") != "none" else None,
        source="ssh -G",
        options={k: options[k] for k in ("obscurekeystroketiming", "compression", "ciphers", "macs", "proxyjump") if k in options},
    )


def check_client(proc: ProcInfo, *, timeout: float = 5.0) -> ClientConfig:
    if not proc.is_ssh_client:
        raise ConfigSkip(f"client process is {proc.name!r}, not ssh")
    if not proc.owned_by_me():
        raise ConfigSkip("client process belongs to another user (V4); its config is not read")
    if not proc.cmdline:
        raise ConfigSkip("client command line not readable (V4)")
    opts, dest = parse_ssh_cmdline(list(proc.cmdline))
    if not dest:
        raise ConfigSkip("no destination found in client command line")
    exe = proc.exe if proc.exe and os.access(proc.exe, os.X_OK) else "ssh"
    try:
        res = subprocess.run(
            [exe, "-G", *opts, dest],
            capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.path.expanduser("~")},
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise ConfigSkip(f"ssh -G failed: {e}") from None
    if res.returncode != 0:
        raise ConfigSkip(f"ssh -G exited {res.returncode}")
    return interpret(_parse_g(res.stdout))
