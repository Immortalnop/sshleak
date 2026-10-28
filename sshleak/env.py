"""Host environment facts: virtualisation (E2), interface flags/MTU, offload (C2)."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

IFF_LOOPBACK = 0x8
SYS_NET = Path("/sys/class/net")


@dataclass(frozen=True)
class Virtualisation:
    kind: str | None  # "wsl2", "vm", None for bare metal / unknown

    @property
    def virtualised(self) -> bool:
        return self.kind is not None


def detect_virtualisation() -> Virtualisation:
    release = platform.release().lower()
    if "microsoft" in release or "wsl" in release:
        return Virtualisation("wsl2")
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text(errors="replace")
        if " hypervisor" in cpuinfo:
            return Virtualisation("vm")
    except OSError:
        pass
    return Virtualisation(None)


def iface_exists(name: str) -> bool:
    return (SYS_NET / name).is_dir()


def iface_is_loopback(name: str) -> bool:
    try:
        flags = int((SYS_NET / name / "flags").read_text().strip(), 16)
    except (OSError, ValueError):
        return False
    return bool(flags & IFF_LOOPBACK)


def iface_mtu(name: str) -> int | None:
    try:
        return int((SYS_NET / name / "mtu").read_text().strip())
    except (OSError, ValueError):
        return None


def offload_features(name: str) -> dict[str, bool] | None:
    """GRO/GSO/TSO state from ethtool, or None if ethtool is unavailable."""
    ethtool = shutil.which("ethtool") or ("/usr/sbin/ethtool" if os.path.exists("/usr/sbin/ethtool") else None)
    if not ethtool:
        return None
    try:
        out = subprocess.run([ethtool, "-k", name], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    wanted = {
        "generic-receive-offload": "gro",
        "generic-segmentation-offload": "gso",
        "tcp-segmentation-offload": "tso",
    }
    feats: dict[str, bool] = {}
    for line in out.splitlines():
        key, _, val = line.strip().partition(":")
        if key in wanted:
            feats[wanted[key]] = val.strip().startswith("on")
    return feats


def offload_warning(name: str) -> str | None:
    """Offload only merges packets on real NICs; loopback has no wire to segment for."""
    if iface_is_loopback(name):
        return None
    feats = offload_features(name)
    if not feats:
        return None
    on = sorted(k for k, v in feats.items() if v)
    if not on:
        return None
    return (
        f"offload enabled on {name} ({', '.join(on)}): captured segments may be merged; "
        f"run 'sshleak doctor' for how to disable"
    )
