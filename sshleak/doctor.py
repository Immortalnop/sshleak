"""`sshleak doctor`: capture rights, kernel, offload, clock, OpenSSH versions, tools."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass

from sshleak.capture.sources import setcap_fix, tcpdump_path
from sshleak.env import detect_virtualisation, offload_features

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"


@dataclass
class Check:
    name: str
    status: str
    detail: str
    fix: str | None = None


def _run(cmd: list[str], timeout: float = 5.0) -> tuple[int, str]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return res.returncode, (res.stdout + res.stderr)
    except (OSError, subprocess.SubprocessError) as e:
        return -1, str(e)


def _openssh_version(text: str) -> str | None:
    m = re.search(r"OpenSSH_[\w.]+", text)
    return m.group(0) if m else None


def run_checks() -> list[Check]:
    checks: list[Check] = []
    py = sys.version_info
    checks.append(Check("python", OK if py >= (3, 11) else FAIL, platform.python_version(),
                        None if py >= (3, 11) else "use Python 3.11+ (uv python install 3.12)"))
    try:
        from sshleak.thresholds import load

        th = load()
        checks.append(Check("thresholds", OK if th.calibrated else WARN,
                            f"{th.version} ({'calibrated' if th.calibrated else 'provisional, not yet accepted'})"))
    except Exception as e:  # report, never crash the doctor
        checks.append(Check("thresholds", FAIL, str(e)))

    virt = detect_virtualisation()
    checks.append(Check("kernel", WARN if virt.virtualised else OK,
                        f"{platform.system()} {platform.release()}" + (f" ({virt.kind})" if virt.kind else ""),
                        "timing on WSL2/VMs is reported as degraded (E2); use native Linux for numbers you publish"
                        if virt.virtualised else None))
    try:
        cs = open("/sys/devices/system/clocksource/clocksource0/current_clocksource").read().strip()
        checks.append(Check("clocksource", OK if cs in ("tsc", "arch_sys_counter") else WARN, cs))
    except OSError:
        checks.append(Check("clocksource", INFO, "unknown"))

    exe = tcpdump_path()
    if exe is None:
        checks.append(Check("tcpdump", FAIL if os.geteuid() == 0 else WARN, "not found",
                            "sudo apt install tcpdump (needed for live capture; --pcap works without it)"))
    else:
        _, out = _run([exe, "--version"])
        libpcap = re.search(r"libpcap version ([\w.]+)", out)
        checks.append(Check("tcpdump", OK, f"{exe} (libpcap {libpcap.group(1) if libpcap else '?'})"))
        if os.geteuid() == 0:
            checks.append(Check("capture rights", OK, "running as root"))
        else:
            getcap = shutil.which("getcap") or "/usr/sbin/getcap"
            _, caps = _run([getcap, exe])
            if "cap_net_raw" in caps:
                checks.append(Check("capture rights", OK, caps.strip()))
            else:
                checks.append(Check("capture rights", WARN, "tcpdump has no cap_net_raw; live scans will exit 3",
                                    setcap_fix(exe)))

    feats = offload_features("lo")
    if feats is None:
        checks.append(Check("offload (lo)", INFO, "ethtool not available"))
    else:
        on = ", ".join(k for k, v in sorted(feats.items()) if v) or "none"
        checks.append(Check("offload (lo)", OK, f"{on} on; loopback has no wire segmentation, so not a concern",
                            "on a real NIC, disable for accurate sizes: sudo ethtool -K <iface> gro off gso off tso off"))

    _, ssh_out = _run(["ssh", "-V"])
    v = _openssh_version(ssh_out)
    detail = v or "not found"
    status = INFO
    if v:
        m = re.match(r"OpenSSH_(\d+)\.(\d+)", v)
        if m and (int(m.group(1)), int(m.group(2))) < (9, 5):
            status, detail = WARN, f"{v}: predates ObscureKeystrokeTiming (L11 will fire on your own sessions)"
        else:
            status = OK
    checks.append(Check("ssh client", status, detail))
    sshd = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
    if sshd:
        _, out = _run([sshd, "-V"])
        checks.append(Check("sshd", OK, _openssh_version(out) or "present (version unknown)"))
    else:
        checks.append(Check("sshd", INFO, "not installed (only needed as a local live target)"))

    docker = shutil.which("docker")
    if docker:
        code, _ = _run([docker, "info", "--format", "{{.ServerVersion}}"])
        if code == 0:
            code2, img = _run([docker, "images", "-q", "sshleak-lab:1"])
            have = bool(img.strip()) and code2 == 0
            checks.append(Check("docker (lab)", OK if have else INFO,
                                "lab image built" if have else "available; lab image not built yet",
                                None if have else "sshleak lab build"))
        else:
            checks.append(Check("docker (lab)", INFO, "installed but daemon not reachable"))
    else:
        checks.append(Check("docker (lab)", INFO, "not installed (selftest then runs synthetic traffic only)"))

    try:
        from sshleak.discovery.sockets import snapshot

        snap = snapshot()
        checks.append(Check("socket discovery", OK,
                            f"{len(snap.listening)} listening, {len(snap.established)} established, "
                            f"{snap.unreadable_sockets} sockets of other users not attributable"))
    except Exception as e:
        checks.append(Check("socket discovery", WARN, str(e)))
    return checks
