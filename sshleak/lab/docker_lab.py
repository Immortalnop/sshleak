"""Docker lab: real, pinned OpenSSH builds in an isolated container.

The container runs with --network none, a minimal capability set and resource
limits. sshd, the ssh client and tcpdump all run on the container's own
loopback, so no host capture rights are needed and no traffic leaves it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from importlib import resources
from pathlib import Path

from sshleak.errors import EnvironmentProblem

IMAGE = "sshleak-lab:1"
CAPS = ("CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID", "SYS_CHROOT", "KILL", "NET_RAW")
F, NF, SK, INS, OBSERVE = "fired", "not_fired", "skipped", "insufficient_evidence", "observe"


@dataclass
class DockerScenario:
    name: str
    cases: tuple[str, ...]
    description: str
    client: str
    server: str
    script: list = field(default_factory=lambda: [["cmds", 12]])
    client_opts: list[str] = field(default_factory=list)
    server_config: dict[str, str] = field(default_factory=dict)
    copy_opts: list[str] = field(default_factory=list)
    mode: str = "pty"  # pty | exec | copy
    expect: dict[str, str] = field(default_factory=dict)  # detector -> status, or "observe"

    def spec(self, seed: int) -> dict:
        d = asdict(self)
        d.pop("expect")
        d.pop("cases")
        d.pop("description")
        d["seed"] = seed
        return d


DOCKER_SCENARIOS: list[DockerScenario] = [
    DockerScenario("d_unprotected", ("V1", "L1", "L11"), "9.4p1 client -> 10.6p1 server (no obfuscation)",
                   "9.4p1", "10.6p1", expect={"L4": NF, "L1": F, "L2": SK, "L3": SK, "L5": F, "L11": F, "L12": F}),
    DockerScenario("d_flawed", ("V2", "L3"), "9.6p1 client -> 9.6p1 server (chaff flaw)",
                   "9.6p1", "9.6p1", expect={"L4": NF, "L1": NF, "L3": F, "L11": NF}),
    DockerScenario("d_fixed_98", ("V2", "L3"), "9.8p1 (first fixed release) both sides",
                   "9.8p1", "9.8p1", expect={"L4": NF, "L1": NF, "L2": NF, "L3": NF, "L11": NF}),
    DockerScenario("d_fixed_106", ("L1", "L3"), "10.6p1 both sides",
                   "10.6p1", "10.6p1", expect={"L4": NF, "L1": NF, "L2": NF, "L3": NF, "L5": NF, "L11": NF}),
    DockerScenario("d_off_106", ("L2",), "10.6p1 with ObscureKeystrokeTiming=no",
                   "10.6p1", "10.6p1", client_opts=["-o", "ObscureKeystrokeTiming=no"],
                   expect={"L4": NF, "L1": F, "L2": F, "L3": SK}),
    DockerScenario("d_old_server", ("L2",), "10.6p1 client -> 9.4p1 server (no ping@openssh.com)",
                   "10.6p1", "9.4p1", expect={"L4": NF, "L1": OBSERVE, "L2": OBSERVE}),
    DockerScenario("d_interval80", ("V3", "L8"), "10.6p1 with interval:80",
                   "10.6p1", "10.6p1", client_opts=["-o", "ObscureKeystrokeTiming=interval:80"],
                   expect={"L4": NF, "L1": NF, "L3": NF, "L8": F}),
    DockerScenario("d_password_106", ("L4",), "echo-off prompts, 10.6p1 both sides",
                   "10.6p1", "10.6p1", script=[["cmds", 6], ["password", 10], ["cmds", 6], ["password", 12]],
                   expect={"L4": OBSERVE, "L1": NF}),
    DockerScenario("d_password_94", ("L4",), "echo-off prompts, 9.4p1 both sides",
                   "9.4p1", "9.4p1", script=[["cmds", 6], ["password", 10], ["cmds", 6], ["password", 12]],
                   expect={"L4": OBSERVE, "L1": F}),
    DockerScenario("d_password_96", ("L4", "V2"), "echo-off prompts, 9.6p1 flawed client",
                   "9.6p1", "9.6p1", script=[["cmds", 6], ["password", 10], ["cmds", 6], ["password", 12]],
                   expect={"L4": OBSERVE, "L3": F}),
    DockerScenario("d_compression", ("V6", "L9"), "10.6p1 with -C",
                   "10.6p1", "10.6p1", client_opts=["-C"], server_config={"Compression": "yes"},
                   expect={"L4": NF, "L9": F, "L10": NF}),
    DockerScenario("d_weak_cipher", ("V6", "L10"), "aes128-cbc negotiated",
                   "10.6p1", "10.6p1", client_opts=["-c", "aes128-cbc"], server_config={"Ciphers": "+aes128-cbc"},
                   expect={"L4": NF, "L10": F, "L9": NF}),
    DockerScenario("d_exec", ("S8",), "remote command without a pty",
                   "10.6p1", "10.6p1", mode="exec", expect={"L1": SK, "L5": SK}),
    DockerScenario("d_sftp", ("S3", "L12"), "8 MB copy with scp (SFTP protocol)",
                   "10.6p1", "10.6p1", mode="copy", expect={"L1": SK, "L12": F}),
    DockerScenario("d_scp_legacy", ("S3", "L12"), "8 MB copy with scp -O (legacy protocol)",
                   "10.6p1", "10.6p1", mode="copy", copy_opts=["-O"], expect={"L1": SK, "L12": F}),
]


def lab_dir() -> Path:
    return Path(str(resources.files("sshleak.lab") / "docker"))


def docker_bin() -> str | None:
    return shutil.which("docker")


def docker_available() -> bool:
    exe = docker_bin()
    if not exe:
        return False
    try:
        return subprocess.run([exe, "info"], capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def image_present() -> bool:
    exe = docker_bin()
    if not exe:
        return False
    res = subprocess.run([exe, "images", "-q", IMAGE], capture_output=True, text=True)
    return bool(res.stdout.strip())


def build_image(no_cache: bool = False) -> None:
    exe = docker_bin()
    if not exe or not docker_available():
        raise EnvironmentProblem("docker is not available (install Docker Engine and start the daemon)")
    cmd = [exe, "build", "-t", IMAGE, *(["--no-cache"] if no_cache else []), str(lab_dir())]
    if subprocess.run(cmd).returncode != 0:
        raise EnvironmentProblem("lab image build failed (see docker output above)")


def run_scenario(sc: DockerScenario, out: Path, *, seed: int = 1, timeout: float = 600) -> Path:
    exe = docker_bin()
    if not exe:
        raise EnvironmentProblem("docker is not available")
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    cmd = [exe, "run", "--rm", "--network", "none", "--cap-drop", "ALL",
           *[a for c in CAPS for a in ("--cap-add", c)],
           "--pids-limit", "256", "--memory", "768m", "-e", f"HOST_UID={os.getuid()}", "-e", f"HOST_GID={os.getgid()}",
           "-v", f"{out}:/out", IMAGE, "python3", "/lab/driver.py", json.dumps(sc.spec(seed))]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    pcap = out / f"{sc.name}.pcap"
    if res.returncode != 0 or not pcap.exists():
        raise EnvironmentProblem(f"lab scenario {sc.name} failed: {res.stderr.strip()[-500:]}")
    labels = json.loads((out / f"{sc.name}.labels.json").read_text())
    labels["expect"] = sc.expect
    labels["cases"] = list(sc.cases)
    (out / f"{sc.name}.labels.json").write_text(json.dumps(labels, indent=2, sort_keys=True) + "\n")
    return pcap


def run_many(scs: list[DockerScenario], out: Path, *, seed: int = 1, jobs: int = 3) -> list[Path]:
    if not image_present():
        raise EnvironmentProblem(f"lab image {IMAGE} not built", fix="sshleak lab build")
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        return list(ex.map(lambda s: run_scenario(s, out, seed=seed), scs))
