"""--config-check: ssh command-line parsing, ssh -G interpretation, V4 skips."""

from __future__ import annotations

import os
import shutil

import pytest

from sshleak.config.client import ConfigSkip, _parse_g, check_client, interpret, parse_ssh_cmdline
from sshleak.discovery.sockets import ProcInfo


def test_parse_cmdline():
    opts, dest = parse_ssh_cmdline(["ssh", "-p", "2222", "-o", "ObscureKeystrokeTiming=interval:80", "-CtA",
                                    "-i", "/k", "user@host", "ls", "-la"])
    assert dest == "user@host"
    assert opts == ["-p", "2222", "-o", "ObscureKeystrokeTiming=interval:80", "-C", "-A", "-i", "/k"]
    opts, dest = parse_ssh_cmdline(["ssh", "-oPort=22", "host"])
    assert opts == ["-o", "Port=22"] and dest == "host"
    opts, dest = parse_ssh_cmdline(["ssh", "-E", "/tmp/log", "-v", "host"])
    assert opts == [] and dest == "host"  # -E/-v are not passed to ssh -G


@pytest.mark.parametrize("raw,enabled,interval", [
    ("yes", True, 20.0), ("no", False, None), ("interval:80", True, 80.0), (None, None, None),
])
def test_interpret(raw, enabled, interval):
    opts = {} if raw is None else {"obscurekeystroketiming": raw}
    cfg = interpret(opts)
    assert cfg.enabled is enabled and cfg.interval_ms == interval


def test_parse_g_output():
    out = _parse_g("user amm\nobscurekeystroketiming interval:20\ncompression no\n")
    assert interpret(out).enabled and interpret(out).compression is False


def test_V4_other_users_process_skipped():
    with pytest.raises(ConfigSkip, match="another user"):
        check_client(ProcInfo(1, "ssh", os.geteuid() + 1, ("ssh", "host")))
    with pytest.raises(ConfigSkip, match="not ssh"):
        check_client(ProcInfo(1, "python3", os.geteuid(), ("python3",)))
    with pytest.raises(ConfigSkip, match="not readable"):
        check_client(ProcInfo(1, "ssh", os.geteuid(), ()))


@pytest.mark.skipif(shutil.which("ssh") is None, reason="no ssh client")
def test_real_ssh_G_runs_without_connecting():
    cfg = check_client(ProcInfo(1, "ssh", os.geteuid(), ("ssh", "-p", "2222", "example.invalid"), shutil.which("ssh")))
    assert cfg.source == "ssh -G"
    # OpenSSH < 9.5 has no obscurekeystroketiming line: enabled stays unknown, never guessed
    if cfg.obscure_raw is None:
        assert cfg.enabled is None
