"""Live loopback capture end to end (needs capture rights: setcap on tcpdump, or root)."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import threading
import time

import pytest

from sshleak.capture.sources import tcpdump_path
from sshleak.kex import build_kexinit_payload
from sshleak.lab.synth import frame_clear, kex_profile
from tests.conftest import run_cli


def _can_capture() -> bool:
    exe = tcpdump_path()
    if not exe:
        return False
    if os.geteuid() == 0:
        return True
    out = subprocess.run(["getcap", exe], capture_output=True, text=True).stdout
    return "cap_net_raw" in out


pytestmark = pytest.mark.skipif(not _can_capture(), reason="no capture rights (see sshleak doctor)")


def _fake_ssh_pair(port_box: list, stop: threading.Event):
    """A loopback client/server speaking a real SSH handshake, then 36-byte 'keystrokes'."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port_box.append(srv.getsockname()[1])

    def server():
        conn, _ = srv.accept()
        conn.sendall(b"SSH-2.0-OpenSSH_9.4\r\n" + frame_clear(build_kexinit_payload(kex_profile("server", strict=False))))
        conn.sendall(frame_clear(b"\x15"))
        conn.settimeout(0.2)
        while not stop.is_set():
            try:
                d = conn.recv(4096)
                if not d:
                    break
                time.sleep(0.0003)
                conn.sendall(b"\x00" * 36)
            except socket.timeout:
                pass
        conn.close()

    threading.Thread(target=server, daemon=True).start()
    time.sleep(1.0)  # let the scanner start first
    cli = socket.create_connection(("127.0.0.1", port_box[0]))
    cli.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    cli.sendall(b"SSH-2.0-OpenSSH_9.4\r\n" + frame_clear(build_kexinit_payload(kex_profile("client", strict=False))))
    cli.sendall(frame_clear(b"\x15"))
    import random

    rng = random.Random(1)
    time.sleep(0.6)
    for _ in range(120):
        time.sleep(min(0.6, max(0.05, rng.lognormvariate(-1.9, 0.4))))
        cli.sendall(b"\x00" * 36)
    stop.set()
    cli.close()


def test_live_loopback_scan_finds_unprotected_flow():
    port_box, stop = [], threading.Event()
    t = threading.Thread(target=_fake_ssh_pair, args=(port_box, stop), daemon=True)
    t.start()
    res = run_cli("scan", "--duration", "25", "--format", "json", "--fail-on", "none")
    t.join(5)
    data = json.loads(res.out)
    assert data["capture"]["mode"] == "live" and data["run"]["iface"] == "lo"
    # our own process owns both ends, so the flow is visible without --all-users
    flows = [f for f in data["flows"] if f["server"].endswith(f":{port_box[0]}")]
    assert flows and {c["id"]: c["status"] for c in flows[0]["checks"]}["L11"] == "fired"
