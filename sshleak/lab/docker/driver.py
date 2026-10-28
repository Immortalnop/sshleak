#!/usr/bin/env python3
"""sshleak lab driver: runs INSIDE the isolated lab container (stdlib only).

Starts a pinned sshd on the container's loopback, captures it with tcpdump
(snaplen 4096, the same as the scanner), drives a pinned ssh client through a
pty with human-like typing, and writes <name>.pcap and <name>.labels.json to
/out. Labels hold timing and typed lengths only, never typed content.
"""

import json
import os
import pty
import random
import select
import signal
import subprocess
import sys
import time

PORT = 2222
PROMPT = b"LAB$ "
KEY = "/lab/id_lab"
COMMANDS = [
    "ls -la /etc", "cat /etc/os-release", "uname -a", "echo hello world", "df -h", "ps aux | head -20",
    "date", "id", "pwd", "ls /usr/bin | wc -l", "ls -la /opt", "head -40 /etc/services", "whoami",
    "echo $HOME", "ls /var", "cat /etc/hostname", "env | sort | head -15", "ls -la /home/lab",
]


def sh(*cmd, **kw):
    return subprocess.run(list(cmd), check=True, **kw)


def setup(spec):
    sv = f"/opt/openssh-{spec['server']}"
    for f in (KEY, KEY + ".pub", "/lab/hostkey", "/lab/hostkey.pub"):
        if os.path.exists(f):
            os.remove(f)
    sh(f"{sv}/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "/lab/hostkey")
    sh(f"{sv}/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", KEY)
    os.makedirs("/lab/authorized_keys", exist_ok=True)
    with open(KEY + ".pub") as src, open("/lab/authorized_keys/lab", "w") as dst:
        dst.write(src.read())
    lines = [
        f"Port {PORT}", "ListenAddress 127.0.0.1", "HostKey /lab/hostkey", "PidFile /run/sshd-lab.pid",
        "PasswordAuthentication no", "KbdInteractiveAuthentication no", "PubkeyAuthentication yes",
        "AuthorizedKeysFile /lab/authorized_keys/%u", "StrictModes no", "PrintMotd no", "PrintLastLog no",
        "LogLevel ERROR", f"Subsystem sftp {sv}/libexec/sftp-server",
    ]
    for k, v in spec.get("server_config", {}).items():
        lines.append(f"{k} {v}")
    with open("/lab/sshd_config", "w") as fh:
        fh.write("\n".join(lines) + "\n")
    sshd = subprocess.Popen([f"{sv}/sbin/sshd", "-D", "-e", "-f", "/lab/sshd_config"],
                            stdout=subprocess.DEVNULL, stderr=open("/out/" + spec["name"] + ".sshd.log", "w"))
    for _ in range(100):
        r = subprocess.run(["sh", "-c", f"cat /proc/net/tcp | grep -qi ':{PORT:04X} 00000000:0000 0A'"])
        if r.returncode == 0:
            break
        time.sleep(0.05)
    return sshd


def start_capture(name):
    path = f"/out/{name}.pcap"
    td = subprocess.Popen(["tcpdump", "-i", "lo", "-s", "4096", "-U", "-n", "--time-stamp-precision=nano",
                           "-Z", "root", "-w", path, f"tcp port {PORT}"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    deadline = time.time() + 10
    buf = b""
    while time.time() < deadline:
        r, _, _ = select.select([td.stderr], [], [], 0.2)
        if r:
            buf += os.read(td.stderr.fileno(), 4096)
            if b"listening on" in buf:
                break
    time.sleep(0.3)
    return td, path


def client_argv(spec, extra=()):
    cl = f"/opt/openssh-{spec['client']}/bin/ssh"
    return [cl, "-p", str(PORT), "-i", KEY, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR", "-o", "BatchMode=yes", *spec.get("client_opts", []), *extra]


class Pty:
    def __init__(self, argv):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execv(argv[0], argv)
        self.buf = b""

    def read_until(self, token, timeout=20.0):
        end = time.time() + timeout
        while time.time() < end:
            if token in self.buf:
                idx = self.buf.index(token) + len(token)
                self.buf = self.buf[idx:]
                return True
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if r:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    return False
                if not data:
                    return False
                self.buf += data
        return False

    def drain(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    self.buf += os.read(self.fd, 65536)
                except OSError:
                    return
        self.buf = self.buf[-4096:]

    def write(self, data):
        os.write(self.fd, data)

    def wait(self, timeout=15.0):
        end = time.time() + timeout
        while time.time() < end:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                return status
            self.drain(0.1)
        os.kill(self.pid, signal.SIGKILL)
        return None


def gap(rng):
    return min(0.8, max(0.05, rng.lognormvariate(-1.897, 0.4)))  # median 150 ms


def type_line(p, text, rng, labels, kind="char"):
    for ch in text:
        time.sleep(gap(rng))
        labels["key_times_ns"].append(time.time_ns())
        p.write(ch.encode())
    time.sleep(gap(rng))
    labels["key_times_ns"].append(time.time_ns())
    p.write(b"\r")


def run_pty(spec, rng, labels):
    p = Pty(client_argv(spec, ["-tt", "lab@127.0.0.1"]))
    if not p.read_until(PROMPT, 30):
        raise SystemExit("no shell prompt from ssh session")
    time.sleep(0.8)
    for action in spec["script"]:
        op = action[0]
        if op == "cmds":
            for _ in range(action[1]):
                cmd = rng.choice(COMMANDS)
                type_line(p, cmd, rng, labels)
                labels["commands"].append(len(cmd))
                p.read_until(PROMPT, 20)
                time.sleep(rng.uniform(0.6, 2.5))
        elif op == "password":
            cmd = "read -rs -p 'pw: ' X; echo"
            type_line(p, cmd, rng, labels)
            labels["commands"].append(len(cmd))
            p.read_until(b"pw: ", 10)
            time.sleep(0.8)
            secret = "".join(rng.choice("abcdefghijkmnopqrstuvwxyz") for _ in range(action[1]))
            t0 = time.time_ns()
            type_line(p, secret, rng, labels)
            labels["password_windows_ns"].append([t0, time.time_ns()])
            p.read_until(PROMPT, 10)
            time.sleep(rng.uniform(0.8, 2.0))
        elif op == "paste":
            blob = "echo " + "".join(rng.choice("abcdefghij ") for _ in range(action[1]))
            time.sleep(0.3)
            p.write(blob.encode() + b"\r")
            p.read_until(PROMPT, 10)
            time.sleep(1.0)
        elif op == "idle":
            p.drain(action[1])
    type_line(p, "exit", rng, labels)
    p.wait(15)


def run_exec(spec, labels):
    subprocess.run(client_argv(spec, ["lab@127.0.0.1", "cat /etc/os-release; ls -la /usr/bin | head -200"]),
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=60)


def run_copy(spec, labels):
    cl = f"/opt/openssh-{spec['client']}/bin/scp"
    argv = [cl, *spec.get("copy_opts", []), "-P", str(PORT), "-i", KEY, "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "BatchMode=yes",
            "lab@127.0.0.1:/home/lab/blob", "/tmp/blob.copy"]
    subprocess.run(argv, stdin=subprocess.DEVNULL, timeout=120, check=True)


def main():
    spec = json.loads(sys.argv[1])
    rng = random.Random(spec.get("seed", 1))
    labels = {"scenario": spec["name"], "client": spec["client"], "server": spec["server"],
              "client_opts": spec.get("client_opts", []), "server_config": spec.get("server_config", {}),
              "mode": spec.get("mode", "pty"), "commands": [], "password_windows_ns": [], "key_times_ns": []}
    sshd = setup(spec)
    td, path = start_capture(spec["name"])
    labels["start_ns"] = time.time_ns()
    try:
        mode = spec.get("mode", "pty")
        if mode == "pty":
            run_pty(spec, rng, labels)
        elif mode == "exec":
            run_exec(spec, labels)
        elif mode == "copy":
            run_copy(spec, labels)
        time.sleep(0.5)
    finally:
        labels["end_ns"] = time.time_ns()
        td.send_signal(signal.SIGINT)
        td.wait(10)
        sshd.terminate()
        sshd.wait(5)
        labels["client_version"] = subprocess.run(
            [f"/opt/openssh-{spec['client']}/bin/ssh", "-V"], capture_output=True, text=True).stderr.strip()
        g = subprocess.run([f"/opt/openssh-{spec['client']}/bin/ssh", "-G", *spec.get("client_opts", []),
                            "-p", str(PORT), "lab@127.0.0.1"], capture_output=True, text=True)
        labels["effective_obscurekeystroketiming"] = next(
            (ln.split(" ", 1)[1] for ln in g.stdout.splitlines() if ln.startswith("obscurekeystroketiming ")), None)
        with open(f"/out/{spec['name']}.labels.json", "w") as fh:
            json.dump(labels, fh, indent=2, sort_keys=True)
        uid, gid = int(os.environ.get("HOST_UID", "0")), int(os.environ.get("HOST_GID", "0"))
        for f in os.listdir("/out"):
            if f.startswith(spec["name"] + "."):
                os.chown(os.path.join("/out", f), uid, gid)


if __name__ == "__main__":
    main()
