"""Synthetic, labelled SSH traffic (the lab generator backend).

Models the on-the-wire metadata of OpenSSH sessions: a real cleartext
handshake (banners, KEXINIT, NEWKEYS), then encrypted packets as random bytes
of the right sizes, with timing for human typing, ObscureKeystrokeTiming
(fixed and the 9.5-9.7 flaw), echo-off prompts, pastes, transfers, tunnels,
redraw noise and capture defects. Everything is seeded and deterministic.
Output is test traffic only: it never contains real session content.
"""

from __future__ import annotations

import math
import random
import socket
import struct
from dataclasses import dataclass, field
from typing import BinaryIO

from sshleak.capture.pcapfile import RawFrame
from sshleak.kex import KexInit, build_kexinit_payload

C2S, S2C = 0, 1
ETH_LINKTYPE = 1
SNAPLEN = 4096

# ---------------------------------------------------------------- KEX lists
_KEX = ("mlkem768x25519-sha256", "sntrup761x25519-sha512", "curve25519-sha256", "ecdh-sha2-nistp256",
        "diffie-hellman-group14-sha256")
_HOSTKEY = ("ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256")
_CIPHERS = ("chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
            "aes128-ctr", "aes192-ctr", "aes256-ctr")
_MACS = ("umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com",
         "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com", "umac-128@openssh.com",
         "hmac-sha2-256", "hmac-sha2-512")


def kex_profile(role: str, *, strict: bool = True, ciphers: tuple[str, ...] = _CIPHERS,
                macs: tuple[str, ...] = _MACS, compression: tuple[str, ...] = ("none", "zlib@openssh.com")) -> KexInit:
    marks = ("ext-info-c" if role == "client" else "ext-info-s",)
    if strict:
        marks += ("kex-strict-c-v00@openssh.com" if role == "client" else "kex-strict-s-v00@openssh.com",)
    return KexInit(_KEX + marks, _HOSTKEY, ciphers, ciphers, macs, macs, compression, compression)


def ssh_size(data_len: int, unit_overhead: int = 36) -> int:
    """Encrypted chacha20-poly1305 packet size for a CHANNEL_DATA of data_len bytes."""
    body = 1 + 4 + 4 + data_len  # msg, channel, length, data
    padded = math.ceil((1 + body + 4) / 8) * 8
    return 4 + padded + 16 + (unit_overhead - 36)


def frame_clear(payload: bytes) -> bytes:
    """Cleartext binary packet framing (before NEWKEYS)."""
    pad = 8 - ((5 + len(payload)) % 8)
    if pad < 4:
        pad += 8
    return struct.pack(">IB", 1 + len(payload) + pad, pad) + payload + b"\x00" * pad


# ---------------------------------------------------------------- actions
@dataclass
class Type:
    n_chars: int
    output_bytes: int = 400


@dataclass
class Password:
    n_chars: int


@dataclass
class Paste:
    n_bytes: int


@dataclass
class Idle:
    seconds: float
    keepalive_s: float | None = None


@dataclass
class Bulk:
    nbytes: int
    kind: str = "scp"  # scp | sftp
    upload: bool = False


@dataclass
class Redraw:
    seconds: float
    period_ms: tuple[float, float] = (50, 150)


@dataclass
class Forward:
    seconds: float


@dataclass
class Exec:
    output_bytes: int = 2000


def typing_script(n: int, seed: int, lo: int = 6, hi: int = 14) -> list:
    """n commands of lo..hi typed characters with 200-2500 bytes of output each."""
    rng = random.Random(seed)
    return [Type(rng.randint(lo, hi), rng.randint(200, 2500)) for _ in range(n)]


@dataclass
class Obfuscation:
    interval_ms: float = 20.0
    flawed: bool = False
    chaff_min_s: float = 1.024
    chaff_max_s: float = 3.072
    coalesce_p: float = 0.85


@dataclass
class SessionSpec:
    name: str
    client_sw: str = "OpenSSH_9.8"
    server_sw: str = "OpenSSH_9.8"
    client_kex: KexInit | None = None
    server_kex: KexInit | None = None
    client_ip: str = "127.0.0.1"
    server_ip: str = "127.0.0.1"
    client_port: int = 50022
    server_port: int = 22
    obfuscation: Obfuscation | None = None
    simulated_echo: bool = True  # OpenSSH server sends IGNORE when echo is off
    server_ping: bool = True
    script: list = field(default_factory=list)
    start_s: float = 0.0
    late_join: bool = False
    close: bool = True
    seed: int = 1
    unit_overhead: int = 36
    retransmit_p: float = 0.0
    reorder_p: float = 0.0
    non_ssh_banner: bytes | None = None  # F3: something else on the port


@dataclass
class Labels:
    name: str
    commands: list[int] = field(default_factory=list)  # typed length per command (no content)
    password_runs: int = 0
    obfuscation_ms: float | None = None
    flawed: bool = False


@dataclass
class Ev:
    t: float
    dir: int
    size: int
    payload: bytes | None = None  # cleartext bytes (handshake) only


# ---------------------------------------------------------------- session model
class _Session:
    def __init__(self, spec: SessionSpec):
        self.s = spec
        self.rng = random.Random(spec.seed)
        self.ev: list[Ev] = []
        self.labels = Labels(spec.name, obfuscation_ms=spec.obfuscation.interval_ms if spec.obfuscation else None,
                             flawed=bool(spec.obfuscation and spec.obfuscation.flawed))
        self.unit = ssh_size(1, spec.unit_overhead)
        self.t = spec.start_s
        self._chaff_until = -1.0
        self._next_tick = None

    def add(self, t: float, d: int, size: int, payload: bytes | None = None) -> None:
        self.ev.append(Ev(t, d, size, payload))

    # -- handshake & auth ------------------------------------------------
    def handshake(self) -> None:
        s, t = self.s, self.t
        if s.non_ssh_banner is not None:
            self.add(t + 0.0004, S2C, len(s.non_ssh_banner), s.non_ssh_banner)
            self.add(t + 0.0009, C2S, 18, b"GET / HTTP/1.0\r\n\r\n")
            self.add(t + 0.0020, S2C, 600)
            self.t = t + 0.003
            return
        cb = f"SSH-2.0-{s.client_sw}\r\n".encode()
        sb = f"SSH-2.0-{s.server_sw}\r\n".encode()
        ck = frame_clear(build_kexinit_payload(s.client_kex or kex_profile("client"), self.rng.randbytes(16)))
        sk = frame_clear(build_kexinit_payload(s.server_kex or kex_profile("server"), self.rng.randbytes(16)))
        self.add(t + 0.0003, C2S, len(cb), cb)
        self.add(t + 0.0005, S2C, len(sb), sb)
        self.add(t + 0.0010, C2S, len(ck), ck)
        self.add(t + 0.0012, S2C, len(sk), sk)
        ecdh = frame_clear(b"\x1e" + self.rng.randbytes(1220))  # mlkem768x25519 client share
        self.add(t + 0.0030, C2S, len(ecdh), ecdh)
        reply = frame_clear(b"\x1f" + self.rng.randbytes(1300)) + frame_clear(b"\x15")
        self.add(t + 0.0065, S2C, len(reply), reply)
        nk = frame_clear(b"\x15")
        self.add(t + 0.0070, C2S, len(nk), nk)
        self.t = t + 0.008

    def auth(self) -> None:
        t = self.t
        seq = [(C2S, 52), (S2C, 52), (S2C, 300), (C2S, 420), (S2C, 380), (C2S, 520), (S2C, 36),
               (C2S, 68), (S2C, 52), (C2S, 260), (C2S, 60), (C2S, 52), (S2C, 36), (S2C, 36), (S2C, 620)]
        for i, (d, size) in enumerate(seq):
            self.add(t + 0.0008 * (i + 1) + self.rng.uniform(0, 0.0002), d, size)
        self.t = t + 0.6 + self.rng.uniform(0, 0.4)

    # -- typing ------------------------------------------------------------
    def _gap(self) -> float:
        return min(0.8, max(0.05, self.rng.lognormvariate(math.log(0.15), 0.4)))

    def _echo_lat(self) -> float:
        return self.rng.lognormvariate(math.log(0.0004), 0.3)

    def _send_key(self, t_key: float, kind: str, output: int = 0) -> None:
        """Send one key (char|enter|pw|pw_enter) at t_key, with obfuscation if configured."""
        obf = self.s.obfuscation
        if obf is None:
            t_send = t_key + 0.00003
            self.add(t_send, C2S, self.unit)
            self._server_reply(t_send, kind, output, flawed=False)
            return
        T = obf.interval_ms / 1000.0
        if self._next_tick is None or t_key > self._chaff_until:
            self._flush_chaff(t_key)
            t_send = t_key + 0.00003
            self._next_tick = t_send + T
        else:
            self._flush_chaff(t_key)
            t_send = self._next_tick
            self._next_tick += T
        if obf.flawed:
            if self.rng.random() < obf.coalesce_p:
                self.add(t_send, C2S, 2 * self.unit)
            else:
                self.add(t_send, C2S, self.unit)
                self.add(t_send + 0.00002, C2S, self.unit)
        else:
            self.add(t_send, C2S, self.unit)
        self._server_reply(t_send, kind, output, flawed=obf.flawed)
        self._chaff_until = t_send + self.rng.uniform(obf.chaff_min_s, obf.chaff_max_s)

    def _flush_chaff(self, until: float) -> None:
        """Emit chaff ticks strictly before `until` while the chaff window is open."""
        if self._next_tick is None or not self.s.server_ping:
            return
        while self._next_tick < until and self._next_tick <= self._chaff_until:
            tk = self._next_tick
            self.add(tk, C2S, self.unit)
            self.add(tk + self.rng.lognormvariate(math.log(0.0001), 0.3), S2C, self.unit)  # PONG
            self._next_tick += self.s.obfuscation.interval_ms / 1000.0
        if self._next_tick is not None and self._next_tick > self._chaff_until and until > self._chaff_until:
            self._next_tick = None

    def _server_reply(self, t_send: float, kind: str, output: int, flawed: bool) -> None:
        if kind in ("char", "enter"):
            lat = self._echo_lat()
            if flawed:  # echo + pong for the chaff sent alongside
                self.add(t_send + lat, S2C, 2 * self.unit)
            else:
                self.add(t_send + lat, S2C, self.unit)
            if kind == "enter" and output > 0:
                tt = t_send + lat + self.rng.uniform(0.002, 0.02)
                left = output
                while left > 0:
                    chunk = min(left, 16384)
                    self.add(tt, S2C, ssh_size(chunk, self.s.unit_overhead))
                    left -= chunk
                    tt += 0.0003
        elif kind in ("pw", "pw_enter"):
            if self.s.simulated_echo:
                lat = self.rng.lognormvariate(math.log(0.00008), 0.3)
                self.add(t_send + lat, S2C, 2 * self.unit if flawed else self.unit)
            elif flawed:
                self.add(t_send + 0.0001, S2C, self.unit)  # pong only
            if kind == "pw_enter":
                self.add(t_send + 0.003, S2C, ssh_size(40, self.s.unit_overhead))

    def do_type(self, a: Type) -> None:
        t = self.t
        for _ in range(a.n_chars):
            t += self._gap()
            self._send_key(t, "char")
        t += self._gap()
        self._send_key(t, "enter", a.output_bytes)
        self.labels.commands.append(a.n_chars)
        self.t = t + self.rng.uniform(0.6, 2.5)

    def do_password(self, a: Password) -> None:
        # the command that triggers the prompt (e.g. "sudo -k true")
        self.do_type(Type(12, output_bytes=0))
        t = self.t - self.rng.uniform(0.3, 0.5)
        self.add(t, S2C, ssh_size(24, self.s.unit_overhead))  # "[sudo] password for ...:"
        t += 0.8
        for _ in range(a.n_chars):
            t += self._gap()
            self._send_key(t, "pw")
        t += self._gap()
        self._send_key(t, "pw_enter")
        self.labels.password_runs += 1
        self.t = t + self.rng.uniform(0.8, 2.0)

    def do_paste(self, a: Paste) -> None:
        t = self.t + 0.2
        size = ssh_size(a.n_bytes, self.s.unit_overhead)
        self.add(t, C2S, size)
        self.add(t + self._echo_lat() + 0.0005, S2C, size)
        self.t = t + 1.0

    def do_idle(self, a: Idle) -> None:
        if self.s.obfuscation:
            self._flush_chaff(self.t + a.seconds)
            self._next_tick = None
        if a.keepalive_s:
            k = self.t + a.keepalive_s
            while k < self.t + a.seconds:
                self.add(k, C2S, 52)
                self.add(k + 0.0003, S2C, 36)
                k += a.keepalive_s
        self.t += a.seconds

    def do_bulk(self, a: Bulk) -> None:
        t = self.t + 0.1
        data_dir, req_dir = (C2S, S2C) if a.upload else (S2C, C2S)
        pkt = ssh_size(32768, self.s.unit_overhead)
        n = max(1, a.nbytes // 32768)
        rate = 40e6  # bytes/s on loopback
        for i in range(n):
            if a.kind == "sftp":
                self.add(t, req_dir, 68)
                t += 0.00002
            self.add(t, data_dir, pkt)
            t += 32768 / rate
            if a.kind == "scp" and i % 30 == 29:
                self.add(t, req_dir, 36)  # window adjust
        self.t = t + 0.5

    def do_redraw(self, a: Redraw) -> None:
        end = self.t + a.seconds
        t = self.t
        while t < end:
            t += self.rng.uniform(*a.period_ms) / 1000.0
            self.add(t, S2C, ssh_size(self.rng.randint(80, 500), self.s.unit_overhead))

    def do_forward(self, a: Forward) -> None:
        end = self.t + a.seconds
        t = self.t
        while t < end:
            t += self.rng.uniform(0.01, 0.2)
            d = C2S if self.rng.random() < 0.5 else S2C
            self.add(t, d, ssh_size(self.rng.randint(200, 1400), self.s.unit_overhead))
        self.t = end

    def do_exec(self, a: Exec) -> None:
        t = self.t - 0.5  # no typing pause
        self.add(t + 0.001, S2C, ssh_size(a.output_bytes, self.s.unit_overhead))
        self.add(t + 0.002, S2C, 52)  # exit-status
        self.add(t + 0.0025, S2C, 36)  # eof/close
        self.add(t + 0.003, C2S, 36)
        self.t = t + 0.01

    def build(self) -> tuple[list[Ev], Labels]:
        s = self.s
        if not s.late_join:
            self.handshake()
            if s.non_ssh_banner is None:
                self.auth()
        else:
            self.t += 0.5
        if s.non_ssh_banner is None:
            for a in s.script:
                getattr(self, "do_" + type(a).__name__.lower())(a)
            if s.obfuscation:
                self._flush_chaff(self.t + 10)
        self.ev.sort(key=lambda e: e.t)
        return self.ev, self.labels


# ---------------------------------------------------------------- TCP / IP framing
def _ip_bytes(ip: str) -> tuple[int, bytes]:
    if ":" in ip:
        return 6, socket.inet_pton(socket.AF_INET6, ip)
    return 4, socket.inet_pton(socket.AF_INET, ip)


def _frame(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes,
           wire_len: int) -> tuple[bytes, int]:
    ver, s_ip = _ip_bytes(src)
    _, d_ip = _ip_bytes(dst)
    tcp = struct.pack(">HHIIHHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, (8 << 12) | flags, 65535, 0, 0)
    tcp += b"\x01\x01\x08\x0a" + struct.pack(">II", 1, 1)  # NOP NOP timestamps (32-byte header)
    if ver == 4:
        total = 20 + len(tcp) + wire_len
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 6, 0, s_ip, d_ip)
        eth = b"\x00" * 12 + b"\x08\x00"
    else:
        ip = struct.pack(">IHBB16s16s", 0x60000000, len(tcp) + wire_len, 6, 64, s_ip, d_ip)
        eth = b"\x00" * 12 + b"\x86\xdd"
    head = eth + ip + tcp
    return head + payload, len(head) + wire_len


@dataclass
class Frame:
    ts_ns: int
    data: bytes
    orig_len: int
    dir: int = -1
    plen: int = 0


def frames_for(spec: SessionSpec, *, marker: bytes | None = None, base_ns: int = 1_793_000_000_000_000_000) -> tuple[list[Frame], Labels]:
    """TCP frames (Ethernet) for one session. `marker` fills encrypted payload (tests)."""
    events, labels = _Session(spec).build()
    rng = random.Random(spec.seed ^ 0x5EED)
    c, sv = (spec.client_ip, spec.client_port), (spec.server_ip, spec.server_port)
    seq = {C2S: rng.randrange(2**32), S2C: rng.randrange(2**32)}
    out: list[Frame] = []

    def emit(t: float, d: int, flags: int, payload: bytes, wire_len: int, seqv: int | None = None) -> None:
        src, dst = (c, sv) if d == C2S else (sv, c)
        sq = seq[d] if seqv is None else seqv
        data, orig = _frame(src[0], dst[0], src[1], dst[1], sq, seq[1 - d], flags, payload, wire_len)
        out.append(Frame(base_ns + int(round(t * 1e9)), data[:SNAPLEN], orig, d, wire_len))

    t0 = events[0].t if events else spec.start_s
    if not spec.late_join:
        emit(t0 - 0.0003, C2S, 0x02, b"", 0)
        seq[C2S] += 1
        emit(t0 - 0.0002, S2C, 0x12, b"", 0)
        seq[S2C] += 1
        emit(t0 - 0.0001, C2S, 0x10, b"", 0)
    pending: list[tuple[float, int, int, bytes, int, int]] = []
    for e in events:
        if e.payload is not None:
            payload = e.payload
        elif marker:
            payload = (marker * (min(e.size, SNAPLEN) // len(marker) + 1))[: min(e.size, SNAPLEN)]
        else:
            payload = rng.randbytes(min(e.size, SNAPLEN))
        cur_seq = seq[e.dir]
        emit(e.t, e.dir, 0x18, payload, e.size)
        seq[e.dir] += e.size
        if spec.retransmit_p and rng.random() < spec.retransmit_p:
            pending.append((e.t + 0.2, e.dir, 0x18, payload, e.size, cur_seq))
        if rng.random() < 0.5:
            emit(e.t + 0.00004, 1 - e.dir, 0x10, b"", 0)
    for t, d, fl, pl, sz, sq in pending:
        emit(t, d, fl, pl, sz, sq)
    if spec.close and events:
        tend = events[-1].t + 0.01
        emit(tend, C2S, 0x11, b"", 0)
        emit(tend + 0.0001, S2C, 0x11, b"", 0)
    out.sort(key=lambda f: f.ts_ns)
    if spec.reorder_p:
        for i in range(len(out) - 1):
            a, b = out[i], out[i + 1]
            if a.dir == b.dir and a.plen and b.plen and rng.random() < spec.reorder_p * 10:
                out[i], out[i + 1] = Frame(a.ts_ns, b.data, b.orig_len, b.dir, b.plen), Frame(b.ts_ns, a.data, a.orig_len, a.dir, a.plen)
    return out, labels


def merge(*streams: list[Frame]) -> list[Frame]:
    allf = [f for s in streams for f in s]
    allf.sort(key=lambda f: f.ts_ns)
    return allf


def to_raw(frames: list[Frame]) -> list[RawFrame]:
    return [RawFrame(f.ts_ns, ETH_LINKTYPE, f.data, f.orig_len) for f in frames]


# ---------------------------------------------------------------- writers (synthetic traffic only)
def write_pcap(fh: BinaryIO, frames: list[Frame], *, snaplen: int = SNAPLEN) -> None:
    fh.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, snaplen, ETH_LINKTYPE))
    for f in frames:
        sec, ns = divmod(f.ts_ns, 1_000_000_000)
        fh.write(struct.pack("<IIII", sec, ns, len(f.data), f.orig_len))
        fh.write(f.data)


def write_pcapng(fh: BinaryIO, frames: list[Frame], *, if_drops: int | None = None, snaplen: int = SNAPLEN) -> None:
    def block(btype: int, body: bytes) -> bytes:
        body += b"\x00" * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack("<II", btype, ln) + body + struct.pack("<I", ln)

    fh.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
    opts = struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0)  # if_tsresol = 10^-9
    fh.write(block(1, struct.pack("<HHI", ETH_LINKTYPE, 0, snaplen) + opts))
    for f in frames:
        hi, lo = f.ts_ns >> 32, f.ts_ns & 0xFFFFFFFF
        fh.write(block(6, struct.pack("<IIIII", 0, hi, lo, len(f.data), f.orig_len) + f.data))
    if if_drops is not None:
        ts = frames[-1].ts_ns if frames else 0
        opts = struct.pack("<HHQ", 5, 8, if_drops) + struct.pack("<HH", 0, 0)
        fh.write(block(5, struct.pack("<III", 0, ts >> 32, ts & 0xFFFFFFFF) + opts))
