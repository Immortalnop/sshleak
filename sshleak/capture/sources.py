"""Capture backends: saved pcap file, live tcpdump subprocess (decision G11).

A backend yields RawFrame objects, or None as an idle tick when live and quiet.
No backend writes packets anywhere: tcpdump writes to a pipe we read.
"""

from __future__ import annotations

import os
import queue
import re
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterator, Protocol

from sshleak.capture.pcapfile import CaptureFormatError, CaptureReader, RawFrame, ReaderStats
from sshleak.env import iface_exists, offload_warning
from sshleak.errors import EnvironmentProblem

SNAPLEN = 4096  # decision G1: enough for banner + KEXINIT; payload discarded at parse


@dataclass
class CaptureInfo:
    mode: str  # live | pcap | lab
    label: str
    ts_source: str
    ts_resolution_ns: int | None = None
    snaplen: int | None = None
    drops: int | None = None
    truncated: bool = False
    truncation_reason: str | None = None
    offload_warning: str | None = None
    interrupted: bool = False
    notes: list[str] = field(default_factory=list)


class CaptureSource(Protocol):
    def frames(self) -> Iterator[RawFrame | None]: ...

    def info(self) -> CaptureInfo: ...

    def stop(self) -> None: ...


class PcapSource:
    """Read a saved capture (offline, repeatable)."""

    def __init__(self, path: str | Path, *, redact: bool = True):
        self.path = Path(path)
        self._label = self.path.name if redact else str(self.path)
        self._reader: CaptureReader | None = None
        self._fh: BinaryIO | None = None

    def frames(self) -> Iterator[RawFrame | None]:
        try:
            self._fh = open(self.path, "rb")
        except FileNotFoundError:
            raise EnvironmentProblem(f"pcap file not found: {self._label}") from None
        except OSError as e:
            raise EnvironmentProblem(f"cannot read pcap {self._label}: {e.strerror}") from None
        self._reader = CaptureReader(self._fh)
        try:
            yield from self._reader
        except CaptureFormatError as e:
            raise EnvironmentProblem(f"{self._label}: {e}") from None
        finally:
            self._fh.close()

    def info(self) -> CaptureInfo:
        st = self._reader.stats if self._reader else ReaderStats()
        return CaptureInfo(
            mode="pcap",
            label=self._label,
            ts_source="file",
            ts_resolution_ns=st.ts_resolution_ns,
            snaplen=st.snaplen,
            drops=st.if_drops,
            truncated=st.truncated,
            truncation_reason=st.truncation_reason,
        )

    def stop(self) -> None:
        pass


_EOF = object()
_PERM_RX = re.compile(r"permission|not permitted|Operation not permitted", re.I)
_DROP_KERNEL = re.compile(r"(\d+) packets? dropped by kernel")
_DROP_IFACE = re.compile(r"(\d+) packets? dropped by interface")


def tcpdump_path() -> str | None:
    found = shutil.which("tcpdump")
    if found:
        return os.path.realpath(found)
    for cand in ("/usr/sbin/tcpdump", "/usr/bin/tcpdump"):
        if os.path.exists(cand):
            return cand
    return None


def setcap_fix(path: str | None) -> str:
    target = path or "$(command -v tcpdump)"
    return (
        f"grant capture rights to tcpdump only (not to Python):\n"
        f"  sudo setcap cap_net_raw,cap_net_admin=eip {target}\n"
        f"or run sshleak under sudo"
    )


class TcpdumpSource:
    """Live capture through a tcpdump subprocess writing pcap to a pipe."""

    def __init__(self, iface: str, bpf: str, *, duration: float | None, snaplen: int = SNAPLEN, idle_tick: float = 0.25):
        self.iface = iface
        self.bpf = bpf
        self.duration = duration
        self.snaplen = snaplen
        self.idle_tick = idle_tick
        self._proc: subprocess.Popen | None = None
        self._q: queue.Queue = queue.Queue(maxsize=65_536)
        self._stderr: list[str] = []
        self._reader: CaptureReader | None = None
        self._threads: list[threading.Thread] = []
        self._interrupted = False
        self._stopped = False
        self._tail: list[RawFrame] = []

    def _start(self) -> None:
        exe = tcpdump_path()
        if exe is None:
            raise EnvironmentProblem(
                "tcpdump not found (capture backend)",
                fix="install it: sudo apt install tcpdump",
                case="E4",
            )
        if not iface_exists(self.iface):
            raise EnvironmentProblem(f"interface {self.iface!r} does not exist", case="E3")
        cmd = [
            exe, "-i", self.iface, "-s", str(self.snaplen), "-U", "-w", "-", "-n",
            "--time-stamp-precision=nano", "--immediate-mode", "-B", "4096", self.bpf,
        ]
        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        err_t = threading.Thread(target=self._drain_stderr, daemon=True)
        err_t.start()
        self._threads.append(err_t)
        # tcpdump prints "listening on" once the handle is open, or exits with an error.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                err_t.join(1.0)
                text = "\n".join(self._stderr)
                if _PERM_RX.search(text):
                    raise EnvironmentProblem(
                        f"no permission to capture on {self.iface}", fix=setcap_fix(exe), case="E1"
                    )
                raise EnvironmentProblem(f"tcpdump failed: {text.strip() or 'exit ' + str(self._proc.returncode)}")
            if any("listening on" in line for line in self._stderr):
                break
            time.sleep(0.02)
        rd_t = threading.Thread(target=self._read_frames, daemon=True)
        rd_t.start()
        self._threads.append(rd_t)

    def _drain_stderr(self) -> None:
        assert self._proc and self._proc.stderr
        for raw in self._proc.stderr:
            self._stderr.append(raw.decode("utf-8", "replace").rstrip())

    def _read_frames(self) -> None:
        assert self._proc and self._proc.stdout
        self._reader = CaptureReader(self._proc.stdout)
        try:
            for frame in self._reader:
                self._q.put(frame)
        except CaptureFormatError:
            pass
        finally:
            self._q.put(_EOF)

    def frames(self) -> Iterator[RawFrame | None]:
        self._start()
        start = time.monotonic()
        try:
            while True:
                if self.duration is not None and time.monotonic() - start >= self.duration:
                    break
                try:
                    item = self._q.get(timeout=self.idle_tick)
                except queue.Empty:
                    yield None
                    continue
                if item is _EOF:
                    break
                yield item
        except KeyboardInterrupt:  # E5: stop cleanly, keep what was seen
            self._interrupted = True
        finally:
            self.stop()
            # Drain frames that arrived before tcpdump flushed.
            while True:
                try:
                    item = self._q.get_nowait()
                except queue.Empty:
                    break
                if item is _EOF:
                    break
                self._tail.append(item)
        yield from self._tail
        self._tail = []

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        proc = self._proc
        if proc is None:
            return
        if proc.poll() is None:
            try:
                proc.send_signal(signal.SIGINT)
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        for t in self._threads:
            t.join(timeout=3)

    def info(self) -> CaptureInfo:
        text = "\n".join(self._stderr)
        drops = None
        for rx in (_DROP_KERNEL, _DROP_IFACE):
            m = rx.search(text)
            if m:
                drops = (drops or 0) + int(m.group(1))
        st = self._reader.stats if self._reader else ReaderStats()
        return CaptureInfo(
            mode="live",
            label=self.iface,
            ts_source="kernel (tcpdump, nanosecond precision requested)",
            ts_resolution_ns=st.ts_resolution_ns,
            snaplen=self.snaplen,
            drops=drops,
            truncated=False,
            offload_warning=offload_warning(self.iface),
            interrupted=self._interrupted,
        )
