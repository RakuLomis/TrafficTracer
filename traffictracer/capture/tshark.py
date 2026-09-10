"""Managed tshark packet capture with observable startup and cleanup errors."""

from __future__ import annotations

from dataclasses import dataclass
import signal
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from typing import BinaryIO, Callable
from threading import Event, Thread

from ..utils import logger


class PacketCaptureError(RuntimeError):
    def __init__(self, code: str, message: str, *, interface: str = "") -> None:
        self.code = code
        self.message = message
        self.interface = interface
        super().__init__(f"{code}: {message}")

    def as_dict(self) -> dict[str, str]:
        payload = {"code": self.code, "message": self.message}
        if self.interface:
            payload["interface"] = self.interface
        return payload


@dataclass
class PacketCapture:
    process: subprocess.Popen
    interface: str
    output_path: Path
    command: tuple[str, ...]
    stderr_file: BinaryIO
    ready_monotonic: float = 0.0


def capture_header_ready(path: Path) -> bool:
    """Accept a complete PCAP header or PCAPNG section plus interface block.

    No packet is required. Reads are bounded even for corrupt block lengths.
    The managed launcher selects PCAPNG explicitly and captures one interface.
    """
    try:
        with path.open("rb") as stream:
            data = stream.read(65536)
    except FileNotFoundError:
        return False
    if len(data) < 24:
        return False
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = "<" if magic[0] in (0xd4, 0x4d) else ">"
        major, minor, _, _, snaplen, _ = struct.unpack(endian + "HHiIII", data[4:24])
        return (major, minor) == (2, 4) and snaplen > 0
    if magic != b"\x0a\x0d\x0d\x0a" or data[8:12] not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
        return False
    endian = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    offset = 0
    while offset + 12 <= len(data):
        kind, size = struct.unpack_from(endian + "II", data, offset)
        if size < 12 or size % 4 or offset + size > len(data):
            return False
        if struct.unpack_from(endian + "I", data, offset + size - 4)[0] != size:
            return False
        if offset == 0 and (size < 28 or struct.unpack_from(endian + "H", data, 12)[0] != 1):
            return False
        if kind == 1:
            return size >= 20
        offset += size
    return False


def capture_output_complete(path: Path) -> bool:
    """Bounded PCAPNG end-block check after the writer has exited."""
    if not capture_header_ready(path):
        return False
    with path.open("rb") as stream:
        prefix = stream.read(12)
        if prefix[:4] != b"\x0a\x0d\x0d\x0a":
            return False  # Managed captures always request PCAPNG.
        endian = "<" if prefix[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
        size = stream.seek(0, 2)
        stream.seek(-4, 2)
        length = struct.unpack(endian + "I", stream.read(4))[0]
        if length < 12 or length % 4 or length > size:
            return False
        stream.seek(size - length + 4)
        return struct.unpack(endian + "I", stream.read(4))[0] == length


@dataclass(frozen=True)
class PacketCaptureStopResult:
    exit_code: int
    killed: bool
    stderr: str


class CaptureMonitor:
    """Job-local health token: never cancels a parent batch on sensor failure."""

    def __init__(self, captures, parent):
        self.captures = tuple(c for c in captures if c is not None)
        self.parent = parent
        self.error = None
        self._stop = Event()
        self._thread = Thread(target=self._watch, name="capture-health", daemon=True)

    def __getattr__(self, name):
        return getattr(self.parent, name)

    def check_health(self):
        if self.error is not None:
            raise self.error
        for capture in self.captures:
            code = capture.process.poll()
            if code is not None:
                self.error = PacketCaptureError("CAPTURE_PROCESS_EXITED", f"packet capture exited during browser lifetime (code {code})", interface=getattr(capture, "interface", ""))
                raise self.error

    def start(self):
        self.check_health()
        self._thread.start()

    def _watch(self):
        while not self._stop.wait(0.1):
            try:
                self.check_health()
            except PacketCaptureError:
                return

    def checkpoint(self):
        self.check_health()
        self.parent.checkpoint()

    def wait(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            self.checkpoint()
            remaining = 0.1 if deadline is None else min(0.1, max(0, deadline - time.monotonic()))
            if self.parent.wait(remaining):
                return True
            if deadline is not None and time.monotonic() >= deadline:
                self.checkpoint()
                return False

    def stop(self):
        self._stop.set()
        if self._thread.ident is not None:
            self._thread.join(timeout=1)


def start_packet_capture(
    interface: str,
    output_path: str | Path,
    capture_filter: str = "",
    *,
    startup_grace: float = 0.15,
    startup_timeout: float = 10.0,
    checkpoint: Callable[[], None] = lambda: None,
) -> PacketCapture:
    if not interface.strip():
        raise PacketCaptureError(
            "CAPTURE_INTERFACE_INVALID", "capture interface must not be empty"
        )
    destination = Path(output_path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if startup_timeout <= 0:
        raise ValueError("capture startup timeout must be positive")
    if destination.exists():
        raise PacketCaptureError("CAPTURE_OUTPUT_EXISTS", "refusing to overwrite an existing capture", interface=interface)
    command = ["tshark", "-i", interface, "-F", "pcapng", "-w", str(destination)]
    if capture_filter:
        command.extend(["-f", capture_filter])
    stderr_file = tempfile.TemporaryFile(mode="w+b")
    logger.info("Starting tshark on %s -> %s", interface, destination)
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=stderr_file,
        )
    except FileNotFoundError as exc:
        stderr_file.close()
        raise PacketCaptureError(
            "CAPTURE_TOOL_NOT_FOUND", "tshark is not installed", interface=interface
        ) from exc
    except PermissionError as exc:
        stderr_file.close()
        raise PacketCaptureError(
            "CAPTURE_PERMISSION_DENIED",
            "permission denied while starting tshark",
            interface=interface,
        ) from exc
    except OSError as exc:
        stderr_file.close()
        raise PacketCaptureError(
            "CAPTURE_START_FAILED", str(exc), interface=interface
        ) from exc
    capture = PacketCapture(
        process=process,
        interface=interface,
        output_path=destination,
        command=tuple(command),
        stderr_file=stderr_file,
    )
    # startup_grace remains accepted for old callers, but is no longer proof
    # of readiness. All waits are cancellable and bounded by a deadline.
    deadline = time.monotonic() + startup_timeout
    try:
        while True:
            checkpoint()
            if process.poll() is not None:
                raise _startup_error(interface, process.returncode, _read_stderr(stderr_file))
            if capture_header_ready(destination) and process.poll() is None:
                capture.ready_monotonic = time.monotonic()
                return capture
            if time.monotonic() >= deadline:
                raise PacketCaptureError("CAPTURE_READY_TIMEOUT", "capture interface did not publish a complete header before deadline", interface=interface)
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    except BaseException:
        # This process has not yet been registered by the caller.
        try:
            stop_packet_capture(capture)
        except Exception:
            logger.exception("Failed to clean up unready packet capture")
        raise


def stop_packet_capture(
    capture: PacketCapture,
    *,
    timeout: float = 5.0,
) -> PacketCaptureStopResult:
    process = capture.process
    killed = False
    try:
        if process.poll() is None:
            logger.info("Stopping tshark (PID %d) gracefully...", process.pid)
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                logger.warning("tshark did not exit, sending SIGKILL")
                process.kill()
                killed = True
                process.wait(timeout=timeout)
        stderr = _read_stderr(capture.stderr_file)
        exit_code = process.returncode if process.returncode is not None else 0
        if exit_code != 0 and _is_permission_error(stderr):
            raise PacketCaptureError(
                "CAPTURE_PERMISSION_DENIED",
                stderr.strip() or "dumpcap capture permission denied",
                interface=capture.interface,
            )
        return PacketCaptureStopResult(exit_code, killed, stderr)
    finally:
        capture.stderr_file.close()


def start_tshark(
    interface: str,
    output_path: str,
    capture_filter: str = "",
) -> subprocess.Popen:
    """Backward-compatible unmanaged tshark launcher."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    command = ["tshark", "-i", interface, "-w", output_path]
    if capture_filter:
        command.extend(["-f", capture_filter])
    return subprocess.Popen(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


def stop_tshark(proc: subprocess.Popen, timeout: int = 5) -> None:
    """Backward-compatible unmanaged tshark stopper."""
    if proc is None or proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _startup_error(interface: str, returncode: int, stderr: str) -> PacketCaptureError:
    message = stderr.strip() or f"tshark exited during startup with code {returncode}"
    code = "CAPTURE_PERMISSION_DENIED" if _is_permission_error(stderr) else "CAPTURE_START_FAILED"
    return PacketCaptureError(code, message, interface=interface)


def _is_permission_error(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(
        marker in lowered
        for marker in (
            "permission denied",
            "operation not permitted",
            "you don't have permission",
            "dumpcap requires",
            "cap_net_raw",
        )
    )


def _read_stderr(stream: BinaryIO) -> str:
    stream.flush()
    stream.seek(0)
    return stream.read(65536).decode("utf-8", errors="replace")
