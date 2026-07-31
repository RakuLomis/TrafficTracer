"""Managed tshark packet capture with observable startup and cleanup errors."""

from __future__ import annotations

from dataclasses import dataclass
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import BinaryIO

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


@dataclass(frozen=True)
class PacketCaptureStopResult:
    exit_code: int
    killed: bool
    stderr: str


def start_packet_capture(
    interface: str,
    output_path: str | Path,
    capture_filter: str = "",
    *,
    startup_grace: float = 0.15,
) -> PacketCapture:
    if not interface.strip():
        raise PacketCaptureError(
            "CAPTURE_INTERFACE_INVALID", "capture interface must not be empty"
        )
    destination = Path(output_path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    command = ["tshark", "-i", interface, "-w", str(destination)]
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
    if startup_grace > 0:
        time.sleep(startup_grace)
    if process.poll() is not None:
        stderr = _read_stderr(stderr_file)
        stderr_file.close()
        raise _startup_error(interface, process.returncode, stderr)
    return PacketCapture(
        process=process,
        interface=interface,
        output_path=destination,
        command=tuple(command),
        stderr_file=stderr_file,
    )


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
                process.wait()
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
    return stream.read().decode("utf-8", errors="replace")
