"""Chrome launch and job-scoped process ownership."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from typing import Callable, Iterable

from ..jobs.cancellation import CancellationToken
from ..process_env import external_process_env
from ..utils import logger


@dataclass(frozen=True)
class LinuxProcessIdentity:
    pid: int
    pgid: int
    start_token: str
    executable: str
    command: tuple[str, ...]


@dataclass(frozen=True)
class ChromeOwnership:
    pid: int
    pgid: int
    start_token: str
    executable: str
    profile: str


class BrowserProcessError(RuntimeError):
    """Chrome or its CDP transport disappeared during the capture window."""

    def __init__(self, code: str, message: str, *, exit_code: int | None = None) -> None:
        self.code = code
        self.message = message
        self.exit_code = exit_code
        super().__init__(f"{code}: {message}")

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"code": self.code, "message": self.message}
        if self.exit_code is not None:
            payload["exit_code"] = self.exit_code
            if self.exit_code < 0:
                payload["signal"] = -self.exit_code
        return payload


class BrowserHealthToken:
    """Cancellation-compatible token that also detects an unexpected Chrome exit."""

    def __init__(self, process, parent: CancellationToken) -> None:
        self.process = process
        self.parent = parent
        self._expected_reason = ""
        self._observed_exit: int | None = None

    def __getattr__(self, name):
        return getattr(self.parent, name)

    @property
    def expected_shutdown(self) -> bool:
        return bool(self._expected_reason)

    def expect_shutdown(self, reason: str = "requested") -> None:
        self._expected_reason = reason.strip() or "requested"

    def observe(self) -> int | None:
        code = self.process.poll()
        if code is not None:
            self._observed_exit = int(code)
        return code

    def checkpoint(self) -> None:
        self.parent.checkpoint()
        code = self.observe()
        if code is not None and not self._expected_reason:
            detail = (
                f"Chrome exited unexpectedly with signal {-code}"
                if code < 0
                else f"Chrome exited unexpectedly with code {code}"
            )
            raise BrowserProcessError(
                "BROWSER_PROCESS_EXITED",
                detail,
                exit_code=code,
            )

    def wait(self, timeout: float | None = None) -> bool:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            self.checkpoint()
            interval = 0.05
            if deadline is not None:
                interval = min(interval, max(0.0, deadline - time.monotonic()))
            if self.parent.wait(interval):
                self.parent.checkpoint()
            if deadline is not None and time.monotonic() >= deadline:
                self.checkpoint()
                return False

    def snapshot(self) -> dict[str, object]:
        code = self.observe()
        if code is None:
            status = "running"
        elif self._expected_reason:
            status = "expected_exit"
        else:
            status = "unexpected_exit"
        payload: dict[str, object] = {
            "schema_version": 1,
            "pid": getattr(self.process, "pid", None),
            "status": status,
            "expected_shutdown_reason": self._expected_reason or None,
            "exit_code": code,
        }
        if code is not None and code < 0:
            payload["signal"] = -code
        return payload


def linux_process_identity(pid: int) -> LinuxProcessIdentity | None:
    """Read a PID-reuse-safe Linux identity without relying on process names."""
    if pid <= 0 or not sys.platform.startswith("linux"):
        return None
    proc = Path("/proc") / str(pid)
    try:
        raw = (proc / "stat").read_text(encoding="utf-8")
        closing = raw.rfind(")")
        if closing < 0:
            return None
        fields = raw[closing + 2 :].split()
        command = tuple(
            item.decode("utf-8", errors="surrogateescape")
            for item in (proc / "cmdline").read_bytes().split(b"\0")
            if item
        )
        return LinuxProcessIdentity(
            pid=pid,
            pgid=int(fields[2]),
            start_token=fields[19],
            executable=os.readlink(proc / "exe"),
            command=command,
        )
    except (OSError, ValueError, IndexError):
        return None


def linux_processes() -> tuple[LinuxProcessIdentity, ...]:
    if not sys.platform.startswith("linux"):
        return ()
    identities = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            identity = linux_process_identity(int(entry.name))
            if identity is not None:
                identities.append(identity)
    return tuple(identities)


class OwnedChromeProcess:
    """Popen-compatible handle that owns one isolated Chrome process tree."""

    def __init__(
        self,
        process: subprocess.Popen,
        ownership: ChromeOwnership,
        *,
        inspect: Callable[[int], LinuxProcessIdentity | None] = linux_process_identity,
        processes: Callable[[], Iterable[LinuxProcessIdentity]] = linux_processes,
        signal_pid: Callable[[int, int], None] = os.kill,
        signal_group: Callable[[int, int], None] = os.killpg,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._process = process
        self.ownership = ownership
        self._inspect = inspect
        self._processes = processes
        self._signal_pid = signal_pid
        self._signal_group = signal_group
        self._monotonic = monotonic
        self._sleep = sleep

    @classmethod
    def create(cls, process: subprocess.Popen, profile: str) -> "OwnedChromeProcess":
        identity = linux_process_identity(process.pid)
        if identity is None or identity.pgid != process.pid:
            process.kill()
            process.wait()
            raise RuntimeError("Chrome did not enter its dedicated Linux process group")
        return cls(
            process,
            ChromeOwnership(
                pid=identity.pid,
                pgid=identity.pgid,
                start_token=identity.start_token,
                executable=identity.executable,
                profile=str(Path(profile).resolve()),
            ),
        )

    @property
    def pid(self) -> int:
        return self.ownership.pid

    @property
    def returncode(self) -> int | None:
        return self._process.returncode

    def poll(self) -> int | None:
        main_status = self._process.poll()
        return None if self.owned_pids() else main_status

    def owned_pids(self) -> tuple[int, ...]:
        """Return only identities proven by leader fingerprint or exact profile."""
        identities = tuple(self._processes())
        leader = self._inspect(self.ownership.pid)
        leader_matches = (
            leader is not None
            and leader.start_token == self.ownership.start_token
            and leader.executable == self.ownership.executable
            and leader.pgid == self.ownership.pgid
        )
        profile_arg = f"--user-data-dir={self.ownership.profile}"
        profile_pids = {
            item.pid for item in identities if profile_arg in item.command
        }
        if leader_matches:
            profile_pids.update(
                item.pid for item in identities
                if item.pgid == self.ownership.pgid
            )
        return tuple(sorted(profile_pids))

    def terminate(self) -> None:
        self._signal_owned(signal.SIGTERM)

    def kill(self) -> None:
        self._signal_owned(signal.SIGKILL)

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else self._monotonic() + timeout
        while self.owned_pids():
            if deadline is not None and self._monotonic() >= deadline:
                raise subprocess.TimeoutExpired(str(self.pid), timeout)
            self._sleep(0.02)
        remaining = None if deadline is None else max(0.0, deadline - self._monotonic())
        try:
            return self._process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise subprocess.TimeoutExpired(str(self.pid), timeout) from None

    def _signal_owned(self, sig: int) -> None:
        owned = set(self.owned_pids())
        if not owned:
            return
        group_members = {
            item.pid for item in self._processes()
            if item.pgid == self.ownership.pgid
        }
        if owned & group_members:
            try:
                self._signal_group(self.ownership.pgid, sig)
            except ProcessLookupError:
                pass
        for pid in sorted(owned - group_members):
            try:
                self._signal_pid(pid, sig)
            except ProcessLookupError:
                pass


def launch_chrome(
    binary: str,
    url: str,
    netlog_path: str,
    user_data_dir: str,
    headless: bool = False,
    proxy_server: str = "",
    remote_debugging_port: int | None = None,
    netlog_capture_mode: str = "Default",
    open_url: bool = True,
    extra_args: list[str] | None = None,
    disable_background_networking: bool = False,
    stderr_path: str | None = None,
) -> subprocess.Popen | OwnedChromeProcess:
    Path(netlog_path).parent.mkdir(parents=True, exist_ok=True)
    profile = str(Path(user_data_dir).resolve())
    cmd = [
        binary,
        f"--user-data-dir={profile}",
        f"--log-net-log={netlog_path}",
        f"--net-log-capture-mode={netlog_capture_mode}",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    if headless:
        cmd.extend([
            "--headless=new",
            "--autoplay-policy=no-user-gesture-required",
            "--disable-features=PreloadMediaEngagementData,MediaEngagementBypassAutoplayPolicies",
            "--disable-background-timer-throttling",
            "--mute-audio",
        ])
    if proxy_server:
        cmd.append(f"--proxy-server={proxy_server}")
    else:
        cmd.append("--no-proxy-server")
    if remote_debugging_port is not None:
        cmd.extend([
            f"--remote-debugging-port={remote_debugging_port}",
            "--remote-allow-origins=*",
        ])
    if extra_args:
        cmd.extend(extra_args)
    if disable_background_networking:
        cmd.extend([
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
        ])
    cmd.append(url if open_url else "about:blank")
    logger.info(
        "Launching Chrome: %s (CDP=%s) url=%s",
        binary,
        remote_debugging_port is not None,
        url if open_url else "about:blank",
    )
    isolated = sys.platform.startswith("linux")
    stderr_file = None
    try:
        stderr_target = subprocess.DEVNULL
        if stderr_path:
            destination = Path(stderr_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            stderr_file = destination.open("wb")
            stderr_target = stderr_file
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=stderr_target,
            start_new_session=isolated,
            env=external_process_env(),
        )
    finally:
        if stderr_file is not None:
            stderr_file.close()
    # Mock Popen objects in command-construction tests are intentionally not
    # treated as managed operating-system processes.
    if isolated and isinstance(process.pid, int):
        return OwnedChromeProcess.create(process, profile)
    return process


def compact_chrome_stderr(
    path: str | Path, limit: int = 64 * 1024,
) -> dict[str, object]:
    """Retain only a bounded diagnostic tail after the managed browser exits."""
    destination = Path(path)
    try:
        size = destination.stat().st_size
    except OSError:
        return {"path": str(destination), "bytes": 0, "truncated": False}
    truncated = size > limit
    if truncated:
        with destination.open("rb") as source:
            source.seek(-limit, 2)
            tail = source.read(limit)
        with destination.open("wb") as output:
            output.write(tail)
        size = len(tail)
    return {"path": str(destination), "bytes": size, "truncated": truncated}


def wait_chrome_exit(
    proc: subprocess.Popen | OwnedChromeProcess,
    timeout: float = 20,
    cancellation: CancellationToken | None = None,
) -> bool:
    if proc is None or proc.poll() is not None:
        return True
    logger.info("Waiting for Chrome (PID %d) to exit...", proc.pid)
    if cancellation is not None and cancellation.cancelled:
        timeout = min(timeout, 1.0)
    try:
        proc.wait(timeout=timeout)
        logger.info("Chrome exited cleanly")
        return True
    except subprocess.TimeoutExpired:
        logger.warning("Chrome did not exit within %ss", timeout)
        return False


def terminate_chrome(
    proc: subprocess.Popen | OwnedChromeProcess,
    timeout: float = 15,
    cancellation: CancellationToken | None = None,
) -> None:
    if proc is None or proc.poll() is not None:
        return
    logger.info("Terminating Chrome (PID %d)", proc.pid)
    if cancellation is not None and cancellation.cancelled:
        timeout = min(timeout, 1.0)
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning("Chrome did not respond to SIGTERM, sending SIGKILL")
        proc.kill()
        proc.wait(timeout=max(timeout, 1.0))


def kill_chrome(proc: subprocess.Popen | OwnedChromeProcess) -> None:
    terminate_chrome(proc)
