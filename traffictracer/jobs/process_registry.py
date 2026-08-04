"""Job-scoped child-process ownership and deterministic cleanup."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import subprocess
from threading import Lock
from typing import Protocol


class ManagedProcess(Protocol):
    pid: int

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...


@dataclass(frozen=True)
class ProcessRecord:
    process: ManagedProcess
    role: str
    pid: int
    started_at: datetime
    pgid: int | None = None
    start_token: str = ""
    executable: str = ""
    profile: str = ""


@dataclass(frozen=True)
class CleanupReport:
    terminated: tuple[str, ...] = ()
    killed: tuple[str, ...] = ()
    already_exited: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()


class ProcessRegistry:
    """Own child processes for one job and clean them up exactly once."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._records: list[ProcessRecord] = []
        self._cleanup_report: CleanupReport | None = None

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._cleanup_report is not None

    def register(self, process: ManagedProcess, role: str) -> ProcessRecord:
        normalized_role = role.strip()
        if not normalized_role:
            raise ValueError("process role must not be empty")
        pid = int(process.pid)
        if pid <= 0:
            raise ValueError("process PID must be positive")
        with self._lock:
            if self._cleanup_report is not None:
                raise RuntimeError("cannot register a process after cleanup")
            if any(record.process is process for record in self._records):
                raise ValueError(f"process {pid} is already registered")
            record = ProcessRecord(
                process=process,
                role=normalized_role,
                pid=pid,
                started_at=datetime.now(timezone.utc),
                pgid=getattr(getattr(process, "ownership", None), "pgid", None),
                start_token=getattr(
                    getattr(process, "ownership", None), "start_token", ""
                ),
                executable=getattr(
                    getattr(process, "ownership", None), "executable", ""
                ),
                profile=getattr(
                    getattr(process, "ownership", None), "profile", ""
                ),
            )
            self._records.append(record)
            return record

    def snapshot(self) -> tuple[ProcessRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def cleanup(self, grace_period: float = 2.0) -> CleanupReport:
        if grace_period < 0:
            raise ValueError("grace_period must be non-negative")
        with self._lock:
            if self._cleanup_report is not None:
                return self._cleanup_report

            terminated: list[str] = []
            killed: list[str] = []
            already_exited: list[str] = []
            errors: list[str] = []
            for record in reversed(self._records):
                process = record.process
                try:
                    if process.poll() is not None:
                        already_exited.append(record.role)
                        continue
                    process.terminate()
                    terminated.append(record.role)
                    try:
                        process.wait(timeout=grace_period)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        killed.append(record.role)
                        process.wait(timeout=grace_period)
                except (OSError, subprocess.SubprocessError) as exc:
                    errors.append(f"{record.role} (pid {record.pid}): {exc}")

            self._cleanup_report = CleanupReport(
                terminated=tuple(terminated),
                killed=tuple(killed),
                already_exited=tuple(already_exited),
                errors=tuple(errors),
            )
            return self._cleanup_report
