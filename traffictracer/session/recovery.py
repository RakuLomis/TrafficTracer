"""Crash recovery journal for interrupted Complete capture Sessions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
from typing import Callable, Iterable, Mapping

from traffictracer.jobs.models import JobState
from traffictracer.jobs.process_registry import ProcessRecord

from .atomic import write_json_atomic
from .store import SessionStore


RECOVERY_JOURNAL_NAME = "recovery.json"
RECOVERY_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class TracingSnapshot:
    enabled: bool
    output: str
    session_id: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "output": self.output,
            "session_id": self.session_id,
        }


@dataclass(frozen=True)
class ProcessFingerprint:
    pid: int
    start_token: str
    executable: str


@dataclass(frozen=True)
class JournalProcess:
    role: str
    pid: int
    start_token: str
    executable: str

    def to_dict(self) -> dict[str, object]:
        return {
            "role": self.role,
            "pid": self.pid,
            "start_token": self.start_token,
            "executable": self.executable,
        }


@dataclass(frozen=True)
class RecoveryJournal:
    session_id: str
    tracing: TracingSnapshot
    processes: tuple[JournalProcess, ...]
    created_at: datetime
    schema_version: int = RECOVERY_SCHEMA_VERSION

    @classmethod
    def capture(
        cls,
        *,
        session_id: str,
        tracing: TracingSnapshot,
        processes: Iterable[ProcessRecord],
        fingerprint: Callable[[int], ProcessFingerprint | None] | None = None,
        now: datetime | None = None,
    ) -> RecoveryJournal:
        identify = fingerprint or linux_process_fingerprint
        identities: list[JournalProcess] = []
        for record in processes:
            current = identify(record.pid)
            if current is None:
                continue
            identities.append(
                JournalProcess(
                    role=record.role,
                    pid=record.pid,
                    start_token=current.start_token,
                    executable=current.executable,
                )
            )
        return cls(
            session_id=session_id,
            tracing=tracing,
            processes=tuple(identities),
            created_at=_utc(now),
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> RecoveryJournal:
        expected = {"schema_version", "session_id", "tracing", "processes", "created_at"}
        if set(payload) != expected:
            raise ValueError("recovery journal has unknown or missing fields")
        if payload["schema_version"] != RECOVERY_SCHEMA_VERSION:
            raise ValueError("unsupported recovery journal schema_version")
        tracing = payload["tracing"]
        processes = payload["processes"]
        if not isinstance(tracing, dict) or set(tracing) != {"enabled", "output", "session_id"}:
            raise ValueError("invalid recovery tracing snapshot")
        if not isinstance(processes, list):
            raise ValueError("invalid recovery process list")
        parsed_processes: list[JournalProcess] = []
        for item in processes:
            if not isinstance(item, dict) or set(item) != {
                "role",
                "pid",
                "start_token",
                "executable",
            }:
                raise ValueError("invalid recovery process identity")
            parsed_processes.append(
                JournalProcess(
                    role=_required_string(item["role"], "process role"),
                    pid=_positive_int(item["pid"], "process pid"),
                    start_token=_required_string(item["start_token"], "process start_token"),
                    executable=_string(item["executable"], "process executable"),
                )
            )
        return cls(
            session_id=_required_string(payload["session_id"], "session_id"),
            tracing=TracingSnapshot(
                enabled=_required_bool(tracing["enabled"], "tracing enabled"),
                output=_string(tracing["output"], "tracing output"),
                session_id=_string(tracing["session_id"], "tracing session_id"),
            ),
            processes=tuple(parsed_processes),
            created_at=_parse_time(_required_string(payload["created_at"], "created_at")),
        )

    @classmethod
    def load(cls, path: str | Path) -> RecoveryJournal:
        with Path(path).open(encoding="utf-8") as stream:
            payload = json.load(stream)
        if not isinstance(payload, dict):
            raise ValueError("recovery journal must contain a JSON object")
        return cls.from_dict(payload)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "tracing": self.tracing.to_dict(),
            "processes": [process.to_dict() for process in self.processes],
            "created_at": _format_time(self.created_at),
        }

    def persist(self, store: SessionStore) -> Path:
        path = store.artifact_path(self.session_id, RECOVERY_JOURNAL_NAME)
        write_json_atomic(path, self.to_dict())
        return path


@dataclass(frozen=True)
class RecoveryReport:
    recovered_sessions: tuple[str, ...]
    terminated_pids: tuple[int, ...]
    skipped_pids: tuple[int, ...]
    errors: tuple[str, ...]


class RecoveryManager:
    def __init__(
        self,
        store: SessionStore,
        *,
        restore_tracing: Callable[[TracingSnapshot], None],
        fingerprint: Callable[[int], ProcessFingerprint | None] | None = None,
        terminate: Callable[[int], None] | None = None,
    ) -> None:
        self._store = store
        self._restore_tracing = restore_tracing
        self._fingerprint = fingerprint or linux_process_fingerprint
        self._terminate = terminate or _terminate_process

    def recover(self) -> RecoveryReport:
        recovered: list[str] = []
        terminated: list[int] = []
        skipped: list[int] = []
        errors: list[str] = []

        scan = self._store.scan()
        errors.extend(f"{item.session_dir}: {item.message}" for item in scan.corrupt)
        for manifest in scan.sessions:
            if manifest.state.terminal:
                continue
            journal_path = self._store.artifact_path(
                manifest.session_id, RECOVERY_JOURNAL_NAME
            )
            journal: RecoveryJournal | None = None
            if journal_path.exists():
                try:
                    journal = RecoveryJournal.load(journal_path)
                    if journal.session_id != manifest.session_id:
                        raise ValueError("recovery journal session_id mismatch")
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    errors.append(f"{manifest.session_id}: invalid recovery journal: {exc}")
                    continue

            recovery_failed = False
            if journal is not None:
                for process in reversed(journal.processes):
                    current = self._fingerprint(process.pid)
                    if not _same_process(process, current):
                        skipped.append(process.pid)
                        continue
                    try:
                        self._terminate(process.pid)
                        terminated.append(process.pid)
                    except ProcessLookupError:
                        skipped.append(process.pid)
                    except OSError as exc:
                        errors.append(
                            f"{manifest.session_id}: terminate {process.role} pid {process.pid}: {exc}"
                        )
                        recovery_failed = True
                try:
                    self._restore_tracing(journal.tracing)
                except Exception as exc:
                    errors.append(f"{manifest.session_id}: restore tracing: {exc}")
                    continue
                if recovery_failed:
                    continue

            try:
                interrupted = manifest.transition(JobState.INTERRUPTED)
                self._store.save(interrupted)
                if journal_path.exists():
                    journal_path.unlink()
                recovered.append(manifest.session_id)
            except (OSError, ValueError) as exc:
                errors.append(f"{manifest.session_id}: finalize recovery: {exc}")

        return RecoveryReport(
            recovered_sessions=tuple(recovered),
            terminated_pids=tuple(terminated),
            skipped_pids=tuple(skipped),
            errors=tuple(errors),
        )


def linux_process_fingerprint(pid: int) -> ProcessFingerprint | None:
    if pid <= 0:
        return None
    stat_path = Path("/proc") / str(pid) / "stat"
    try:
        raw = stat_path.read_text(encoding="utf-8")
        closing = raw.rfind(")")
        if closing < 0:
            return None
        fields = raw[closing + 2 :].split()
        start_token = fields[19]
        executable = os.readlink(Path("/proc") / str(pid) / "exe")
    except (OSError, IndexError):
        return None
    return ProcessFingerprint(pid=pid, start_token=start_token, executable=executable)


def _same_process(
    expected: JournalProcess,
    current: ProcessFingerprint | None,
) -> bool:
    return (
        current is not None
        and current.pid == expected.pid
        and current.start_token == expected.start_token
        and current.executable == expected.executable
    )


def _terminate_process(pid: int) -> None:
    os.kill(pid, signal.SIGTERM)


def _string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _required_string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _required_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _positive_int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _utc(value: datetime | None) -> datetime:
    timestamp = value or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        raise ValueError("recovery timestamp must be timezone-aware")
    return timestamp.astimezone(timezone.utc)


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _format_time(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")
