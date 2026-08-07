"""Crash recovery journal for interrupted Complete capture Sessions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import signal
from typing import Callable, Iterable, Mapping
from uuid import UUID

from traffictracer.jobs.models import JobState
from traffictracer.jobs.process_registry import ProcessRecord

from .atomic import write_json_atomic
from .store import SessionStore


RECOVERY_JOURNAL_NAME = "recovery.json"
RECOVERY_SCHEMA_VERSION = 2


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
    pgid: int | None = None
    profile: str = ""

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "role": self.role,
            "pid": self.pid,
            "start_token": self.start_token,
            "executable": self.executable,
        }
        if self.pgid is not None:
            payload["pgid"] = self.pgid
        if self.profile:
            payload["profile"] = self.profile
        return payload


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
                    pgid=record.pgid,
                    profile=record.profile,
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
        schema_version = payload["schema_version"]
        if schema_version not in {1, RECOVERY_SCHEMA_VERSION}:
            raise ValueError("unsupported recovery journal schema_version")
        tracing = payload["tracing"]
        processes = payload["processes"]
        if not isinstance(tracing, dict) or set(tracing) != {"enabled", "output", "session_id"}:
            raise ValueError("invalid recovery tracing snapshot")
        if not isinstance(processes, list):
            raise ValueError("invalid recovery process list")
        parsed_processes: list[JournalProcess] = []
        for item in processes:
            required = {"role", "pid", "start_token", "executable"}
            allowed = required | ({"pgid", "profile"} if schema_version == 2 else set())
            if not isinstance(item, dict) or not required <= set(item) or set(item) - allowed:
                raise ValueError("invalid recovery process identity")
            parsed_processes.append(
                JournalProcess(
                    role=_required_string(item["role"], "process role"),
                    pid=_positive_int(item["pid"], "process pid"),
                    start_token=_required_string(item["start_token"], "process start_token"),
                    executable=_string(item["executable"], "process executable"),
                    pgid=(
                        _positive_int(item["pgid"], "process pgid")
                        if "pgid" in item else None
                    ),
                    profile=_string(item.get("profile", ""), "process profile"),
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
            schema_version=schema_version,
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
        terminate_group: Callable[[int], None] | None = None,
        profile_members: Callable[[str, int], tuple[int, ...]] | None = None,
    ) -> None:
        self._store = store
        self._restore_tracing = restore_tracing
        self._fingerprint = fingerprint or linux_process_fingerprint
        self._terminate = terminate or _terminate_process
        self._terminate_group = terminate_group or _terminate_process_group
        self._profile_members = profile_members or _profile_processes

    def recover(self) -> RecoveryReport:
        recovered: list[str] = []
        terminated: list[int] = []
        skipped: list[int] = []
        errors: list[str] = []

        scan = self._store.scan()
        errors.extend(f"{item.session_dir}: {item.message}" for item in scan.corrupt)
        for manifest in scan.sessions:
            errors.extend(
                _recover_analysis_workspace(Path(manifest.session_dir))
            )
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
                    same_leader = _same_process(process, current)
                    members = (
                        self._profile_members(process.profile, process.pgid)
                        if process.profile and process.pgid is not None
                        else ()
                    )
                    if not same_leader and not members:
                        skipped.append(process.pid)
                        continue
                    try:
                        if process.pgid is not None and (same_leader or members):
                            self._terminate_group(process.pgid)
                            terminated.extend(members or (process.pid,))
                        else:
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


def _recover_analysis_workspace(session: Path) -> tuple[str, ...]:
    """Restore or remove only UUID-named atomic analysis work directories."""
    errors: list[str] = []
    staging: list[Path] = []
    backups: list[Path] = []
    try:
        entries = tuple(session.iterdir())
    except OSError as exc:
        return (f"{session}: inspect analysis workspace: {exc}",)

    for entry in entries:
        if _atomic_workspace_path(entry, ".analysis-staging-"):
            staging.append(entry)
        elif _atomic_workspace_path(entry, ".analysis-backup-"):
            backups.append(entry)

    analysis = session / "analysis"
    if analysis.is_symlink():
        return (f"{session}: analysis directory must not be a symbolic link",)

    backups.sort(key=lambda path: path.name)
    staging.sort(key=lambda path: path.name)
    if len(backups) > 1:
        errors.append(
            f"{session}: multiple analysis backups require manual recovery"
        )
        return tuple(errors)

    if backups:
        backup = backups[0]
        try:
            if analysis.exists():
                shutil.rmtree(backup)
            else:
                os.replace(backup, analysis)
        except OSError as exc:
            errors.append(f"{session}: recover analysis backup: {exc}")
            return tuple(errors)

    for path in staging:
        try:
            shutil.rmtree(path)
        except OSError as exc:
            errors.append(f"{session}: remove analysis staging {path.name}: {exc}")
    return tuple(errors)


def _atomic_workspace_path(path: Path, prefix: str) -> bool:
    if not path.name.startswith(prefix):
        return False
    suffix = path.name.removeprefix(prefix)
    try:
        valid_uuid = str(UUID(suffix)) == suffix
    except (ValueError, AttributeError):
        return False
    if not valid_uuid:
        return False
    if path.is_symlink() or not path.is_dir():
        return False
    return True

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


def _terminate_process_group(pgid: int) -> None:
    os.killpg(pgid, signal.SIGTERM)


def _profile_processes(profile: str, pgid: int) -> tuple[int, ...]:
    """Find exact-profile Chrome processes; never match by executable name."""
    from traffictracer.capture.chrome import linux_processes

    argument = f"--user-data-dir={Path(profile).resolve()}"
    return tuple(sorted(
        identity.pid
        for identity in linux_processes()
        if argument in identity.command
        and (identity.pgid == pgid or identity.pid == pgid)
    ))


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
