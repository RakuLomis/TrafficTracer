"""Persistent, scope-safe storage for TrafficTracer Complete Sessions."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
from threading import RLock
from time import perf_counter
from typing import Callable
from uuid import UUID, uuid4

from traffictracer.jobs.models import JobState
from traffictracer.layout import CapturePageLayout, group_directory_name


from .atomic import write_json_atomic
from .manifest import ComponentVersions, SessionManifest, SessionTarget


MANIFEST_NAME = "manifest.json"
_CATALOG_DIRECTORY = ".session-catalog"
_CATALOG_NAME = "catalog-v1.json"
_CATALOG_SCHEMA_VERSION = 1
_RESERVED_ROOT_DIRECTORIES = frozenset({
    ".batches", ".chrome-profiles", _CATALOG_DIRECTORY,
})
_CAPTURE_GROUP_NAME = re.compile(r"^\d{8}-\d{6}-\d{3}$")


class SessionStoreError(RuntimeError):
    """Base error for persistent Session storage."""


class SessionNotFoundError(SessionStoreError):
    pass


class CorruptSessionError(SessionStoreError):
    pass


class UnsafeSessionPathError(SessionStoreError):
    pass


@dataclass(frozen=True)
class CorruptSession:
    session_dir: str
    message: str


@dataclass(frozen=True)
class SessionScanResult:
    sessions: tuple[SessionManifest, ...]
    corrupt: tuple[CorruptSession, ...]


@dataclass(frozen=True)
class SessionPageResult:
    sessions: tuple[SessionManifest, ...]
    corrupt: tuple[CorruptSession, ...]
    total: int


@dataclass(frozen=True)
class SessionScope:
    scope_id: str
    directory: str
    kind: str
    created_at: str | None
    exists: bool

    def to_dict(self) -> dict[str, str | bool | None]:
        return {
            "scope_id": self.scope_id,
            "display_name": self.scope_id,
            "directory": self.directory,
            "kind": self.kind,
            "created_at": self.created_at,
            "exists": self.exists,
        }


@dataclass(frozen=True)
class _CatalogEntry:
    manifest_path: Path
    scope_id: str
    fingerprint: tuple[int, int, int, int]
    session_id: str
    job_id: str
    state: str
    created_at: datetime
    analysis_recovery: bool = False
    manifest: SessionManifest | None = None


class SessionStore:
    def __init__(
        self,
        output_root: str | Path,
        *,
        id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        root = Path(output_root)
        if not root.is_absolute():
            raise ValueError("output_root must be an absolute path")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._root = root.resolve(strict=True)
        if not self._root.is_dir():
            raise ValueError("output_root must be a directory")
        self._id_factory = id_factory
        self._catalog_lock = RLock()
        self._catalog_loaded = False
        self._catalog_by_path: dict[Path, _CatalogEntry] = {}
        self._catalog_by_id: dict[str, set[Path]] = {}
        self._catalog_by_job: dict[str, set[Path]] = {}
        self._catalog_by_scope: dict[str, set[Path]] = {}
        self._catalog_corrupt: dict[Path, CorruptSession] = {}
        self._catalog_corrupt_ids: dict[str, set[Path]] = {}
        self._catalog_corrupt_fingerprints: dict[Path, tuple[int, int, int, int]] = {}
        self._catalog_path = self._root / _CATALOG_DIRECTORY / _CATALOG_NAME
        self._catalog_timing: dict[str, object] = {}
        self._catalog_reconciled_changes = 0

    @property
    def output_root(self) -> Path:
        return self._root

    @property
    def catalog_timing(self) -> dict[str, object]:
        with self._catalog_lock:
            return dict(self._catalog_timing)

    def create(
        self,
        *,
        job_id: str,
        target: SessionTarget,
        component_versions: ComponentVersions,
        now: datetime | None = None,
        page_type: str | None = None,
        capture_group: str = "",
    ) -> SessionManifest:
        timestamp = _utc(now)
        session_id = str(self._id_factory())
        _validate_session_id(session_id)
        if page_type is None:
            directory_name = f"{timestamp.strftime('%Y%m%dT%H%M%S.%fZ')}_{session_id}"
            session_dir = self._root / directory_name
        else:
            layout = CapturePageLayout(
                self._root / (capture_group or group_directory_name(timestamp)),
                target.domain,
                page_type,
                target.url,
            )
            session_dir = layout.page_root
            retry = 2
            while session_dir.exists():
                session_dir = layout.page_root.with_name(
                    f"{layout.page_root.name}__retry{retry}"
                )
                retry += 1
        try:
            if page_type is None and session_dir.exists():
                raise FileExistsError(session_dir)
            session_dir.mkdir(parents=page_type is not None, mode=0o700)
            if page_type is not None:
                (session_dir / "raw").mkdir(mode=0o700)
                (session_dir / "analysis").mkdir(mode=0o700)
        except FileExistsError as exc:
            raise SessionStoreError(f"Session directory already exists: {session_dir}") from exc
        try:
            manifest = SessionManifest.create(
                session_id=session_id,
                job_id=job_id,
                session_dir=str(session_dir),
                target=target,
                component_versions=component_versions,
                now=timestamp,
            )
            self.save(manifest)
            return manifest
        except Exception:
            try:
                session_dir.rmdir()
            except OSError:
                pass
            raise

    def save(self, manifest: SessionManifest) -> None:
        with self._catalog_lock:
            if manifest.read_only:
                raise SessionStoreError("Session v1 manifest is read-only")
            session_dir = self._managed_directory(Path(manifest.session_dir))
            if not session_dir.is_dir():
                raise SessionNotFoundError(f"Session directory does not exist: {session_dir}")
            if session_dir.parent == self._root and not session_dir.name.endswith(f"_{manifest.session_id}"):
                raise UnsafeSessionPathError("Session directory name does not match session_id")
            manifest_path = session_dir / MANIFEST_NAME
            write_json_atomic(manifest_path, manifest.to_dict())
            if self._catalog_loaded:
                self._refresh_catalog_path_locked(manifest_path, force=True)
                self._persist_catalog_locked()

    def get(self, session_id: str) -> SessionManifest:
        canonical = _validate_session_id(session_id)
        with self._catalog_lock:
            self._ensure_catalog_locked()
            reconciled_before = self._catalog_reconciled_changes
            self._refresh_catalog_identity_locked(canonical)
            if not self._catalog_has_identity_locked(canonical):
                self._rebuild_catalog_locked()
                self._refresh_catalog_identity_locked(canonical)
            manifest = self._catalog_manifest_locked(canonical)
            if self._catalog_reconciled_changes != reconciled_before:
                self._persist_catalog_locked()
                self._catalog_timing["reconciled_changes"] = (
                    self._catalog_reconciled_changes
                )
            return manifest

    def scan(self) -> SessionScanResult:
        with self._catalog_lock:
            started_at = perf_counter()
            self._rebuild_catalog_locked()
            self._record_catalog_timing("catalog.full_rebuild", started_at)
            return self._catalog_snapshot_locked()

    def scan_scope(self, scope_id: str) -> SessionScanResult:
        scope = self.resolve_scope_id(scope_id, allow_missing_capture_group=True)
        if not scope.exists:
            return SessionScanResult((), ())
        with self._catalog_lock:
            self._ensure_catalog_locked()
            self._reconcile_catalog_scope_locked(
                scope.scope_id, Path(scope.directory)
            )
            self._persist_catalog_locked()
            return self._catalog_snapshot_locked(scope.scope_id)

    def resolve_scope_path(self, value: str | Path) -> SessionScope:
        path = Path(value)
        if not path.is_absolute():
            raise UnsafeSessionPathError("Session scope path must be absolute")
        if path.is_symlink():
            raise UnsafeSessionPathError("Session scope must not be a symbolic link")
        unresolved = path.resolve(strict=False)
        if unresolved.parent != self._root:
            raise UnsafeSessionPathError(
                "Session scope must be a direct child of output_root"
            )
        return self.resolve_scope_id(path.name)

    def resolve_scope_id(
        self,
        scope_id: str,
        *,
        allow_missing_capture_group: bool = False,
    ) -> SessionScope:
        if (
            not isinstance(scope_id, str)
            or not scope_id
            or scope_id in {".", ".."}
            or Path(scope_id).name != scope_id
            or scope_id.startswith(".")
            or scope_id in _RESERVED_ROOT_DIRECTORIES
        ):
            raise UnsafeSessionPathError("Invalid Session scope identifier")
        candidate = self._root / scope_id
        if candidate.is_symlink():
            raise UnsafeSessionPathError("Session scope must not be a symbolic link")
        resolved = candidate.resolve(strict=False)
        if resolved.parent != self._root:
            raise UnsafeSessionPathError("Session scope is outside output_root")
        exists = candidate.exists()
        if exists and not candidate.is_dir():
            raise UnsafeSessionPathError("Session scope must be a directory")
        direct_manifest = candidate / MANIFEST_NAME
        if exists and direct_manifest.is_file():
            kind = "legacy_session"
        elif exists and _CAPTURE_GROUP_NAME.fullmatch(scope_id):
            kind = "capture_group"
        elif (
            not exists
            and allow_missing_capture_group
            and _CAPTURE_GROUP_NAME.fullmatch(scope_id)
        ):
            kind = "capture_group"
        else:
            raise UnsafeSessionPathError(
                "Selected directory is not a TrafficTracer timestamp folder"
            )
        return SessionScope(
            scope_id=scope_id,
            directory=str(resolved),
            kind=kind,
            created_at=_scope_created_at(scope_id),
            exists=exists,
        )

    def scope_for_job(self, job_id: str) -> SessionScope | None:
        session_id = self.session_id_for_job(job_id)
        if session_id is None:
            return None
        manifest = self.get(session_id)
        relative = Path(manifest.session_dir).relative_to(self._root)
        return self.resolve_scope_id(relative.parts[0])

    def session_id_for_job(self, job_id: str) -> str | None:
        if not isinstance(job_id, str) or not job_id:
            return None
        with self._catalog_lock:
            self._ensure_catalog_locked()
            self._refresh_catalog_job_locked(job_id)
            if not self._catalog_by_job.get(job_id):
                self._rebuild_catalog_locked()
                self._refresh_catalog_job_locked(job_id)
            entries = [
                self._catalog_by_path[path]
                for path in self._catalog_by_job.get(job_id, set())
                if path in self._catalog_by_path
            ]
            if not entries:
                return None
            entries.sort(
                key=lambda entry: (
                    entry.created_at,
                    entry.session_id,
                ),
                reverse=True,
            )
            return entries[0].session_id

    def recovery_candidates(self) -> SessionScanResult:
        with self._catalog_lock:
            self._ensure_catalog_locked()
            entries = [
                entry
                for entry in self._catalog_by_path.values()
                if not JobState(entry.state).terminal or entry.analysis_recovery
            ]
            sessions = sorted(
                (
                    self._materialize_catalog_entry_locked(entry.manifest_path)
                    for entry in entries
                ),
                key=lambda item: (item.created_at, item.session_id),
                reverse=True,
            )
            corrupt = sorted(
                self._catalog_corrupt.values(), key=lambda item: item.session_dir
            )
            return SessionScanResult(tuple(sessions), tuple(corrupt))

    def page(
        self, *, offset: int, limit: int, scope_id: str | None = None
    ) -> SessionPageResult:
        if offset < 0 or limit < 1:
            raise ValueError("invalid Session page")
        with self._catalog_lock:
            self._ensure_catalog_locked()
            entries = (
                list(self._catalog_by_path.values())
                if scope_id is None
                else [
                    self._catalog_by_path[path]
                    for path in self._catalog_by_scope.get(scope_id, set())
                ]
            )
            entries.sort(
                key=lambda entry: (entry.created_at, entry.session_id),
                reverse=True,
            )
            selected = entries[offset:offset + limit]
            reconciled_before = self._catalog_reconciled_changes
            for entry in selected:
                self._refresh_catalog_path_locked(entry.manifest_path)
            sessions = tuple(
                self._materialize_catalog_entry_locked(entry.manifest_path)
                for entry in selected
            )
            if self._catalog_reconciled_changes != reconciled_before:
                self._persist_catalog_locked()
            corrupt = tuple(sorted(
                (
                    issue
                    for path, issue in self._catalog_corrupt.items()
                    if scope_id is None or self._path_scope_id(path) == scope_id
                ),
                key=lambda item: item.session_dir,
            ))
            return SessionPageResult(sessions, corrupt, len(entries))

    def set_analysis_recovery(self, session_id: str, required: bool) -> None:
        canonical = _validate_session_id(session_id)
        with self._catalog_lock:
            self._ensure_catalog_locked()
            self._refresh_catalog_identity_locked(canonical)
            paths = self._catalog_by_id.get(canonical, set())
            if len(paths) != 1:
                self._catalog_manifest_locked(canonical)
            path = next(iter(paths))
            entry = self._catalog_by_path[path]
            if entry.analysis_recovery == required:
                return
            self._catalog_by_path[path] = replace(
                entry, analysis_recovery=required
            )
            self._persist_catalog_locked()

    def clear_analysis_recovery_if_clean(self, session_id: str) -> bool:
        manifest = self.get(session_id)
        session_dir = self._managed_directory(Path(manifest.session_dir))
        if _analysis_workspace_exists(session_dir):
            return False
        self.set_analysis_recovery(session_id, False)
        return True

    def _scan_candidates(self, candidates) -> SessionScanResult:
        sessions: list[SessionManifest] = []
        corrupt: list[CorruptSession] = []
        for manifest_path in candidates:
            child = manifest_path.parent
            try:
                sessions.append(self._load_managed_manifest(child))
            except (OSError, ValueError, json.JSONDecodeError, SessionStoreError) as exc:
                corrupt.append(CorruptSession(str(child), str(exc)))
        sessions.sort(key=lambda item: (item.created_at, item.session_id), reverse=True)
        corrupt.sort(key=lambda item: item.session_dir)
        return SessionScanResult(tuple(sessions), tuple(corrupt))

    def _ensure_catalog_locked(self) -> None:
        if not self._catalog_loaded:
            started_at = perf_counter()
            if self._load_persistent_catalog_locked():
                operation = "catalog.warm_reconcile"
            else:
                self._rebuild_catalog_locked()
                operation = "catalog.cold_rebuild"
            self._record_catalog_timing(operation, started_at)

    def _rebuild_catalog_locked(self) -> None:
        self._catalog_by_path.clear()
        self._catalog_by_id.clear()
        self._catalog_by_job.clear()
        self._catalog_by_scope.clear()
        self._catalog_corrupt.clear()
        self._catalog_corrupt_ids.clear()
        self._catalog_corrupt_fingerprints.clear()
        for manifest_path in self._manifest_candidates():
            self._refresh_catalog_path_locked(manifest_path, force=True)
        self._catalog_loaded = True
        self._catalog_reconciled_changes = len(self._catalog_by_path)
        self._persist_catalog_locked()

    def _load_persistent_catalog_locked(self) -> bool:
        try:
            payload = json.loads(self._catalog_path.read_text(encoding="utf-8"))
            entries, corrupt_entries, discovery_fingerprint = (
                self._parse_persistent_catalog(payload)
            )
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return False

        self._catalog_by_path.clear()
        self._catalog_by_id.clear()
        self._catalog_by_job.clear()
        self._catalog_by_scope.clear()
        self._catalog_corrupt.clear()
        self._catalog_corrupt_ids.clear()
        self._catalog_corrupt_fingerprints.clear()
        for entry in entries:
            self._add_catalog_entry_locked(entry)
        for path, issue, fingerprint, session_id in corrupt_entries:
            self._catalog_corrupt[path] = issue
            self._catalog_corrupt_fingerprints[path] = fingerprint
            if session_id is not None:
                self._catalog_corrupt_ids.setdefault(session_id, set()).add(path)
        self._catalog_loaded = True
        if discovery_fingerprint == self._discovery_fingerprint():
            self._catalog_reconciled_changes = 0
            return True

        current_paths = {
            path.resolve(strict=False) for path in self._manifest_candidates()
        }
        cached_paths = set(self._catalog_by_path)
        changed = len(current_paths ^ cached_paths)
        for missing in cached_paths - current_paths:
            self._remove_catalog_path_locked(missing)
        for path in current_paths:
            previous = self._catalog_by_path.get(path)
            try:
                fingerprint = self._manifest_fingerprint(path)
            except OSError:
                fingerprint = None
            if previous is None or fingerprint != previous.fingerprint:
                changed += 1
                self._refresh_catalog_path_locked(path, force=True)
        self._catalog_reconciled_changes = changed
        if changed:
            self._persist_catalog_locked()
        return True

    def _parse_persistent_catalog(
        self, payload: object
    ) -> tuple[
        list[_CatalogEntry],
        list[tuple[Path, CorruptSession, tuple[int, int, int, int], str | None]],
        dict[str, object],
    ]:
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version", "output_root", "root_identity",
            "discovery_fingerprint", "entries", "corrupt",
        }:
            raise ValueError("invalid Session catalog fields")
        if payload["schema_version"] != _CATALOG_SCHEMA_VERSION:
            raise ValueError("unsupported Session catalog schema")
        if payload["output_root"] != str(self._root):
            raise ValueError("Session catalog output_root mismatch")
        if payload["root_identity"] != self._root_identity():
            raise ValueError("Session catalog root identity mismatch")
        discovery_fingerprint = payload["discovery_fingerprint"]
        self._validate_discovery_fingerprint(discovery_fingerprint)
        raw_entries = payload["entries"]
        if not isinstance(raw_entries, list):
            raise ValueError("Session catalog entries must be a list")
        entries: list[_CatalogEntry] = []
        seen_paths: set[Path] = set()
        for raw in raw_entries:
            if not isinstance(raw, dict) or set(raw) != {
                "path", "fingerprint", "session_id", "job_id", "scope_id",
                "state", "created_at",
                "analysis_recovery",
            }:
                raise ValueError("invalid Session catalog entry")
            raw_path = raw["path"]
            if not isinstance(raw_path, str) or not raw_path or raw_path.startswith("/"):
                raise ValueError("unsafe Session catalog path")
            parts = raw_path.split("/")
            if any(part in {"", ".", ".."} for part in parts):
                raise ValueError("unsafe Session catalog path")
            if parts[-1] != MANIFEST_NAME:
                raise ValueError("Session catalog path must name a manifest")
            # The canonical root plus a traversal-free relative path is already
            # absolute and contained. Avoid resolving every cached entry here:
            # selected entries are resolved and validated before materialization.
            manifest_path = self._root.joinpath(*parts)
            fingerprint_raw = raw["fingerprint"]
            if (
                not isinstance(fingerprint_raw, list)
                or len(fingerprint_raw) != 4
                or any(not isinstance(value, int) for value in fingerprint_raw)
            ):
                raise ValueError("invalid Session catalog fingerprint")
            session_id = _validate_session_id(raw["session_id"])
            job_id = raw["job_id"]
            scope_id = raw["scope_id"]
            state = raw["state"]
            analysis_recovery = raw["analysis_recovery"]
            if not all(
                isinstance(value, str) and value
                for value in (job_id, scope_id, state, raw["created_at"])
            ):
                raise ValueError("invalid Session catalog metadata")
            JobState(state)
            if not isinstance(analysis_recovery, bool):
                raise ValueError("invalid analysis recovery marker")
            created_at = _catalog_time(raw["created_at"])
            if scope_id != parts[0]:
                raise ValueError("Session catalog scope mismatch")
            if manifest_path in seen_paths:
                raise ValueError("duplicate Session catalog path")
            seen_paths.add(manifest_path)
            entries.append(_CatalogEntry(
                manifest_path=manifest_path,
                scope_id=scope_id,
                fingerprint=tuple(fingerprint_raw),
                session_id=session_id,
                job_id=job_id,
                state=state,
                created_at=created_at,
                analysis_recovery=analysis_recovery,
            ))
        raw_corrupt = payload["corrupt"]
        if not isinstance(raw_corrupt, list):
            raise ValueError("Session catalog corrupt entries must be a list")
        corrupt_entries = []
        for raw in raw_corrupt:
            if not isinstance(raw, dict) or set(raw) != {
                "path", "fingerprint", "message", "session_id"
            }:
                raise ValueError("invalid corrupt Session catalog entry")
            raw_path = raw["path"]
            if not isinstance(raw_path, str) or not raw_path or raw_path.startswith("/"):
                raise ValueError("unsafe corrupt Session catalog path")
            parts = raw_path.split("/")
            if (
                any(part in {"", ".", ".."} for part in parts)
                or parts[-1] != MANIFEST_NAME
            ):
                raise ValueError("unsafe corrupt Session catalog path")
            path = self._root.joinpath(*parts)
            if path in seen_paths:
                raise ValueError("catalog path is both valid and corrupt")
            seen_paths.add(path)
            fingerprint_raw = raw["fingerprint"]
            if (
                not isinstance(fingerprint_raw, list)
                or len(fingerprint_raw) != 4
                or any(not isinstance(item, int) for item in fingerprint_raw)
            ):
                raise ValueError("invalid corrupt Session fingerprint")
            message = raw["message"]
            if not isinstance(message, str) or not message:
                raise ValueError("invalid corrupt Session message")
            session_id_raw = raw["session_id"]
            session_id = (
                _validate_session_id(session_id_raw)
                if isinstance(session_id_raw, str)
                else None
            )
            if session_id_raw is not None and session_id is None:
                raise ValueError("invalid corrupt Session identity")
            corrupt_entries.append((
                path,
                CorruptSession(str(path.parent), message),
                tuple(fingerprint_raw),
                session_id,
            ))
        return entries, corrupt_entries, discovery_fingerprint

    def _persist_catalog_locked(self) -> None:
        directory = self._catalog_path.parent
        directory.mkdir(mode=0o700, exist_ok=True)
        entries = sorted(
            self._catalog_by_path.values(),
            key=lambda entry: str(entry.manifest_path),
        )
        write_json_atomic(
            self._catalog_path,
            {
                "schema_version": _CATALOG_SCHEMA_VERSION,
                "output_root": str(self._root),
                "root_identity": self._root_identity(),
                "discovery_fingerprint": self._discovery_fingerprint(),
                "entries": [self._persistent_catalog_entry(entry) for entry in entries],
                "corrupt": [
                    self._persistent_corrupt_entry(path, issue)
                    for path, issue in sorted(
                        self._catalog_corrupt.items(), key=lambda item: str(item[0])
                    )
                ],
            },
            indent=None,
        )

    def _persistent_catalog_entry(self, entry: _CatalogEntry) -> dict[str, object]:
        return {
            "path": entry.manifest_path.relative_to(self._root).as_posix(),
            "fingerprint": list(entry.fingerprint),
            "session_id": entry.session_id,
            "job_id": entry.job_id,
            "scope_id": entry.scope_id,
            "state": entry.state,
            "created_at": entry.created_at.isoformat().replace("+00:00", "Z"),
            "analysis_recovery": entry.analysis_recovery,
        }

    def _persistent_corrupt_entry(
        self, path: Path, issue: CorruptSession
    ) -> dict[str, object]:
        fingerprint = self._catalog_corrupt_fingerprints.get(path)
        if fingerprint is None:
            fingerprint = self._manifest_fingerprint(path)
        session_id = next(
            (
                identity
                for identity, paths in self._catalog_corrupt_ids.items()
                if path in paths
            ),
            None,
        )
        return {
            "path": path.relative_to(self._root).as_posix(),
            "fingerprint": list(fingerprint),
            "message": issue.message,
            "session_id": session_id,
        }

    def _root_identity(self) -> dict[str, int]:
        stat = self._root.stat()
        return {"device": stat.st_dev, "inode": stat.st_ino}

    def _discovery_fingerprint(self) -> dict[str, object]:
        root_stat = self._root.stat()
        groups: dict[str, list[int]] = {}
        for child in self._root.iterdir():
            if not _CAPTURE_GROUP_NAME.fullmatch(child.name):
                continue
            try:
                if child.is_symlink() or not child.is_dir():
                    continue
                stat = child.stat()
            except OSError:
                continue
            groups[child.name] = [stat.st_dev, stat.st_ino, stat.st_mtime_ns]
        return {
            "root_mtime_ns": root_stat.st_mtime_ns,
            "capture_groups": dict(sorted(groups.items())),
        }

    @staticmethod
    def _validate_discovery_fingerprint(value: object) -> None:
        if not isinstance(value, dict) or set(value) != {
            "root_mtime_ns", "capture_groups"
        }:
            raise ValueError("invalid catalog discovery fingerprint")
        if not isinstance(value["root_mtime_ns"], int):
            raise ValueError("invalid catalog root fingerprint")
        groups = value["capture_groups"]
        if not isinstance(groups, dict):
            raise ValueError("invalid catalog capture-group fingerprints")
        for name, fingerprint in groups.items():
            if (
                not isinstance(name, str)
                or not _CAPTURE_GROUP_NAME.fullmatch(name)
                or not isinstance(fingerprint, list)
                or len(fingerprint) != 3
                or any(not isinstance(item, int) for item in fingerprint)
            ):
                raise ValueError("invalid catalog capture-group fingerprint")

    def _record_catalog_timing(self, operation: str, started_at: float) -> None:
        self._catalog_timing = {
            "operation": operation,
            "duration_ms": max(0, int(round((perf_counter() - started_at) * 1000))),
            "entries": len(self._catalog_by_path),
            "corrupt": len(self._catalog_corrupt),
            "reconciled_changes": self._catalog_reconciled_changes,
        }

    def _reconcile_catalog_scope_locked(
        self, scope_id: str, scope_directory: Path
    ) -> None:
        for path in tuple(self._catalog_by_scope.get(scope_id, set())):
            self._remove_catalog_path_locked(path)
        for path in tuple(self._catalog_corrupt):
            if self._path_scope_id(path) == scope_id:
                self._remove_catalog_path_locked(path)
        for manifest_path in self._manifest_candidates(scope_directory):
            self._refresh_catalog_path_locked(manifest_path, force=True)

    def _refresh_catalog_identity_locked(self, session_id: str) -> None:
        paths = set(self._catalog_by_id.get(session_id, set()))
        paths.update(self._catalog_corrupt_ids.get(session_id, set()))
        for path in tuple(paths):
            self._refresh_catalog_path_locked(path)

    def _refresh_catalog_job_locked(self, job_id: str) -> None:
        for path in tuple(self._catalog_by_job.get(job_id, set())):
            self._refresh_catalog_path_locked(path)

    def _refresh_catalog_path_locked(
        self, manifest_path: Path, *, force: bool = False
    ) -> None:
        manifest_path = manifest_path.resolve(strict=False)
        previous = self._catalog_by_path.get(manifest_path)
        previously_corrupt = manifest_path in self._catalog_corrupt
        previous_id = previous.session_id if previous is not None else None
        try:
            fingerprint = self._manifest_fingerprint(manifest_path)
        except OSError:
            self._remove_catalog_path_locked(manifest_path)
            if previous is not None or previously_corrupt:
                self._catalog_reconciled_changes += 1
            return
        if previous is not None and not force and previous.fingerprint == fingerprint:
            return
        if (
            previously_corrupt
            or (previous is not None and previous.fingerprint != fingerprint)
        ):
            self._catalog_reconciled_changes += 1
        self._remove_catalog_path_locked(manifest_path)
        try:
           entry = self._catalog_entry(manifest_path)
        except (OSError, ValueError, json.JSONDecodeError, SessionStoreError) as exc:
            issue = CorruptSession(str(manifest_path.parent), str(exc))
            self._catalog_corrupt[manifest_path] = issue
            self._catalog_corrupt_fingerprints[manifest_path] = fingerprint
            corrupt_id = self._raw_manifest_session_id(manifest_path) or previous_id
            if corrupt_id is not None:
                self._catalog_corrupt_ids.setdefault(corrupt_id, set()).add(
                    manifest_path
                )
            return
        self._add_catalog_entry_locked(entry)

    def _catalog_entry(self, manifest_path: Path) -> _CatalogEntry:
        previous = self._catalog_by_path.get(manifest_path)
        analysis_recovery = (
            previous.analysis_recovery
            if previous is not None
            else _analysis_workspace_exists(manifest_path.parent)
        )
        for _ in range(2):
            before = self._manifest_fingerprint(manifest_path)
            manifest = self._load_managed_manifest(manifest_path.parent)
            after = self._manifest_fingerprint(manifest_path)
            if before == after:
                return _CatalogEntry(
                    manifest_path=manifest_path,
                    scope_id=self._path_scope_id(manifest_path),
                    fingerprint=after,
                    session_id=manifest.session_id,
                    job_id=manifest.job_id,
                    state=manifest.state.value,
                    created_at=manifest.created_at,
                    analysis_recovery=analysis_recovery,
                    manifest=manifest,
                )
        raise CorruptSessionError(
            f"Session manifest changed while being read: {manifest_path}"
        )

    @staticmethod
    def _manifest_fingerprint(path: Path) -> tuple[int, int, int, int]:
        stat = path.stat()
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)

    def _path_scope_id(self, manifest_path: Path) -> str:
        return manifest_path.parent.relative_to(self._root).parts[0]

    @staticmethod
    def _raw_manifest_session_id(manifest_path: Path) -> str | None:
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            value = payload.get("session_id") if isinstance(payload, dict) else None
            return _validate_session_id(value) if isinstance(value, str) else None
        except (OSError, ValueError, json.JSONDecodeError):
            return None

    def _add_catalog_entry_locked(self, entry: _CatalogEntry) -> None:
        path = entry.manifest_path
        self._catalog_by_path[path] = entry
        self._catalog_by_id.setdefault(entry.session_id, set()).add(path)
        self._catalog_by_job.setdefault(entry.job_id, set()).add(path)
        self._catalog_by_scope.setdefault(entry.scope_id, set()).add(path)

    def _remove_catalog_path_locked(self, path: Path) -> None:
        entry = self._catalog_by_path.pop(path, None)
        if entry is not None:
            self._discard_catalog_mapping(
                self._catalog_by_id, entry.session_id, path
            )
            self._discard_catalog_mapping(
                self._catalog_by_job, entry.job_id, path
            )
            self._discard_catalog_mapping(
                self._catalog_by_scope, entry.scope_id, path
            )
        self._catalog_corrupt.pop(path, None)
        self._catalog_corrupt_fingerprints.pop(path, None)
        for session_id in tuple(self._catalog_corrupt_ids):
            self._discard_catalog_mapping(
                self._catalog_corrupt_ids, session_id, path
            )

    @staticmethod
    def _discard_catalog_mapping(
        mapping: dict[str, set[Path]], key: str, path: Path
    ) -> None:
        paths = mapping.get(key)
        if paths is None:
            return
        paths.discard(path)
        if not paths:
            mapping.pop(key, None)

    def _catalog_has_identity_locked(self, session_id: str) -> bool:
        return bool(
            self._catalog_by_id.get(session_id)
            or self._catalog_corrupt_ids.get(session_id)
        )

    def _catalog_manifest_locked(self, session_id: str) -> SessionManifest:
        paths = self._catalog_by_id.get(session_id, set())
        if len(paths) > 1:
            raise CorruptSessionError(
                f"multiple Session directories found for {session_id}"
            )
        if len(paths) == 1:
            return self._materialize_catalog_entry_locked(next(iter(paths)))
        corrupt_paths = sorted(self._catalog_corrupt_ids.get(session_id, set()))
        if corrupt_paths:
            raise CorruptSessionError(
                self._catalog_corrupt[corrupt_paths[0]].message
            )
        raise SessionNotFoundError(f"Session not found: {session_id}")

    def _materialize_catalog_entry_locked(self, path: Path) -> SessionManifest:
        entry = self._catalog_by_path[path]
        if entry.manifest is not None:
            return entry.manifest
        self._refresh_catalog_path_locked(path, force=True)
        refreshed = self._catalog_by_path.get(path)
        if refreshed is None or refreshed.manifest is None:
            issue = self._catalog_corrupt.get(path)
            if issue is not None:
                raise CorruptSessionError(issue.message)
            raise SessionNotFoundError(f"Session manifest disappeared: {path}")
        return refreshed.manifest

    def _catalog_snapshot_locked(
        self, scope_id: str | None = None
    ) -> SessionScanResult:
        if scope_id is None:
            entries = list(self._catalog_by_path.values())
            corrupt = list(self._catalog_corrupt.values())
        else:
            entries = [
                self._catalog_by_path[path]
                for path in self._catalog_by_scope.get(scope_id, set())
            ]
            corrupt = [
                issue
                for path, issue in self._catalog_corrupt.items()
                if self._path_scope_id(path) == scope_id
            ]
        sessions = sorted(
            (
                self._materialize_catalog_entry_locked(entry.manifest_path)
                for entry in entries
            ),
            key=lambda item: (item.created_at, item.session_id),
            reverse=True,
        )
        corrupt.sort(key=lambda item: item.session_dir)
        return SessionScanResult(tuple(sessions), tuple(corrupt))

    def _manifest_candidates(self, scope: Path | None = None):
        roots = [scope] if scope is not None else self._session_roots()
        for root in roots:
            direct = root / MANIFEST_NAME
            if direct.is_file():
                yield direct
                continue
            if not root.is_dir():
                continue
            for domain in sorted(root.iterdir(), key=lambda item: item.name):
                if (
                    not domain.is_dir()
                    or domain.is_symlink()
                    or domain.name.startswith(".")
                ):
                    continue
                for page in sorted(domain.iterdir(), key=lambda item: item.name):
                    if (
                        not page.is_dir()
                        or page.is_symlink()
                        or page.name.startswith(".")
                    ):
                        continue
                    manifest_path = page / MANIFEST_NAME
                    if manifest_path.is_file():
                        yield manifest_path

    def _session_roots(self):
        for child in sorted(self._root.iterdir(), key=lambda item: item.name):
            if (
                child.name.startswith(".")
                or child.name in _RESERVED_ROOT_DIRECTORIES
                or child.is_symlink()
                or not child.is_dir()
            ):
                continue
            yield child

    def list_sessions(self) -> tuple[SessionManifest, ...]:
        return self.scan().sessions

    def artifact_path(self, session_id: str, relative_path: str | Path) -> Path:
        manifest = self.get(session_id)
        return self._artifact_path_in_session(
            self._managed_directory(Path(manifest.session_dir)), relative_path
        )

    def artifact_path_for_session(
        self,
        session_id: str,
        session_dir: str | Path,
        relative_path: str | Path,
    ) -> Path:
        """Resolve an artifact from an already known Session without a root scan."""
        canonical = _validate_session_id(session_id)
        managed = self._managed_directory(Path(session_dir))
        manifest = self._load_managed_manifest(managed)
        if manifest.session_id != canonical:
            raise UnsafeSessionPathError(
                "Session context does not match the requested session_id"
            )
        return self._artifact_path_in_session(managed, relative_path)

    @staticmethod
    def _artifact_path_in_session(
        session_dir: Path, relative_path: str | Path
    ) -> Path:
        relative = Path(relative_path)
        if relative.is_absolute() or relative == Path("."):
            raise UnsafeSessionPathError("artifact path must be a non-empty relative path")
        candidate = (session_dir / relative).resolve(strict=False)
        if candidate == session_dir or not candidate.is_relative_to(session_dir):
            raise UnsafeSessionPathError("artifact path escapes the Session directory")
        return candidate

    def preview_derived_cleanup(self, session_id: str) -> dict:
        """List safely removable legacy/stale derived files without deleting them."""
        manifest = self.get(session_id)
        session_dir = self._managed_directory(Path(manifest.session_dir))
        candidates: dict[str, dict] = {}

        generations = [
            getattr(artifact, "generation_id", None)
            for artifact in manifest.artifacts
            if getattr(artifact, "generation_id", None)
        ]
        current_generation = generations[-1] if generations else None
        generation_root = session_dir / "results" / "generations"
        generation_dirs = (
            sorted(
                (path for path in generation_root.iterdir() if path.is_dir()),
                key=lambda path: (path.stat().st_mtime_ns, path.name),
            )
            if generation_root.is_dir()
            else []
        )
        if generation_dirs:
            current_generation = generation_dirs[-1].name
            for generation_dir in generation_dirs[:-1]:
                for path in generation_dir.rglob("*"):
                    if not path.is_file():
                        continue
                    self._add_cleanup_candidate(
                        session_dir,
                        path.relative_to(session_dir),
                        "stale_analysis_generation",
                        candidates,
                    )
        for artifact in manifest.artifacts:
            generation_id = getattr(artifact, "generation_id", None)
            if not generation_id or generation_id == current_generation:
                continue
            self._add_cleanup_candidate(
                session_dir,
                artifact.path,
                "stale_analysis_generation",
                candidates,
            )

        captures = session_dir / "captures"
        if captures.is_dir():
            for path in captures.glob("*/*/flows/**/*.pcap"):
                try:
                    relative = path.relative_to(session_dir)
                except ValueError:
                    continue
                self._add_cleanup_candidate(
                    session_dir,
                    relative,
                    "legacy_per_url_derived_pcap",
                    candidates,
                )

        ordered = [candidates[key] for key in sorted(candidates)]
        return {
            "session_id": manifest.session_id,
            "delete_supported": False,
            "current_generation_id": current_generation,
            "candidate_count": len(ordered),
            "total_bytes": sum(item["size_bytes"] for item in ordered),
            "candidates": ordered,
        }

    def _add_cleanup_candidate(
        self,
        session_dir: Path,
        relative_path: str | Path,
        reason: str,
        output: dict[str, dict],
    ) -> None:
        relative = Path(relative_path)
        if relative.is_absolute() or relative == Path("."):
            return
        candidate = (session_dir / relative).resolve(strict=False)
        if candidate == session_dir or not candidate.is_relative_to(session_dir):
            return
        if not candidate.is_file():
            return
        normalized = str(candidate.relative_to(session_dir))
        output[normalized] = {
            "path": normalized,
            "reason": reason,
            "size_bytes": candidate.stat().st_size,
        }

    def delete(self, session_id: str) -> None:
        manifest = self.get(session_id)
        session_dir = self._managed_directory(Path(manifest.session_dir))
        if session_dir == self._root or not session_dir.is_relative_to(self._root):
            raise UnsafeSessionPathError("refusing to delete outside output_root")
        shutil.rmtree(session_dir)
        with self._catalog_lock:
            self._remove_catalog_path_locked(session_dir / MANIFEST_NAME)
            if self._catalog_loaded:
                self._persist_catalog_locked()

    def _load_managed_manifest(self, session_dir: Path) -> SessionManifest:
        managed = self._managed_directory(session_dir)
        manifest_path = managed / MANIFEST_NAME
        try:
            manifest = SessionManifest.load(manifest_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise CorruptSessionError(f"invalid Session manifest {manifest_path}: {exc}") from exc
        try:
            declared = self._managed_directory(Path(manifest.session_dir))
        except UnsafeSessionPathError as exc:
            raise CorruptSessionError(str(exc)) from exc
        if declared != managed:
            raise CorruptSessionError("manifest session_dir does not match its containing directory")
        if managed.parent == self._root and not managed.name.endswith(f"_{manifest.session_id}"):
            raise CorruptSessionError("manifest session_id does not match its directory name")
        return manifest

    def _managed_directory(self, path: Path) -> Path:
        if not path.is_absolute():
            raise UnsafeSessionPathError("Session directory must be absolute")
        resolved = path.resolve(strict=False)
        if resolved == self._root or not resolved.is_relative_to(self._root):
            raise UnsafeSessionPathError("Session directory is outside output_root")
        return resolved


def _scope_created_at(scope_id: str) -> str | None:
    if not _CAPTURE_GROUP_NAME.fullmatch(scope_id):
        return None
    value = datetime.strptime(scope_id, "%Y%m%d-%H%M%S-%f").replace(
        tzinfo=timezone.utc
    )
    return value.isoformat().replace("+00:00", "Z")


def _catalog_time(value: str) -> datetime:
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("Session catalog timestamp must be timezone-aware")
    return timestamp.astimezone(timezone.utc)


def _analysis_workspace_exists(session_dir: Path) -> bool:
    try:
        entries = session_dir.iterdir()
        return any(
            _owned_analysis_workspace(entry)
            for entry in entries
        )
    except OSError:
        return False


def _owned_analysis_workspace(path: Path) -> bool:
    if path.is_symlink() or not path.is_dir():
        return False
    for prefix in (".analysis-staging-", ".analysis-backup-"):
        if not path.name.startswith(prefix):
            continue
        value = path.name.removeprefix(prefix)
        try:
            return str(UUID(value)) == value.lower()
        except ValueError:
            return False
    return False


def _validate_session_id(value: str) -> str:
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"invalid Session UUID: {value!r}") from exc
    canonical = str(parsed)
    if value.lower() != canonical:
        raise ValueError(f"Session UUID must use canonical form: {value!r}")
    return canonical


def _utc(value: datetime | None) -> datetime:
    timestamp = value or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        raise ValueError("Session timestamps must be timezone-aware")
    return timestamp.astimezone(timezone.utc)
