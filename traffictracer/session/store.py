"""Persistent, scope-safe storage for TrafficTracer Complete Sessions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
from typing import Callable
from uuid import UUID, uuid4

from .atomic import write_json_atomic
from .manifest import ComponentVersions, SessionManifest, SessionTarget


MANIFEST_NAME = "manifest.json"


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

    @property
    def output_root(self) -> Path:
        return self._root

    def create(
        self,
        *,
        job_id: str,
        target: SessionTarget,
        component_versions: ComponentVersions,
        now: datetime | None = None,
    ) -> SessionManifest:
        timestamp = _utc(now)
        session_id = str(self._id_factory())
        _validate_session_id(session_id)
        directory_name = f"{timestamp.strftime('%Y%m%dT%H%M%S.%fZ')}_{session_id}"
        session_dir = self._root / directory_name
        try:
            session_dir.mkdir(mode=0o700)
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
        if manifest.read_only:
            raise SessionStoreError("Session v1 manifest is read-only")
        session_dir = self._managed_directory(Path(manifest.session_dir))
        if not session_dir.is_dir():
            raise SessionNotFoundError(f"Session directory does not exist: {session_dir}")
        if not session_dir.name.endswith(f"_{manifest.session_id}"):
            raise UnsafeSessionPathError("Session directory name does not match session_id")
        write_json_atomic(session_dir / MANIFEST_NAME, manifest.to_dict())

    def get(self, session_id: str) -> SessionManifest:
        canonical = _validate_session_id(session_id)
        matches = tuple(self._root.glob(f"*_{canonical}"))
        if not matches:
            raise SessionNotFoundError(f"Session not found: {canonical}")
        if len(matches) != 1:
            raise CorruptSessionError(f"multiple Session directories found for {canonical}")
        return self._load_managed_manifest(matches[0])

    def scan(self) -> SessionScanResult:
        sessions: list[SessionManifest] = []
        corrupt: list[CorruptSession] = []
        for child in self._root.iterdir():
            manifest_path = child / MANIFEST_NAME
            if not manifest_path.is_file():
                continue
            try:
                sessions.append(self._load_managed_manifest(child))
            except (OSError, ValueError, json.JSONDecodeError, SessionStoreError) as exc:
                corrupt.append(CorruptSession(str(child), str(exc)))
        sessions.sort(key=lambda item: (item.created_at, item.session_id), reverse=True)
        corrupt.sort(key=lambda item: item.session_dir)
        return SessionScanResult(tuple(sessions), tuple(corrupt))

    def list_sessions(self) -> tuple[SessionManifest, ...]:
        return self.scan().sessions

    def artifact_path(self, session_id: str, relative_path: str | Path) -> Path:
        manifest = self.get(session_id)
        session_dir = self._managed_directory(Path(manifest.session_dir))
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
        if session_dir.parent != self._root or session_dir == self._root:
            raise UnsafeSessionPathError("refusing to delete outside output_root")
        shutil.rmtree(session_dir)

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
        if not managed.name.endswith(f"_{manifest.session_id}"):
            raise CorruptSessionError("manifest session_id does not match its directory name")
        return manifest

    def _managed_directory(self, path: Path) -> Path:
        if not path.is_absolute():
            raise UnsafeSessionPathError("Session directory must be absolute")
        resolved = path.resolve(strict=False)
        if resolved == self._root or resolved.parent != self._root:
            raise UnsafeSessionPathError("Session directory is outside output_root")
        return resolved


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
