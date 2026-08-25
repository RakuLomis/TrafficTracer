"""Owned Chrome scratch-profile roots and fail-closed cold-profile cleanup."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
from uuid import UUID

MARKER_NAME = ".traffictracer-profile-root-v1"
PROFILE_ROOT_ENV = "TRAFFICTRACER_CHROME_PROFILE_ROOT"


class ProfileOwnershipError(RuntimeError):
    pass


class ProfileCleanupError(RuntimeError):
    pass


def resolve_owned_profile_root(override: str | Path | None = None) -> Path:
    configured = override or os.environ.get(PROFILE_ROOT_ENV, "")
    if configured:
        candidate = Path(configured)
    else:
        runtime = os.environ.get("XDG_RUNTIME_DIR", "")
        if runtime and Path(runtime).is_absolute():
            candidate = Path(runtime) / "traffictracer" / "chrome-profiles"
        else:
            candidate = (
                Path(tempfile.gettempdir())
                / f"traffictracer-{os.getuid()}"
                / "chrome-profiles"
            )
    if not candidate.is_absolute():
        raise ProfileOwnershipError("Chrome profile scratch root must be absolute")
    if candidate.is_symlink():
        raise ProfileOwnershipError("Chrome profile scratch root must not be a symlink")
    resolved = candidate.resolve(strict=False)
    broad = {Path("/"), Path.home().resolve(), Path(tempfile.gettempdir()).resolve()}
    if resolved in broad:
        raise ProfileOwnershipError("Chrome profile scratch root is too broad")
    browser_directories = {
        "google-chrome", "chromium", "chrome", "brave-browser", "microsoft-edge"
    }
    if any(part.lower() in browser_directories for part in resolved.parts):
        raise ProfileOwnershipError("Chrome profile scratch root overlaps a user browser")
    resolved.mkdir(parents=True, mode=0o700, exist_ok=True)
    if resolved.is_symlink() or not resolved.is_dir():
        raise ProfileOwnershipError("Chrome profile scratch root is not a directory")
    stat = resolved.stat()
    if hasattr(os, "getuid") and stat.st_uid != os.getuid():
        raise ProfileOwnershipError("Chrome profile scratch root is not owned by this user")
    if stat.st_mode & 0o077:
        raise ProfileOwnershipError("Chrome profile scratch root must use private permissions")
    marker = resolved / MARKER_NAME
    if marker.exists():
        _validate_marker(marker, resolved)
    else:
        _create_marker(marker, resolved)
    return resolved


def remove_owned_cold_profile(
    profile: str | Path,
    root: str | Path,
    session_id: str,
    *,
    attempts: int = 3,
) -> None:
    if attempts < 1:
        raise ValueError("profile cleanup attempts must be positive")
    owned_root = resolve_owned_profile_root(root)
    candidate = _validate_cold_profile(profile, owned_root, session_id)
    errors: list[str] = []
    for _ in range(attempts):
        if not candidate.exists():
            return
        try:
            shutil.rmtree(candidate)
        except OSError as exc:
            errors.append(str(exc))
        if not candidate.exists():
            return
    detail = errors[-1] if errors else "directory still exists"
    raise ProfileCleanupError(f"cold Chrome profile cleanup failed: {detail}")


def remove_recovered_cold_profile(
    profile: str | Path, session_id: str, *, attempts: int = 3
) -> bool:
    candidate = Path(profile)
    for parent in candidate.parents:
        marker = parent / MARKER_NAME
        if not marker.is_file():
            continue
        _validate_marker(marker, parent)
        resolved = candidate.resolve(strict=False)
        try:
            relative = resolved.relative_to(parent)
        except ValueError as exc:
            raise ProfileOwnershipError(
                "recovered Chrome profile is outside its marked root"
            ) from exc
        if len(relative.parts) == 3 and relative.parts[0] == "warm":
            # Warm profiles are intentionally reusable and must survive both
            # normal cleanup and Worker crash recovery.
            return False
        if len(relative.parts) != 3 or relative.parts[0] != "cold":
            raise ProfileOwnershipError(
                "recovered Chrome profile has an unexpected owned layout"
            )
        remove_owned_cold_profile(candidate, parent, session_id, attempts=attempts)
        return True
    return False


def _validate_cold_profile(profile: str | Path, root: Path, session_id: str) -> Path:
    canonical = str(UUID(session_id))
    if canonical != session_id.lower():
        raise ProfileOwnershipError("Session ID must be a canonical UUID")
    candidate = Path(profile)
    if not candidate.is_absolute() or candidate.is_symlink():
        raise ProfileOwnershipError("cold Chrome profile must be absolute and non-symlinked")
    resolved = candidate.resolve(strict=False)
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ProfileOwnershipError("cold Chrome profile is outside the owned root") from exc
    if len(relative.parts) != 3 or relative.parts[0] != "cold":
        raise ProfileOwnershipError("cold Chrome profile has an unexpected layout")
    if relative.parts[-1] != canonical:
        raise ProfileOwnershipError("cold Chrome profile does not match the Session")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ProfileOwnershipError("cold Chrome profile path contains a symlink")
    return resolved


def _marker_payload(root: Path) -> dict[str, object]:
    stat = root.stat()
    return {
        "schema_version": 1,
        "root": str(root),
        "device": stat.st_dev,
        "inode": stat.st_ino,
    }


def _create_marker(marker: Path, root: Path) -> None:
    payload = (json.dumps(_marker_payload(root), sort_keys=True) + "\n").encode()
    try:
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        _validate_marker(marker, root)
        return
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_marker(marker: Path, root: Path) -> None:
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileOwnershipError(f"invalid Chrome profile root marker: {exc}") from exc
    if payload != _marker_payload(root):
        raise ProfileOwnershipError("Chrome profile root marker does not match the directory")
