"""Audited recovery for captures blocked by Session artifact finalization.

The repair is deliberately narrow: it accepts only non-terminal v2 Sessions
whose capture context proves that Chrome, both packet captures, the trace
boundary, and the runtime proxy semantics snapshot completed successfully.
It never launches Chrome, tshark, or Mihomo and it never changes a proxy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from traffictracer.capture.tshark import capture_output_complete
from traffictracer.jobs.models import JobState
from traffictracer.session.atomic import write_json_atomic
from traffictracer.session.manifest import Artifact, SessionManifest
from traffictracer.session.store import MANIFEST_NAME, SessionStore


REPAIR_WARNING = "RECOVERED_AFTER_ARTIFACT_CONTRACT_FAILURE"
REPAIR_REPORT_NAME = "finalization-repair-report.json"
_REQUIRED_RAW = (
    "capture-context.json",
    "proxy-semantics.json",
    "mihomo-trace.jsonl",
    "netlog.json",
    "cdp.json",
    "tun.pcap",
    "phys.pcap",
)
_OPTIONAL_RAW = (
    "proxy-info.json",
    "chrome-stderr.log",
)


@dataclass(frozen=True)
class RepairInspection:
    session_id: str
    session_dir: str
    output_root: str
    eligible: bool
    artifacts: tuple[str, ...]
    errors: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "session_dir": self.session_dir,
            "output_root": self.output_root,
            "eligible": self.eligible,
            "artifacts": list(self.artifacts),
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class SessionRepairResult:
    inspection: RepairInspection
    applied: bool
    state: str
    backup_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = self.inspection.to_dict()
        payload.update({"applied": self.applied, "state": self.state})
        if self.backup_path is not None:
            payload["backup_path"] = self.backup_path
        return payload


def inspect_finalization_failure(
    output_root: str | Path,
    session_dir: str | Path,
    *,
    pcap_validator: Callable[[Path], bool] = capture_output_complete,
) -> RepairInspection:
    root = Path(output_root).expanduser().resolve(strict=True)
    session = Path(session_dir).expanduser().resolve(strict=True)
    errors: list[str] = []
    warnings: list[str] = []
    artifacts: list[str] = []

    try:
        session.relative_to(root)
    except ValueError:
        errors.append("session directory escapes its run output root")

    manifest_path = session / MANIFEST_NAME
    try:
        manifest = SessionManifest.load(manifest_path)
    except Exception as exc:
        return RepairInspection(
            "", str(session), str(root), False, (),
            (f"manifest is invalid: {_safe_error(exc)}",), (),
        )
    if Path(manifest.session_dir).resolve() != session:
        errors.append("manifest session_dir does not match the selected directory")
    if manifest.schema_version != 2:
        errors.append("only Session v2 manifests are repairable")
    if manifest.state is not JobState.CAPTURING:
        errors.append(
            "repair requires a Session left in capturing state; observed "
            f"{manifest.state.value}"
        )
    if any(item.phase == "analysis" for item in manifest.artifacts):
        errors.append("Session already contains analysis artifacts")

    raw = session / "raw"
    paths = {name: raw / name for name in (*_REQUIRED_RAW, *_OPTIONAL_RAW)}
    for name in _REQUIRED_RAW:
        if not paths[name].is_file():
            errors.append(f"required capture artifact is missing: raw/{name}")
    if errors:
        return RepairInspection(
            manifest.session_id, str(session), str(root), False, (),
            tuple(errors), tuple(warnings),
        )

    context = _load_json_object(paths["capture-context.json"], errors)
    semantics = _load_json_object(paths["proxy-semantics.json"], errors)
    _load_json(paths["netlog.json"], errors)
    _load_json(paths["cdp.json"], errors)

    if context:
        if context.get("session_id") != manifest.session_id:
            errors.append("capture context session_id does not match manifest")
        target = context.get("target", {})
        if not isinstance(target, dict) or (
            target.get("url") != manifest.target.url
            or target.get("domain") != manifest.target.domain
        ):
            errors.append("capture context target does not match manifest")
        coverage = context.get("packet_coverage", {})
        if not isinstance(coverage, dict) or coverage.get("status") != "passed":
            errors.append("packet coverage is not passed")
        else:
            for side in ("tun", "physical"):
                exit_info = coverage.get("exit", {}).get(side, {})
                if (
                    not isinstance(exit_info, dict)
                    or exit_info.get("code") != 0
                    or exit_info.get("killed") is not False
                ):
                    errors.append(f"{side} packet capture did not stop cleanly")
        browser = context.get("browser_lifecycle", {})
        if (
            not isinstance(browser, dict)
            or browser.get("status") != "expected_exit"
            or browser.get("exit_code") != 0
        ):
            errors.append("Chrome lifecycle is not a clean expected exit")
        summary = context.get("proxy_semantics", {})
        if (
            not isinstance(summary, dict)
            or summary.get("verification", {}).get("state") != "passed"
        ):
            errors.append("runtime proxy semantics verification is not passed")
        boundary = context.get("trace_boundary", {})
        _validate_trace_boundary(
            paths["mihomo-trace.jsonl"], boundary, manifest.session_id, errors
        )

    if semantics:
        if semantics.get("schema_version") != 1:
            errors.append("runtime proxy semantics schema_version is unsupported")
        verification = semantics.get("verification", {})
        if not isinstance(verification, dict) or verification.get("state") != "passed":
            errors.append("runtime proxy semantics start/end verification failed")
        if semantics.get("capture_time_authoritative") is not True:
            errors.append("runtime proxy semantics is not capture-time authoritative")

    for name in ("tun.pcap", "phys.pcap"):
        try:
            valid = pcap_validator(paths[name])
        except Exception as exc:
            valid = False
            errors.append(f"raw/{name} validation failed: {_safe_error(exc)}")
        if not valid and not any(f"raw/{name} validation failed" in item for item in errors):
            errors.append(f"raw/{name} is incomplete or invalid")

    for name in (*_REQUIRED_RAW, *_OPTIONAL_RAW):
        if paths[name].is_file():
            artifacts.append(f"raw/{name}")
    if REPAIR_WARNING in manifest.warnings:
        warnings.append("Session already carries the finalization repair marker")

    return RepairInspection(
        manifest.session_id,
        str(session),
        str(root),
        not errors,
        tuple(artifacts),
        tuple(errors),
        tuple(warnings),
    )


def repair_finalization_failure(
    output_root: str | Path,
    session_dir: str | Path,
    *,
    apply: bool = False,
    now: datetime | None = None,
    pcap_validator: Callable[[Path], bool] = capture_output_complete,
) -> SessionRepairResult:
    inspection = inspect_finalization_failure(
        output_root, session_dir, pcap_validator=pcap_validator
    )
    if not inspection.eligible:
        return SessionRepairResult(inspection, False, "ineligible")
    if not apply:
        return SessionRepairResult(inspection, False, "eligible")

    root = Path(inspection.output_root)
    session = Path(inspection.session_dir)
    manifest_path = session / MANIFEST_NAME
    manifest = SessionManifest.load(manifest_path)
    timestamp = _utc(now)
    backup_dir = session / "diagnostics" / "finalization-repair"
    backup_path = backup_dir / "manifest.before.json"
    if backup_path.exists():
        raise FileExistsError(
            f"finalization repair backup already exists: {backup_path}"
        )
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    write_json_atomic(backup_path, manifest.to_dict())

    updated = manifest
    existing = {artifact.path for artifact in updated.artifacts}
    for relative in inspection.artifacts:
        if relative in existing:
            continue
        path = session / relative
        updated = updated.with_artifact(
            Artifact(
                name=path.name,
                kind="raw",
                phase="capture",
                path=relative,
                media_type=_media_type(path),
                size_bytes=path.stat().st_size,
                size_semantics=(
                    "as_of" if relative == "raw/mihomo-trace.jsonl" else "exact"
                ),
                sha256=_sha256(path),
                created_at=datetime.fromtimestamp(
                    path.stat().st_mtime, tz=timezone.utc
                ),
            ),
            now=timestamp,
        )
        existing.add(relative)
    if REPAIR_WARNING not in updated.warnings:
        updated = updated.with_warning(REPAIR_WARNING, now=timestamp)
    updated = updated.transition(JobState.COMPLETED, now=timestamp)
    SessionStore(root).save(updated)
    return SessionRepairResult(
        inspection, True, "capture_complete_recovered", str(backup_path)
    )


def _validate_trace_boundary(
    trace_path: Path,
    boundary: Any,
    session_id: str,
    errors: list[str],
) -> None:
    if not isinstance(boundary, dict):
        errors.append("capture trace boundary is missing")
        return
    if boundary.get("session_id") != session_id:
        errors.append("trace boundary session_id does not match manifest")
    event_seq = boundary.get("event_seq")
    if isinstance(event_seq, bool) or not isinstance(event_seq, int) or event_seq < 0:
        errors.append("trace boundary event_seq is invalid")
        return
    found = False
    try:
        with trace_path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    errors.append(
                        f"Mihomo trace line {line_number} is invalid JSON: {exc.msg}"
                    )
                    return
                if (
                    isinstance(event, dict)
                    and event.get("session_id") == session_id
                    and event.get("event_seq") == event_seq
                ):
                    found = True
    except OSError as exc:
        errors.append(f"Mihomo trace cannot be read: {_safe_error(exc)}")
        return
    if not found:
        errors.append("trace boundary event is not present in Mihomo trace")


def _load_json(path: Path, errors: list[str]) -> Any:
    try:
        with path.open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{path.name} is not valid JSON: {_safe_error(exc)}")
        return None


def _load_json_object(path: Path, errors: list[str]) -> dict[str, Any]:
    payload = _load_json(path, errors)
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        errors.append(f"{path.name} must contain a JSON object")
        return {}
    return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _media_type(path: Path) -> str:
    if path.suffix == ".pcap":
        return "application/vnd.tcpdump.pcap"
    if path.suffix == ".jsonl":
        return "application/x-ndjson"
    if path.suffix == ".log":
        return "text/plain"
    return "application/json"


def _safe_error(exc: Exception) -> str:
    text = str(exc).strip()
    return text[:1000] if text else type(exc).__name__


def _utc(value: datetime | None) -> datetime:
    timestamp = value or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        raise ValueError("repair timestamp must be timezone-aware")
    return timestamp.astimezone(timezone.utc)
