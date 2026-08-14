"""Authoritative, side-effect-free status inspection for per-flow PCAP splits."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path

from traffictracer.contracts import validate_pcap_index
from traffictracer.jobs.models import JobState
from traffictracer.session.manifest import Artifact, SessionManifest


class PacketSplitStatus(str, Enum):
    UNSPLIT = "unsplit"
    COMPLETE = "complete"
    COMPLETE_EMPTY = "complete_empty"
    PARTIAL = "partial"
    STALE = "stale"
    RAW_MISSING = "raw_missing"
    INELIGIBLE = "ineligible"


@dataclass(frozen=True)
class PacketSplitInspection:
    status: PacketSplitStatus
    reason: str
    connection_count: int = 0

    @property
    def runnable_missing(self) -> bool:
        return self.status is PacketSplitStatus.UNSPLIT

    @property
    def runnable_repair(self) -> bool:
        return self.status in {PacketSplitStatus.PARTIAL, PacketSplitStatus.STALE}

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "reason": self.reason,
            "connection_count": self.connection_count,
            "runnable_missing": self.runnable_missing,
            "runnable_repair": self.runnable_repair,
        }


def inspect_packet_split(manifest: SessionManifest) -> PacketSplitInspection:
    """Inspect published evidence; directory presence alone never means complete."""
    if manifest.schema_version != 2 or manifest.state is not JobState.COMPLETED:
        return PacketSplitInspection(
            PacketSplitStatus.INELIGIBLE,
            "only completed Session v2 captures can be split",
        )

    session = Path(manifest.session_dir).resolve(strict=False)
    index_artifact = _latest_artifact(manifest, "pcap_index")
    index_path = session / "analysis" / "pcap-index-v1.json"
    if index_artifact is not None:
        index_path = session / index_artifact.path

    if not index_path.is_file():
        return _without_index(manifest, session)

    try:
        if index_path.is_symlink():
            raise ValueError("PCAP index must not be a symbolic link")
        resolved_index = index_path.resolve(strict=True)
        resolved_index.relative_to(session)
        payload = json.loads(resolved_index.read_text(encoding="utf-8"))
        validate_pcap_index(payload)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return PacketSplitInspection(
            PacketSplitStatus.STALE,
            f"published PCAP index is invalid: {exc}",
        )

    if payload["session_id"] != manifest.session_id:
        return PacketSplitInspection(
            PacketSplitStatus.STALE,
            "PCAP index belongs to a different Session",
        )
    if payload["split_mode"] == "none":
        return _without_index(manifest, session)

    generation = payload["analysis_generation_id"]
    if index_artifact is None or index_artifact.generation_id != generation:
        return PacketSplitInspection(
            PacketSplitStatus.STALE,
            "PCAP index generation is not the generation published by the Session manifest",
            len(payload["connections"]),
        )

    derived = {
        artifact.path: artifact
        for artifact in manifest.artifacts
        if artifact.role == "derived_pcap"
    }
    has_failed = False
    for connection in payload["connections"]:
        for side_name in ("pre_proxy", "post_proxy"):
            side = connection[side_name]
            status = side["status"]
            if status == "failed":
                has_failed = True
                continue
            if status == "not_requested":
                return PacketSplitInspection(
                    PacketSplitStatus.STALE,
                    f"{side_name} was not requested by a unique-connections split",
                    len(payload["connections"]),
                )
            if status != "success":
                continue
            relative = side["path"]
            artifact = derived.get(relative)
            if artifact is None or artifact.generation_id != generation:
                return PacketSplitInspection(
                    PacketSplitStatus.STALE,
                    f"{relative} is not published in the current analysis generation",
                    len(payload["connections"]),
                )
            if not _safe_regular_file(session, relative):
                return PacketSplitInspection(
                    PacketSplitStatus.STALE,
                    f"published split artifact is missing or unsafe: {relative}",
                    len(payload["connections"]),
                )

    count = len(payload["connections"])
    if has_failed:
        return PacketSplitInspection(
            PacketSplitStatus.PARTIAL,
            "one or more connection sides failed to split",
            count,
        )
    if count == 0:
        return PacketSplitInspection(
            PacketSplitStatus.COMPLETE_EMPTY,
            "split completed and no logical connections were eligible",
        )
    return PacketSplitInspection(
        PacketSplitStatus.COMPLETE,
        "all requested connection sides have terminal split evidence",
        count,
    )


def _without_index(
    manifest: SessionManifest, session: Path
) -> PacketSplitInspection:
    raw_roles = {artifact.role for artifact in manifest.artifacts}
    missing = []
    for role, relative in (("tun_pcap", "raw/tun.pcap"), ("physical_pcap", "raw/phys.pcap")):
        if role not in raw_roles or not _safe_regular_file(session, relative):
            missing.append(relative)
    if missing:
        return PacketSplitInspection(
            PacketSplitStatus.RAW_MISSING,
            "required raw capture is missing: " + ", ".join(missing),
        )
    return PacketSplitInspection(
        PacketSplitStatus.UNSPLIT,
        "raw captures are available and no unique-connections split is published",
    )


def _latest_artifact(manifest: SessionManifest, role: str) -> Artifact | None:
    matches = [artifact for artifact in manifest.artifacts if artifact.role == role]
    return matches[-1] if matches else None


def _safe_regular_file(session: Path, relative: str) -> bool:
    try:
        candidate = session / relative
        if candidate.is_symlink():
            return False
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(session)
        return resolved.is_file()
    except (OSError, ValueError):
        return False
