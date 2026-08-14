from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
from uuid import UUID

from traffictracer.analyze.packet_split_status import (
    PacketSplitStatus,
    inspect_packet_split,
)
from traffictracer.jobs.models import JobState
from traffictracer.session.manifest import (
    Artifact,
    ComponentVersion,
    ComponentVersions,
    SessionTarget,
)
from traffictracer.session.store import SessionStore


FIXTURE = Path(__file__).parent / "fixtures/contracts/pcap-index-v1-valid.json"
GENERATION = "78fdab68-4e5d-4b67-9910-33da00a2632a"


def _completed(tmp_path):
    store = SessionStore(
        tmp_path,
        id_factory=lambda: UUID("5027aee9-c6e4-41de-8625-7ea0869a3307"),
    )
    version = ComponentVersion("complete", "unknown")
    manifest = store.create(
        job_id="bc973e98-c472-40c8-bf82-e2992352ece0",
        target=SessionTarget("https://example.com/", "example.com"),
        component_versions=ComponentVersions(version, version, version),
        now=datetime(2026, 8, 14, tzinfo=timezone.utc),
        page_type="main-page",
        capture_group="20260814-080000-000",
    )
    session = Path(manifest.session_dir)
    for relative, role in (
        ("raw/tun.pcap", "tun_pcap"),
        ("raw/phys.pcap", "physical_pcap"),
    ):
        path = session / relative
        path.write_bytes(b"pcap")
        manifest = manifest.with_artifact(Artifact(
            name=path.name,
            path=relative,
            media_type="application/vnd.tcpdump.pcap",
            size_bytes=4,
            phase="capture",
            role=role,
        ))
    manifest = manifest.transition(JobState.PREPARING)
    manifest = manifest.transition(JobState.CAPTURING)
    manifest = manifest.transition(JobState.COMPLETED)
    store.save(manifest)
    return store, manifest, session


def _publish_index(store, manifest, session, *, failed=False, missing=False):
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    if failed:
        payload["connections"][0]["pre_proxy"] = {
            "status": "failed",
            "display_filter": "tcp.stream eq 7",
            "packet_count": 0,
            "byte_count": 0,
            "error_code": "TSHARK_FAILED",
        }
    index = session / "analysis/pcap-index-v1.json"
    index.write_text(json.dumps(payload), encoding="utf-8")
    paths = [index]
    for connection in payload["connections"]:
        for side in (connection["pre_proxy"], connection["post_proxy"]):
            if side["status"] != "success":
                continue
            path = session / side["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            if not missing or not paths[1:]:
                path.write_bytes(b"pcap")
            paths.append(path)
    manifest = replace(
        manifest,
        artifacts=tuple(item for item in manifest.artifacts if item.phase != "analysis"),
    )
    for path in paths:
        relative = str(path.relative_to(session))
        manifest = manifest.with_artifact(Artifact(
            name=path.name,
            path=relative,
            media_type="application/json" if path.suffix == ".json" else "application/vnd.tcpdump.pcap",
            size_bytes=path.stat().st_size if path.exists() else 4,
            phase="analysis",
            role="pcap_index" if path is index else "derived_pcap",
            generation_id=GENERATION,
        ))
    store.save(manifest)
    return store.get(manifest.session_id)


def test_unsplit_requires_both_managed_raw_pcaps(tmp_path):
    _, manifest, _ = _completed(tmp_path)
    assert inspect_packet_split(manifest).status is PacketSplitStatus.UNSPLIT


def test_valid_published_generation_is_complete(tmp_path):
    store, manifest, session = _completed(tmp_path)
    manifest = _publish_index(store, manifest, session)
    inspection = inspect_packet_split(manifest)
    assert inspection.status is PacketSplitStatus.COMPLETE
    assert inspection.connection_count == 2


def test_failed_side_is_partial_and_runnable_only_for_repair(tmp_path):
    store, manifest, session = _completed(tmp_path)
    manifest = _publish_index(store, manifest, session, failed=True)
    inspection = inspect_packet_split(manifest)
    assert inspection.status is PacketSplitStatus.PARTIAL
    assert inspection.runnable_missing is False
    assert inspection.runnable_repair is True


def test_missing_published_split_file_is_stale(tmp_path):
    store, manifest, session = _completed(tmp_path)
    manifest = _publish_index(store, manifest, session, missing=True)
    assert inspect_packet_split(manifest).status is PacketSplitStatus.STALE
