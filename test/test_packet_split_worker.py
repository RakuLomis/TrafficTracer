from datetime import datetime, timezone
from pathlib import Path
from threading import Event

from traffictracer.jobs.models import JobState
from traffictracer.jobs.packet_split import (
    PacketSplitGroupSpec,
    PacketSplitPolicy,
)
from traffictracer.session.manifest import (
    Artifact,
    ComponentVersion,
    ComponentVersions,
    SessionTarget,
)
from traffictracer.worker.services import WorkerServices


def test_packet_split_job_spec_round_trips_through_versioned_contract(tmp_path):
    spec = PacketSplitGroupSpec(
        job_id="3edb7429-5718-48b4-93dc-1b3687b51d66",
        scope_id="20260814-080000-000",
        output_root=str(tmp_path),
        policy=PacketSplitPolicy.MISSING_ONLY,
    )
    assert PacketSplitGroupSpec.from_dict(spec.to_dict()) == spec


def test_scope_preview_and_session_summary_report_unsplit_standard_capture(tmp_path):
    services = WorkerServices(
        tmp_path / "sessions",
        notify=lambda message: None,
        shutdown_event=Event(),
    )
    version = ComponentVersion("complete", "unknown")
    manifest = services.store.create(
        job_id="bc973e98-c472-40c8-bf82-e2992352ece0",
        target=SessionTarget("https://example.com/", "example.com"),
        component_versions=ComponentVersions(version, version, version),
        now=datetime(2026, 8, 14, tzinfo=timezone.utc),
        page_type="main-page",
        capture_group="20260814-080000-000",
    )
    session = Path(manifest.session_dir)
    for relative in ("raw/tun.pcap", "raw/phys.pcap"):
        path = session / relative
        path.write_bytes(b"pcap")
        manifest = manifest.with_artifact(Artifact(
            name=path.name,
            path=relative,
            media_type="application/vnd.tcpdump.pcap",
            size_bytes=4,
            kind="raw",
        ))
    manifest = manifest.transition(JobState.PREPARING)
    manifest = manifest.transition(JobState.CAPTURING)
    services.store.save(manifest.transition(JobState.COMPLETED))

    preview = services.session_scope_packet_split_preview(
        {"scope_id": "20260814-080000-000"}
    )
    listed = services.session_scope_list({
        "scope_id": "20260814-080000-000",
        "offset": 0,
        "limit": 8,
    })

    assert preview["counts"] == {"unsplit": 1}
    assert preview["missing_only"] == 1
    assert preview["repair_incomplete"] == 0
    assert listed["sessions"][0]["packet_split"]["status"] == "unsplit"
