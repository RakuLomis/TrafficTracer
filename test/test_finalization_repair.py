from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from traffictracer.jobs.models import JobState
from traffictracer.session.finalization_repair import (
    REPAIR_WARNING,
    inspect_finalization_failure,
    repair_finalization_failure,
)
from traffictracer.session.manifest import (
    ComponentVersion,
    ComponentVersions,
    SessionManifest,
    SessionTarget,
)
from traffictracer.session.store import SessionStore


BASE_TIME = datetime(2026, 9, 25, 15, 52, tzinfo=timezone.utc)


def _versions() -> ComponentVersions:
    return ComponentVersions(
        traffictracer=ComponentVersion("1.0.28", "a" * 40),
        mihomo=ComponentVersion("TrafficTracer", "b" * 40),
        clash_verge_rev=ComponentVersion("feat/traffic-tracer", "c" * 40),
    )


def _write_json(path: Path, payload) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _fixture(tmp_path: Path) -> tuple[Path, Path, SessionManifest]:
    root = tmp_path / "run"
    store = SessionStore(root)
    manifest = store.create(
        job_id="2f746e31-d62a-4e1c-a919-3f88ecde31c2",
        target=SessionTarget("https://example.com/", "example.com"),
        component_versions=_versions(),
        now=BASE_TIME,
    )
    manifest = manifest.transition(
        JobState.PREPARING, now=BASE_TIME + timedelta(seconds=1)
    ).transition(
        JobState.CAPTURING, now=BASE_TIME + timedelta(seconds=2)
    )
    store.save(manifest)
    session = Path(manifest.session_dir)
    raw = session / "raw"
    raw.mkdir()
    context = {
        "schema_version": 1,
        "session_id": manifest.session_id,
        "target": {
            "url": manifest.target.url,
            "domain": manifest.target.domain,
        },
        "browser_lifecycle": {
            "status": "expected_exit",
            "exit_code": 0,
        },
        "packet_coverage": {
            "status": "passed",
            "exit": {
                "tun": {"code": 0, "killed": False},
                "physical": {"code": 0, "killed": False},
            },
        },
        "proxy_semantics": {
            "verification": {"state": "passed"},
        },
        "trace_boundary": {
            "session_id": manifest.session_id,
            "event_seq": 7,
        },
    }
    _write_json(raw / "capture-context.json", context)
    _write_json(raw / "proxy-semantics.json", {
        "schema_version": 1,
        "capture_time_authoritative": True,
        "verification": {"state": "passed"},
    })
    _write_json(raw / "netlog.json", {"events": []})
    _write_json(raw / "cdp.json", {"events": []})
    _write_json(raw / "proxy-info.json", [])
    (raw / "mihomo-trace.jsonl").write_text(
        json.dumps({
            "schema_version": 1,
            "session_id": manifest.session_id,
            "event_seq": 7,
            "type": "trace_barrier",
        }) + "\n",
        encoding="utf-8",
    )
    (raw / "tun.pcap").write_bytes(b"fixture-tun")
    (raw / "phys.pcap").write_bytes(b"fixture-phys")
    return root, session, manifest


def test_finalization_repair_dry_run_is_read_only(tmp_path):
    root, session, manifest = _fixture(tmp_path)
    before = (session / "manifest.json").read_bytes()

    inspection = inspect_finalization_failure(
        root, session, pcap_validator=lambda path: True
    )
    result = repair_finalization_failure(
        root, session, apply=False, pcap_validator=lambda path: True
    )

    assert inspection.eligible is True
    assert "raw/proxy-semantics.json" in inspection.artifacts
    assert result.state == "eligible"
    assert result.applied is False
    assert (session / "manifest.json").read_bytes() == before
    assert SessionManifest.load(session / "manifest.json") == manifest


def test_finalization_repair_rebuilds_capture_manifest_with_audit(tmp_path):
    root, session, manifest = _fixture(tmp_path)
    semantics_before = (session / "raw" / "proxy-semantics.json").read_bytes()
    result = repair_finalization_failure(
        root,
        session,
        apply=True,
        now=BASE_TIME + timedelta(minutes=2),
        pcap_validator=lambda path: True,
    )

    repaired = SessionManifest.load(session / "manifest.json")
    assert result.applied is True
    assert result.state == "capture_complete_recovered"
    assert repaired.state is JobState.COMPLETED
    assert repaired.completed_at == BASE_TIME + timedelta(minutes=2)
    assert REPAIR_WARNING in repaired.warnings
    assert {
        artifact.role or artifact.to_dict()["role"]
        for artifact in repaired.artifacts
    } >= {
        "tun_pcap",
        "physical_pcap",
        "mihomo_trace",
        "proxy_semantics",
        "netlog",
        "cdp_events",
        "capture_context",
    }
    assert all(artifact.sha256 for artifact in repaired.artifacts)
    backup = Path(result.backup_path or "")
    assert backup.is_file()
    assert SessionManifest.load(backup) == manifest
    assert (
        session / "raw" / "proxy-semantics.json"
    ).read_bytes() == semantics_before
    semantics_artifact = next(item for item in repaired.artifacts if item.role == "proxy_semantics")
    assert semantics_artifact.sha256


def test_finalization_repair_rejects_incomplete_capture(tmp_path):
    root, session, _ = _fixture(tmp_path)
    context_path = session / "raw" / "capture-context.json"
    context = json.loads(context_path.read_text(encoding="utf-8"))
    context["packet_coverage"]["status"] = "failed"
    _write_json(context_path, context)

    result = repair_finalization_failure(
        root, session, apply=True, pcap_validator=lambda path: True
    )

    assert result.applied is False
    assert result.state == "ineligible"
    assert "packet coverage is not passed" in result.inspection.errors
    assert SessionManifest.load(session / "manifest.json").state is JobState.CAPTURING


def test_finalization_repair_requires_boundary_event(tmp_path):
    root, session, _ = _fixture(tmp_path)
    (session / "raw" / "mihomo-trace.jsonl").write_text(
        json.dumps({"session_id": "other", "event_seq": 7}) + "\n",
        encoding="utf-8",
    )

    inspection = inspect_finalization_failure(
        root, session, pcap_validator=lambda path: True
    )

    assert inspection.eligible is False
    assert "trace boundary event is not present" in " ".join(inspection.errors)
