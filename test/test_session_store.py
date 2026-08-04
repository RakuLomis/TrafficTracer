"""Tests for persistent and scope-safe Complete Session storage."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from uuid import UUID

import pytest

from traffictracer.session.manifest import ComponentVersion, ComponentVersions, SessionTarget
from traffictracer.session.store import (
    CorruptSessionError,
    SessionNotFoundError,
    SessionStore,
    SessionStoreError,
    UnsafeSessionPathError,
)


BASE_TIME = datetime(2026, 7, 31, 8, 0, tzinfo=timezone.utc)
IDS = (
    UUID("5027aee9-c6e4-41de-8625-7ea0869a3307"),
    UUID("76904d43-1852-43a8-a37b-c2b719250bcd"),
)


def _versions():
    component = ComponentVersion("complete", "unknown")
    return ComponentVersions(component, component, component)


def _factory(values):
    iterator = iter(values)
    return lambda: next(iterator)


def _create(store, *, now=BASE_TIME):
    return store.create(
        job_id="2f746e31-d62a-4e1c-a919-3f88ecde31c2",
        target=SessionTarget("https://example.com/", "example.com"),
        component_versions=_versions(),
        now=now,
    )


def test_create_uses_utc_timestamp_uuid_and_persists_manifest(tmp_path):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    manifest = _create(store)
    session_dir = Path(manifest.session_dir)
    assert session_dir.parent == tmp_path.resolve()
    assert session_dir.name == "20260731T080000.000000Z_5027aee9-c6e4-41de-8625-7ea0869a3307"
    assert (session_dir / "manifest.json").is_file()
    assert store.get(manifest.session_id) == manifest


def test_list_is_newest_first_and_scan_reports_corrupt_manifests(tmp_path):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    older = _create(store, now=BASE_TIME)
    newer = _create(store, now=BASE_TIME + timedelta(seconds=1))
    corrupt_dir = tmp_path / "broken_11111111-1111-4111-8111-111111111111"
    corrupt_dir.mkdir()
    (corrupt_dir / "manifest.json").write_text("{not-json", encoding="utf-8")

    result = store.scan()
    assert [item.session_id for item in result.sessions] == [newer.session_id, older.session_id]
    assert store.list_sessions() == result.sessions
    assert len(result.corrupt) == 1
    assert result.corrupt[0].session_dir == str(corrupt_dir)


def test_artifact_path_rejects_absolute_parent_and_symlink_escape(tmp_path):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    manifest = _create(store)
    session_dir = Path(manifest.session_dir)
    assert store.artifact_path(manifest.session_id, "analysis/correlation.json") == (
        session_dir / "analysis/correlation.json"
    )
    with pytest.raises(UnsafeSessionPathError, match="relative"):
        store.artifact_path(manifest.session_id, "/tmp/outside.json")
    with pytest.raises(UnsafeSessionPathError, match="escapes"):
        store.artifact_path(manifest.session_id, "../outside.json")

    outside = tmp_path / "outside"
    outside.mkdir()
    (session_dir / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(UnsafeSessionPathError, match="escapes"):
        store.artifact_path(manifest.session_id, "link/data.json")


def test_delete_removes_only_a_valid_managed_session(tmp_path):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    manifest = _create(store)
    session_dir = Path(manifest.session_dir)
    outside = tmp_path.parent / "must-survive"
    outside.mkdir(exist_ok=True)
    store.delete(manifest.session_id)
    assert not session_dir.exists()
    assert outside.exists()
    with pytest.raises(SessionNotFoundError):
        store.get(manifest.session_id)


def test_manifest_declaring_external_directory_is_corrupt_and_not_deleted(tmp_path):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    manifest = _create(store)
    session_dir = Path(manifest.session_dir)
    outside = tmp_path.parent / "external-session"
    outside.mkdir(exist_ok=True)
    manifest_path = session_dir / "manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["session_dir"] = str(outside.resolve())
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(CorruptSessionError, match="outside output_root"):
        store.delete(manifest.session_id)
    assert session_dir.exists()
    assert outside.exists()


def test_constructor_and_ids_reject_ambiguous_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="absolute"):
        SessionStore("relative-output")
    store = SessionStore(tmp_path / "sessions")
    with pytest.raises(ValueError, match="invalid Session UUID"):
        store.get("not-a-uuid")


def test_cleanup_preview_lists_legacy_pcaps_without_deleting_or_escaping(tmp_path):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    manifest = _create(store)
    session = Path(manifest.session_dir)
    legacy = session / "captures" / "example.com" / "all_1" / "flows" / "url"
    legacy.mkdir(parents=True)
    pcap = legacy / "pre_proxy.pcap"
    pcap.write_bytes(b"legacy-pcap")
    outside = tmp_path.parent / "cleanup-preview-outside.pcap"
    outside.write_bytes(b"outside")
    (legacy / "escape.pcap").symlink_to(outside)

    preview = store.preview_derived_cleanup(manifest.session_id)

    assert preview["delete_supported"] is False
    assert preview["candidate_count"] == 1
    assert preview["total_bytes"] == len(b"legacy-pcap")
    assert preview["candidates"][0]["reason"] == "legacy_per_url_derived_pcap"
    assert pcap.is_file()
    assert outside.read_bytes() == b"outside"


def test_scan_reads_v1_and_v2_manifests_together(tmp_path):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    current = _create(store, now=BASE_TIME)
    legacy = _create(store, now=BASE_TIME + timedelta(seconds=1))
    path = Path(legacy.session_dir) / "manifest.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["schema_version"] = 1
    payload["artifacts"] = []
    path.write_text(json.dumps(payload), encoding="utf-8")

    sessions = store.list_sessions()

    assert {item.schema_version for item in sessions} == {1, 2}
    assert store.get(legacy.session_id).read_only is True
    assert store.get(current.session_id).read_only is False
    with pytest.raises(ValueError, match="read-only"):
        store.get(legacy.session_id).with_warning("must not mutate")
    with pytest.raises(SessionStoreError, match="read-only"):
        store.save(store.get(legacy.session_id))


def test_cleanup_preview_keeps_latest_generation(tmp_path):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    manifest = _create(store)
    root = Path(manifest.session_dir) / "results" / "generations"
    older = root / "11111111-1111-4111-8111-111111111111"
    latest = root / "22222222-2222-4222-8222-222222222222"
    older.mkdir(parents=True)
    (older / "flow-index.json").write_bytes(b"old")
    latest.mkdir()
    (latest / "flow-index.json").write_bytes(b"new")

    preview = store.preview_derived_cleanup(manifest.session_id)

    assert preview["current_generation_id"] == latest.name
    assert [item["path"] for item in preview["candidates"]] == [
        f"results/generations/{older.name}/flow-index.json"
    ]
    assert (latest / "flow-index.json").read_bytes() == b"new"
