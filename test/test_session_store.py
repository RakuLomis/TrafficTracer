"""Tests for persistent and scope-safe Complete Session storage."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
from uuid import NAMESPACE_URL, UUID, uuid5

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


def test_known_session_artifact_path_is_direct_and_still_validates_context(
    tmp_path, monkeypatch
):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    manifest = _create(store)
    session_dir = Path(manifest.session_dir)
    monkeypatch.setattr(
        store,
        "get",
        lambda session_id: (_ for _ in ()).throw(
            AssertionError("direct lookup must not call SessionStore.get")
        ),
    )

    assert store.artifact_path_for_session(
        manifest.session_id, session_dir, "recovery.json"
    ) == session_dir / "recovery.json"
    with pytest.raises(UnsafeSessionPathError, match="match"):
        store.artifact_path_for_session(
            str(IDS[1]), session_dir, "recovery.json"
        )
    with pytest.raises(UnsafeSessionPathError, match="escapes"):
        store.artifact_path_for_session(
            manifest.session_id, session_dir, "../outside.json"
        )


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



def test_scan_ignores_chrome_extension_manifests(tmp_path):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    manifest = _create(store)
    extension = (
        tmp_path
        / ".chrome-profiles"
        / "example.com"
        / "main-page"
        / "Default"
        / "Extensions"
        / "extension-id"
        / "1.0.0"
    )
    extension.mkdir(parents=True)
    (extension / "manifest.json").write_text(
        json.dumps({"manifest_version": 3, "name": "Chrome extension"}),
        encoding="utf-8",
    )

    result = store.scan()

    assert [item.session_id for item in result.sessions] == [manifest.session_id]
    assert result.corrupt == ()


def test_scoped_scan_only_returns_selected_capture_group(tmp_path):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    first = store.create(
        job_id="2f746e31-d62a-4e1c-a919-3f88ecde31c2",
        target=SessionTarget("https://example.com/one", "example.com"),
        component_versions=_versions(),
        now=BASE_TIME,
        page_type="main-page",
        capture_group="20260731-080000-000",
    )
    second = store.create(
        job_id="c8c76aef-bbf2-45d4-96d6-9a0c52c34f91",
        target=SessionTarget("https://example.org/two", "example.org"),
        component_versions=_versions(),
        now=BASE_TIME + timedelta(seconds=1),
        page_type="video-play1",
        capture_group="20260731-080001-000",
    )

    scope = store.resolve_scope_path(tmp_path / "20260731-080000-000")
    result = store.scan_scope(scope.scope_id)

    assert scope.kind == "capture_group"
    assert scope.created_at == "2026-07-31T08:00:00Z"
    assert [item.session_id for item in result.sessions] == [first.session_id]
    assert second.session_id not in {item.session_id for item in result.sessions}
    assert store.scope_for_job(first.job_id) == scope


def test_scope_rejects_root_reserved_nested_external_and_symlink(tmp_path):
    store = SessionStore(tmp_path / "sessions")
    root = store.output_root
    (root / ".chrome-profiles").mkdir()
    group = root / "20260731-080000-000"
    (group / "example.com").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "20260731-080001-000").symlink_to(outside, target_is_directory=True)

    for selected in (root, root / ".chrome-profiles", group / "example.com", outside):
        with pytest.raises(UnsafeSessionPathError):
            store.resolve_scope_path(selected)
    with pytest.raises(UnsafeSessionPathError, match="symbolic link"):
        store.resolve_scope_path(root / "20260731-080001-000")


def test_missing_active_capture_group_can_be_resolved_but_not_scanned(tmp_path):
    store = SessionStore(tmp_path)
    scope = store.resolve_scope_id(
        "20260731-080000-000", allow_missing_capture_group=True
    )

    assert scope.exists is False
    assert scope.kind == "capture_group"
    assert store.scan_scope(scope.scope_id).sessions == ()
    assert store.scan_scope(scope.scope_id).corrupt == ()


def test_catalog_repeated_get_save_and_job_lookup_do_not_enumerate_root(
    tmp_path, monkeypatch
):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    manifest = _create(store)
    assert store.get(manifest.session_id) == manifest

    def unexpected_enumeration(*args, **kwargs):
        raise AssertionError("catalog hit must not enumerate unrelated Sessions")

    monkeypatch.setattr(store, "_manifest_candidates", unexpected_enumeration)
    updated = manifest.with_warning(
        "catalog update", now=BASE_TIME + timedelta(seconds=1)
    )
    store.save(updated)

    assert store.get(manifest.session_id) == updated
    assert store.session_id_for_job(manifest.job_id) == manifest.session_id
    assert store.scope_for_job(manifest.job_id).scope_id == Path(
        manifest.session_dir
    ).name


def test_catalog_rediscovers_a_valid_externally_moved_session(tmp_path):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    manifest = _create(store)
    assert store.get(manifest.session_id) == manifest
    original = Path(manifest.session_dir)
    moved = tmp_path / f"moved_{manifest.session_id}"
    original.rename(moved)
    manifest_path = moved / "manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["session_dir"] = str(moved.resolve())
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    discovered = store.get(manifest.session_id)

    assert discovered.session_dir == str(moved.resolve())
    assert not original.exists()


def test_catalog_invalidates_an_externally_removed_session(tmp_path):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    manifest = _create(store)
    assert store.get(manifest.session_id) == manifest
    shutil.rmtree(manifest.session_dir)

    with pytest.raises(SessionNotFoundError):
        store.get(manifest.session_id)


def test_catalog_reloads_replaced_manifest_and_fails_closed_on_corruption(tmp_path):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    manifest = _create(store)
    assert store.get(manifest.session_id) == manifest
    manifest_path = Path(manifest.session_dir) / "manifest.json"
    replaced = manifest.with_warning(
        "external replacement", now=BASE_TIME + timedelta(seconds=1)
    )
    manifest_path.write_text(json.dumps(replaced.to_dict()), encoding="utf-8")

    assert store.get(manifest.session_id) == replaced
    manifest_path.write_text("{bad-json", encoding="utf-8")
    with pytest.raises(CorruptSessionError, match="invalid Session manifest"):
        store.get(manifest.session_id)


def test_catalog_preserves_duplicate_session_id_failure(tmp_path):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    manifest = _create(store)
    source = Path(manifest.session_dir)
    duplicate = tmp_path / f"duplicate_{manifest.session_id}"
    shutil.copytree(source, duplicate)
    manifest_path = duplicate / "manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["session_dir"] = str(duplicate.resolve())
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(CorruptSessionError, match="multiple Session directories"):
        store.get(manifest.session_id)


def test_persistent_catalog_warm_load_materializes_only_selected_manifest(
    tmp_path, monkeypatch
):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    first = _create(store, now=BASE_TIME)
    _create(store, now=BASE_TIME + timedelta(seconds=1))
    store.scan()

    warm = SessionStore(tmp_path)
    loaded = []
    real_load = warm._load_managed_manifest

    def record_load(session_dir):
        loaded.append(Path(session_dir))
        return real_load(session_dir)

    monkeypatch.setattr(warm, "_load_managed_manifest", record_load)

    assert warm.get(first.session_id).session_id == first.session_id
    assert loaded == [Path(first.session_dir)]
    assert warm.catalog_timing["operation"] == "catalog.warm_reconcile"
    assert warm.catalog_timing["reconciled_changes"] == 0


def test_persistent_catalog_reconciles_only_changed_manifest(tmp_path, monkeypatch):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    first = _create(store, now=BASE_TIME)
    second = _create(store, now=BASE_TIME + timedelta(seconds=1))
    store.scan()
    changed = first.with_warning(
        "changed outside catalog", now=BASE_TIME + timedelta(seconds=2)
    )
    first_path = Path(first.session_dir) / "manifest.json"
    first_path.write_text(json.dumps(changed.to_dict()), encoding="utf-8")

    warm = SessionStore(tmp_path)
    loaded = []
    real_load = warm._load_managed_manifest

    def record_load(session_dir):
        loaded.append(Path(session_dir))
        return real_load(session_dir)

    monkeypatch.setattr(warm, "_load_managed_manifest", record_load)

    assert warm.get(first.session_id) == changed
    assert loaded == [Path(first.session_dir)]
    assert Path(second.session_dir) not in loaded
    assert warm.catalog_timing["reconciled_changes"] == 1


def test_corrupt_or_root_mismatched_persistent_catalog_rebuilds_safely(
    tmp_path, monkeypatch
):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    first = _create(store, now=BASE_TIME)
    second = _create(store, now=BASE_TIME + timedelta(seconds=1))
    store.scan()
    catalog_path = tmp_path / ".session-catalog" / "catalog-v1.json"
    payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    payload["root_identity"]["inode"] += 1
    catalog_path.write_text(json.dumps(payload), encoding="utf-8")

    rebuilt = SessionStore(tmp_path)
    loaded = []
    real_load = rebuilt._load_managed_manifest

    def record_load(session_dir):
        loaded.append(Path(session_dir))
        return real_load(session_dir)

    monkeypatch.setattr(rebuilt, "_load_managed_manifest", record_load)

    assert rebuilt.get(first.session_id).session_id == first.session_id
    assert set(loaded) == {Path(first.session_dir), Path(second.session_dir)}
    assert rebuilt.catalog_timing["operation"] == "catalog.cold_rebuild"
    repaired = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert repaired["root_identity"] == rebuilt._root_identity()


def test_removing_persistent_catalog_only_causes_safe_rebuild(tmp_path):
    store = SessionStore(tmp_path, id_factory=_factory(IDS))
    manifest = _create(store)
    store.scan()
    catalog_path = tmp_path / ".session-catalog" / "catalog-v1.json"
    catalog_path.unlink()

    rebuilt = SessionStore(tmp_path)

    assert rebuilt.get(manifest.session_id) == manifest
    assert rebuilt.catalog_timing["operation"] == "catalog.cold_rebuild"
    assert catalog_path.is_file()


def test_persistent_catalog_page_materializes_only_requested_history_slice(
    tmp_path, monkeypatch
):
    identifiers = iter(
        uuid5(NAMESPACE_URL, f"lazy-history-{index}") for index in range(30)
    )
    store = SessionStore(tmp_path, id_factory=lambda: next(identifiers))
    manifests = [
        _create(store, now=BASE_TIME + timedelta(seconds=index))
        for index in range(30)
    ]
    store.scan()

    warm = SessionStore(tmp_path)
    loaded = []
    real_load = warm._load_managed_manifest

    def record_load(session_dir):
        loaded.append(Path(session_dir))
        return real_load(session_dir)

    monkeypatch.setattr(warm, "_load_managed_manifest", record_load)
    page = warm.page(offset=10, limit=5)

    expected = list(reversed(manifests))[10:15]
    assert page.total == 30
    assert [item.session_id for item in page.sessions] == [
        item.session_id for item in expected
    ]
    assert loaded == [Path(item.session_dir) for item in expected]
    assert warm.page(offset=10, limit=5).sessions == page.sessions
    assert len(loaded) == 5
