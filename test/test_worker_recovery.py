"""Fault-injection tests for non-fatal Worker startup recovery."""

from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID
from uuid import NAMESPACE_URL, uuid5

from traffictracer.contracts import validate_worker_message
from traffictracer.capture.profile import resolve_owned_profile_root
from traffictracer.jobs.models import JobState
from traffictracer.jobs.process_registry import ProcessRecord
from traffictracer.session.manifest import (
    ComponentVersion,
    ComponentVersions,
    SessionTarget,
)
from traffictracer.session.recovery import (
    ProcessFingerprint,
    RecoveryJournal,
    TracingSnapshot,
)
from traffictracer.session.store import SessionStore
from traffictracer.worker.recovery import WorkerRecovery


SESSION_ID = UUID("5027aee9-c6e4-41de-8625-7ea0869a3307")
NOW = datetime(2026, 7, 31, 8, 0, tzinfo=timezone.utc)


class StubProcess:
    pid = 123


def _capturing_store(tmp_path):
    store = SessionStore(tmp_path, id_factory=lambda: SESSION_ID)
    version = ComponentVersion("complete", "unknown")
    manifest = store.create(
        job_id="2f746e31-d62a-4e1c-a919-3f88ecde31c2",
        target=SessionTarget("https://example.com/", "example.com"),
        component_versions=ComponentVersions(version, version, version),
        now=NOW,
    )
    manifest = manifest.transition(JobState.PREPARING, now=NOW)
    manifest = manifest.transition(JobState.CAPTURING, now=NOW)
    store.save(manifest)
    return store, manifest


def test_startup_recovery_terminates_fingerprinted_process_restores_and_notifies(
    tmp_path,
):
    store, manifest = _capturing_store(tmp_path)
    fingerprint = ProcessFingerprint(123, "start-1", "/usr/bin/chromium")
    previous = TracingSnapshot(True, "/tmp/previous.jsonl", "previous-session")
    RecoveryJournal.capture(
        session_id=manifest.session_id,
        tracing=previous,
        processes=[ProcessRecord(StubProcess(), "chrome", 123, NOW)],
        fingerprint=lambda pid: fingerprint,
        now=NOW,
    ).persist(store)
    restored = []
    terminated = []
    notifications = []
    clock = iter((100.0, 101.25)).__next__
    report = WorkerRecovery(
        store,
        restore_tracing=restored.append,
        notify=notifications.append,
        fingerprint=lambda pid: fingerprint,
        terminate=terminated.append,
        clock=clock,
    ).run()
    assert report.status == "ok"
    assert report.recovered_sessions == (manifest.session_id,)
    assert report.terminated_pids == (123,)
    assert terminated == [123]
    assert restored == [previous.to_dict()]
    assert store.get(manifest.session_id).state is JobState.INTERRUPTED
    assert not (Path(manifest.session_dir) / "recovery.json").exists()
    assert notifications[0]["params"]["code"] == "RECOVERY_COMPLETE"
    timing = notifications[0]["params"]["timing"]
    assert timing["operation"] == "worker.recovery"
    assert timing["duration_ms"] == 1250
    assert timing["catalog"]["operation"] == "catalog.cold_rebuild"
    assert validate_worker_message(notifications[0]) is notifications[0]


def test_restore_failure_is_visible_but_history_remains_readable(tmp_path):
    store, manifest = _capturing_store(tmp_path)
    RecoveryJournal.capture(
        session_id=manifest.session_id,
        tracing=TracingSnapshot(False, "", ""),
        processes=[],
        now=NOW,
    ).persist(store)

    def fail_restore(state):
        raise ConnectionError("controller offline")

    report = WorkerRecovery(store, restore_tracing=fail_restore).run()
    assert report.status == "degraded"
    assert "controller offline" in report.errors[0]
    sessions = store.list_sessions()
    assert [item.session_id for item in sessions] == [manifest.session_id]
    assert sessions[0].state is JobState.CAPTURING
    assert (Path(manifest.session_dir) / "recovery.json").exists()


def test_corrupt_journal_is_reported_without_blocking_session_scan(tmp_path):
    store, manifest = _capturing_store(tmp_path)
    (Path(manifest.session_dir) / "recovery.json").write_text(
        "{bad-json", encoding="utf-8"
    )
    report = WorkerRecovery(store, restore_tracing=lambda state: None).run()
    assert report.status == "degraded"
    assert "invalid recovery journal" in report.errors[0]
    assert store.get(manifest.session_id).state is JobState.CAPTURING



def test_startup_recovery_removes_atomic_analysis_workdirs_for_terminal_session(
    tmp_path,
):
    store, manifest = _capturing_store(tmp_path)
    completed = manifest.transition(JobState.COMPLETED)
    store.save(completed)
    session = Path(manifest.session_dir)
    analysis = session / "analysis"
    analysis.mkdir()
    (analysis / "summary.json").write_text("published", encoding="utf-8")
    backup = session / ".analysis-backup-11111111-1111-4111-8111-111111111111"
    staging = session / ".analysis-staging-22222222-2222-4222-8222-222222222222"
    backup.mkdir()
    staging.mkdir()

    report = WorkerRecovery(store, restore_tracing=lambda state: None).run()

    assert report.status == "ok"
    assert (analysis / "summary.json").read_text(encoding="utf-8") == "published"
    assert not backup.exists()
    assert not staging.exists()
    assert store.get(manifest.session_id).state is JobState.COMPLETED


def test_startup_recovery_restores_backup_when_publish_was_interrupted(tmp_path):
    store, manifest = _capturing_store(tmp_path)
    completed = manifest.transition(JobState.COMPLETED)
    store.save(completed)
    session = Path(manifest.session_dir)
    backup = session / ".analysis-backup-33333333-3333-4333-8333-333333333333"
    backup.mkdir()
    (backup / "summary.json").write_text("previous", encoding="utf-8")

    report = WorkerRecovery(store, restore_tracing=lambda state: None).run()

    assert report.status == "ok"
    assert not backup.exists()
    assert (session / "analysis" / "summary.json").read_text(
        encoding="utf-8"
    ) == "previous"

def test_unexpected_recovery_scan_failure_returns_degraded_report(
    tmp_path, monkeypatch
):
    import traffictracer.worker.recovery as module

    store, manifest = _capturing_store(tmp_path)

    def crash(self):
        raise OSError("filesystem unavailable")

    monkeypatch.setattr(module.RecoveryManager, "recover", crash)
    notifications = []
    report = WorkerRecovery(
        store,
        restore_tracing=lambda state: None,
        notify=notifications.append,
    ).run()
    assert report.status == "degraded"
    assert "filesystem unavailable" in report.errors[0]
    assert notifications[0]["params"]["code"] == "RECOVERY_DEGRADED"
    assert store.get(manifest.session_id).state is JobState.CAPTURING


def test_warm_recovery_materializes_only_nonterminal_catalog_candidates(
    tmp_path, monkeypatch
):
    identifiers = iter(
        uuid5(NAMESPACE_URL, f"recovery-candidate-{index}")
        for index in range(21)
    )
    store = SessionStore(tmp_path, id_factory=lambda: next(identifiers))
    version = ComponentVersion("complete", "unknown")
    versions = ComponentVersions(version, version, version)
    active = None
    for index in range(21):
        created = NOW.replace(microsecond=index)
        manifest = store.create(
            job_id=str(uuid5(NAMESPACE_URL, f"recovery-job-{index}")),
            target=SessionTarget(
                f"https://site-{index}.example/", f"site-{index}.example"
            ),
            component_versions=versions,
            now=created,
        )
        manifest = manifest.transition(JobState.PREPARING, now=created)
        manifest = manifest.transition(JobState.CAPTURING, now=created)
        if index < 20:
            manifest = manifest.transition(JobState.COMPLETED, now=created)
        else:
            active = manifest
        store.save(manifest)
    store.scan()

    warm = SessionStore(tmp_path)
    loaded = []
    real_load = warm._load_managed_manifest

    def record_load(session_dir):
        loaded.append(Path(session_dir))
        return real_load(session_dir)

    monkeypatch.setattr(warm, "_load_managed_manifest", record_load)
    report = WorkerRecovery(
        warm, restore_tracing=lambda snapshot: None
    ).run()

    assert active is not None
    assert report.recovered_sessions == (active.session_id,)
    assert set(loaded) == {Path(active.session_dir)}
    assert len(loaded) == 2  # candidate materialization plus persisted transition
    assert warm.catalog_timing["operation"] == "catalog.warm_reconcile"


def test_warm_catalog_preserves_corrupt_manifest_recovery_warning(tmp_path):
    store, manifest = _capturing_store(tmp_path)
    store.save(manifest.transition(JobState.INTERRUPTED, now=NOW))
    corrupt = tmp_path / "broken_11111111-1111-4111-8111-111111111111"
    corrupt.mkdir()
    (corrupt / "manifest.json").write_text("{bad-json", encoding="utf-8")
    store.scan()

    warm = SessionStore(tmp_path)
    report = WorkerRecovery(
        warm, restore_tracing=lambda snapshot: None
    ).run()

    assert report.status == "degraded"
    assert str(corrupt) in report.errors[0]
    assert warm.catalog_timing["operation"] == "catalog.warm_reconcile"


def test_recovery_removes_only_journaled_owned_cold_profile_after_process_exit(
    tmp_path,
):
    store, manifest = _capturing_store(tmp_path / "sessions")
    root = resolve_owned_profile_root(tmp_path / "scratch" / "profiles")
    profile = root / "cold" / "example.com" / manifest.session_id
    profile.mkdir(parents=True)
    (profile / "state").write_text("owned", encoding="utf-8")
    fingerprint = ProcessFingerprint(123, "start-1", "/usr/bin/chromium")
    RecoveryJournal.capture(
        session_id=manifest.session_id,
        tracing=TracingSnapshot(False, "", ""),
        processes=[ProcessRecord(StubProcess(), "chrome", 123, NOW, profile=str(profile))],
        fingerprint=lambda pid: fingerprint,
        now=NOW,
    ).persist(store)

    report = WorkerRecovery(
        store,
        restore_tracing=lambda snapshot: None,
        fingerprint=lambda pid: None,
    ).run()

    assert report.recovered_sessions == (manifest.session_id,)
    assert report.skipped_pids == (123,)
    assert not profile.exists()
    assert root.is_dir()
    assert store.get(manifest.session_id).state is JobState.INTERRUPTED
