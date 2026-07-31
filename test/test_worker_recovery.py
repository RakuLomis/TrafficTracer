"""Fault-injection tests for non-fatal Worker startup recovery."""

from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from traffictracer.contracts import validate_worker_message
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
    report = WorkerRecovery(
        store,
        restore_tracing=restored.append,
        notify=notifications.append,
        fingerprint=lambda pid: fingerprint,
        terminate=terminated.append,
    ).run()
    assert report.status == "ok"
    assert report.recovered_sessions == (manifest.session_id,)
    assert report.terminated_pids == (123,)
    assert terminated == [123]
    assert restored == [previous.to_dict()]
    assert store.get(manifest.session_id).state is JobState.INTERRUPTED
    assert not (Path(manifest.session_dir) / "recovery.json").exists()
    assert notifications[0]["params"]["code"] == "RECOVERY_COMPLETE"
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
