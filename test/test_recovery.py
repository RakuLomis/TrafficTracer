"""Tests for idempotent, PID-safe interrupted Session recovery."""

from datetime import datetime, timezone
import os
from pathlib import Path
from uuid import UUID

from traffictracer.jobs.models import JobState
from traffictracer.jobs.process_registry import ProcessRecord
from traffictracer.session.manifest import ComponentVersion, ComponentVersions, SessionTarget
from traffictracer.session.recovery import (
    ProcessFingerprint,
    RecoveryJournal,
    RecoveryManager,
    TracingSnapshot,
    linux_process_fingerprint,
)
from traffictracer.session.store import SessionStore


NOW = datetime(2026, 7, 31, 8, 0, tzinfo=timezone.utc)
SESSION_ID = UUID("5027aee9-c6e4-41de-8625-7ea0869a3307")


class StubProcess:
    def __init__(self, pid):
        self.pid = pid


class IdFactory:
    def __init__(self):
        self.used = False

    def __call__(self):
        assert not self.used
        self.used = True
        return SESSION_ID


def _versions():
    value = ComponentVersion("complete", "unknown")
    return ComponentVersions(value, value, value)


def _capturing_store(tmp_path):
    store = SessionStore(tmp_path, id_factory=IdFactory())
    manifest = store.create(
        job_id="2f746e31-d62a-4e1c-a919-3f88ecde31c2",
        target=SessionTarget("https://example.com/", "example.com"),
        component_versions=_versions(),
        now=NOW,
    )
    manifest = manifest.transition(JobState.PREPARING, now=NOW)
    manifest = manifest.transition(JobState.CAPTURING, now=NOW)
    store.save(manifest)
    return store, manifest


def _record(pid=123, role="chrome", *, pgid=None, profile=""):
    return ProcessRecord(
        StubProcess(pid),
        role,
        pid,
        NOW,
        pgid=pgid,
        profile=profile,
    )


def test_journal_capture_persist_and_load(tmp_path):
    store, manifest = _capturing_store(tmp_path)
    fingerprint = ProcessFingerprint(123, "start-1", "/usr/bin/chrome")
    journal = RecoveryJournal.capture(
        session_id=manifest.session_id,
        tracing=TracingSnapshot(True, "/tmp/trace.jsonl", manifest.session_id),
        processes=[_record()],
        fingerprint=lambda pid: fingerprint,
        now=NOW,
    )
    path = journal.persist(store)
    assert path == Path(manifest.session_dir) / "recovery.json"
    assert RecoveryJournal.load(path) == journal


def test_journal_records_chrome_group_and_exact_profile(tmp_path):
    store, manifest = _capturing_store(tmp_path)
    fingerprint = ProcessFingerprint(123, "start-1", "/usr/bin/chrome")
    journal = RecoveryJournal.capture(
        session_id=manifest.session_id,
        tracing=TracingSnapshot(False, ""),
        processes=[_record(pgid=123, profile="/tmp/session profile")],
        fingerprint=lambda pid: fingerprint,
        now=NOW,
    )

    assert journal.schema_version == 2
    assert journal.processes[0].pgid == 123
    assert journal.processes[0].profile == "/tmp/session profile"
    assert RecoveryJournal.from_dict(journal.to_dict()) == journal


def test_recovery_terminates_exact_profile_group_after_leader_exits(tmp_path):
    store, manifest = _capturing_store(tmp_path)
    fingerprint = ProcessFingerprint(123, "start-1", "/usr/bin/chrome")
    RecoveryJournal.capture(
        session_id=manifest.session_id,
        tracing=TracingSnapshot(False, ""),
        processes=[_record(pgid=123, profile="/tmp/job-profile")],
        fingerprint=lambda pid: fingerprint,
        now=NOW,
    ).persist(store)
    groups = []
    report = RecoveryManager(
        store,
        restore_tracing=lambda snapshot: None,
        fingerprint=lambda pid: None,
        terminate_group=groups.append,
        profile_members=lambda profile, pgid: (124,),
    ).recover()

    assert groups == [123]
    assert report.terminated_pids == (124,)
    assert report.skipped_pids == ()


def test_recovery_terminates_matching_process_restores_and_is_idempotent(tmp_path):
    store, manifest = _capturing_store(tmp_path)
    fingerprint = ProcessFingerprint(123, "start-1", "/usr/bin/chrome")
    snapshot = TracingSnapshot(False, "/tmp/previous.jsonl", "previous-session")
    RecoveryJournal.capture(
        session_id=manifest.session_id,
        tracing=snapshot,
        processes=[_record()],
        fingerprint=lambda pid: fingerprint,
        now=NOW,
    ).persist(store)
    restored = []
    terminated = []
    manager = RecoveryManager(
        store,
        restore_tracing=restored.append,
        fingerprint=lambda pid: fingerprint,
        terminate=terminated.append,
    )

    first = manager.recover()
    assert first.recovered_sessions == (manifest.session_id,)
    assert first.terminated_pids == (123,)
    assert first.errors == ()
    assert restored == [snapshot]
    assert terminated == [123]
    assert store.get(manifest.session_id).state is JobState.INTERRUPTED
    assert not (Path(manifest.session_dir) / "recovery.json").exists()

    second = manager.recover()
    assert second.recovered_sessions == ()
    assert restored == [snapshot]
    assert terminated == [123]


def test_pid_reuse_fingerprint_mismatch_never_terminates_unrelated_process(tmp_path):
    store, manifest = _capturing_store(tmp_path)
    recorded = ProcessFingerprint(123, "old-start", "/usr/bin/chrome")
    current = ProcessFingerprint(123, "new-start", "/usr/bin/unrelated")
    RecoveryJournal.capture(
        session_id=manifest.session_id,
        tracing=TracingSnapshot(False, ""),
        processes=[_record()],
        fingerprint=lambda pid: recorded,
        now=NOW,
    ).persist(store)
    terminated = []
    report = RecoveryManager(
        store,
        restore_tracing=lambda snapshot: None,
        fingerprint=lambda pid: current,
        terminate=terminated.append,
    ).recover()
    assert report.skipped_pids == (123,)
    assert terminated == []
    assert store.get(manifest.session_id).state is JobState.INTERRUPTED


def test_nonterminal_session_without_journal_is_marked_interrupted(tmp_path):
    store, manifest = _capturing_store(tmp_path)
    restored = []
    report = RecoveryManager(store, restore_tracing=restored.append).recover()
    assert report.recovered_sessions == (manifest.session_id,)
    assert restored == []
    assert store.get(manifest.session_id).state is JobState.INTERRUPTED


def test_corrupt_journal_causes_no_process_or_tracing_side_effects(tmp_path):
    store, manifest = _capturing_store(tmp_path)
    (Path(manifest.session_dir) / "recovery.json").write_text("{bad-json", encoding="utf-8")
    restored = []
    terminated = []
    report = RecoveryManager(
        store,
        restore_tracing=restored.append,
        fingerprint=lambda pid: ProcessFingerprint(pid, "x", "/bin/x"),
        terminate=terminated.append,
    ).recover()
    assert report.recovered_sessions == ()
    assert len(report.errors) == 1
    assert restored == []
    assert terminated == []
    assert store.get(manifest.session_id).state is JobState.CAPTURING


def test_termination_error_keeps_journal_for_safe_retry(tmp_path):
    store, manifest = _capturing_store(tmp_path)
    fingerprint = ProcessFingerprint(123, "start-1", "/usr/bin/chrome")
    RecoveryJournal.capture(
        session_id=manifest.session_id,
        tracing=TracingSnapshot(False, ""),
        processes=[_record()],
        fingerprint=lambda pid: fingerprint,
        now=NOW,
    ).persist(store)

    def deny_termination(pid):
        raise PermissionError("not permitted")

    report = RecoveryManager(
        store,
        restore_tracing=lambda snapshot: None,
        fingerprint=lambda pid: fingerprint,
        terminate=deny_termination,
    ).recover()
    assert report.recovered_sessions == ()
    assert "not permitted" in report.errors[0]
    assert store.get(manifest.session_id).state is JobState.CAPTURING
    assert (Path(manifest.session_dir) / "recovery.json").exists()


def test_linux_process_fingerprint_identifies_current_process():
    fingerprint = linux_process_fingerprint(os.getpid())
    assert fingerprint is not None
    assert fingerprint.pid == os.getpid()
    assert fingerprint.start_token.isdigit()
    assert Path(fingerprint.executable).is_absolute()
