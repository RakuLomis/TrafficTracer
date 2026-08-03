"""Lifecycle tests for the job-scoped single-domain capture."""

import json
from pathlib import Path

import pytest

from traffictracer.capture.job import CaptureJob, CaptureRuntime, CaptureSessionContext
from traffictracer.jobs.cancellation import CancellationToken, CancelledError
from traffictracer.jobs.models import (
    CaptureInterfaces,
    CaptureJobOptions,
    CaptureJobSpec,
    ControllerSpec,
    JobState,
)
from traffictracer.jobs.process_registry import ProcessRegistry
from traffictracer.jobs.progress import ProgressReporter
from traffictracer.session.recovery import RECOVERY_JOURNAL_NAME, RecoveryJournal


class FakeProcess:
    next_pid = 100

    def __init__(self, role, events):
        FakeProcess.next_pid += 1
        self.pid = FakeProcess.next_pid
        self.role = role
        self.events = events
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.events.append(f"terminate:{self.role}")
        self.returncode = -15

    def kill(self):
        self.events.append(f"kill:{self.role}")
        self.returncode = -9

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


class FakeMihomo:
    def __init__(self, events):
        self.events = events

    def get_tracing_status(self):
        self.events.append("tracing:get")
        return {"enabled": False, "output": ""}

    def enable_tracing(self, path, session_id=""):
        self.events.append("tracing:enable")

    def get_proxy_info(self):
        self.events.append("proxy:info")
        return []

    def restore_tracing(self, state):
        self.events.append("tracing:restore")


class FakeRecoveryStore:
    def __init__(self, root):
        self.root = root

    def artifact_path(self, session_id, relative_path):
        assert session_id == "session-1"
        return self.root / relative_path


def _spec(tmp_path):
    return CaptureJobSpec(
        job_id="2f746e31-d62a-4e1c-a919-3f88ecde31c2",
        url="https://example.com/",
        domain="example.com",
        duration_seconds=1,
        network="all",
        interfaces=CaptureInterfaces("Meta", "eth0"),
        output_root=str(tmp_path),
        chrome_binary="/usr/bin/chromium",
        controller=ControllerSpec("unix:///tmp/mihomo.sock"),
        options=CaptureJobOptions(collect_cdp=False, analyze_after_capture=False),
    )


def _job(tmp_path, monkeypatch, events, *, cancellation=None, recovery_store=None):
    import traffictracer.capture.job as module

    def start(interface, path):
        role = "tun" if interface == "Meta" else "physical"
        events.append(f"start:{role}")
        return type("Capture", (), {"process": FakeProcess(role, events)})()

    def stop(capture):
        process = capture.process
        events.append(f"stop:{process.role}")
        process.returncode = 0

    def launch(**kwargs):
        events.append("launch:chrome")
        return FakeProcess("chrome", events)

    def terminate(process, **kwargs):
        events.append("stop:chrome")
        process.returncode = 0

    monkeypatch.setattr(module, "start_packet_capture", start)
    monkeypatch.setattr(module, "stop_packet_capture", stop)
    monkeypatch.setattr(module, "launch_chrome", launch)
    monkeypatch.setattr(module, "terminate_chrome", terminate)
    monkeypatch.setattr(module, "repair_truncated_netlog", lambda path: events.append("repair:netlog"))
    token = cancellation or CancellationToken()
    monkeypatch.setattr(
        token,
        "wait",
        lambda seconds: events.append("wait") or token.cancelled,
    )
    registry = ProcessRegistry()
    progress_events = []
    job = CaptureJob(
        _spec(tmp_path),
        runtime=CaptureRuntime("/tmp/profile", enable_cdp=False, run_label="visit"),
        mihomo=FakeMihomo(events),
        session=CaptureSessionContext("session-1", tmp_path, recovery_store),
        registry=registry,
        progress=ProgressReporter("job-1", progress_events.append, min_interval=0),
        cancellation=token,
    )
    return job, registry, progress_events


def test_capture_job_owns_lifecycle_and_cleans_up_in_order(tmp_path, monkeypatch):
    events = []
    job, registry, progress = _job(tmp_path, monkeypatch, events)
    result = job.run()
    assert result.state is JobState.COMPLETED
    assert registry.closed
    assert events == [
        "tracing:get",
        "tracing:enable",
        "proxy:info",
        "start:tun",
        "start:physical",
        "launch:chrome",
        "wait",
        "stop:chrome",
        "repair:netlog",
        "stop:physical",
        "stop:tun",
        "tracing:restore",
    ]
    assert [event.stage for event in progress] == [
        "preparing",
        "core.configure",
        "capture.packets",
        "capture.browser",
        "cleanup",
        "finished",
    ]
    assert (tmp_path / "captures" / "example.com" / "visit_1").is_dir()
    context_path = next((tmp_path / "logs").glob("capture_context_*.json"))
    context = json.loads(context_path.read_text(encoding="utf-8"))
    assert context["interfaces"] == {"tun": "Meta", "physical": "eth0"}
    assert str(context_path.relative_to(tmp_path)) in result.artifacts


def test_tracing_state_is_journaled_before_patch_and_cleared_after_restore(
    tmp_path, monkeypatch
):
    events = []
    store = FakeRecoveryStore(tmp_path)
    job, registry, progress = _job(
        tmp_path, monkeypatch, events, recovery_store=store
    )
    previous = {
        "enabled": True,
        "output": "/tmp/previous.jsonl",
        "session_id": "previous-session",
    }

    class InspectingMihomo(FakeMihomo):
        def get_tracing_status(self):
            self.events.append("tracing:get")
            return previous

        def enable_tracing(self, path, session_id=""):
            journal = RecoveryJournal.load(tmp_path / RECOVERY_JOURNAL_NAME)
            assert journal.tracing.enabled is True
            assert journal.tracing.output == "/tmp/previous.jsonl"
            assert journal.tracing.session_id == "previous-session"
            assert session_id == "session-1"
            self.events.append("tracing:enable")

        def restore_tracing(self, state):
            assert state == previous
            self.events.append("tracing:restore")

    job.mihomo = InspectingMihomo(events)
    job.run()
    assert not (tmp_path / RECOVERY_JOURNAL_NAME).exists()
    assert events.index("tracing:get") < events.index("tracing:enable")
    assert events[-1] == "tracing:restore"
    assert registry.closed
    assert progress[-1].state is JobState.COMPLETED


def test_capture_failure_still_stops_started_processes_and_restores_tracing(tmp_path, monkeypatch):
    events = []
    job, registry, progress = _job(tmp_path, monkeypatch, events)

    import traffictracer.capture.job as module
    monkeypatch.setattr(module, "launch_chrome", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("launch failed")))
    with pytest.raises(RuntimeError, match="launch failed"):
        job.run()
    assert registry.closed
    assert events[-3:] == ["stop:physical", "stop:tun", "tracing:restore"]
    assert progress[-1].state is JobState.FAILED


def test_capture_failure_restores_tracing_and_clears_recovery_journal(
    tmp_path, monkeypatch
):
    events = []
    store = FakeRecoveryStore(tmp_path)
    job, registry, progress = _job(
        tmp_path, monkeypatch, events, recovery_store=store
    )
    import traffictracer.capture.job as module

    monkeypatch.setattr(
        module,
        "launch_chrome",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("launch failed")),
    )
    with pytest.raises(RuntimeError, match="launch failed"):
        job.run()
    assert not (tmp_path / RECOVERY_JOURNAL_NAME).exists()
    assert events[-1] == "tracing:restore"
    assert registry.closed
    assert progress[-1].state is JobState.FAILED


def test_pre_cancelled_job_has_no_process_or_controller_side_effects(tmp_path, monkeypatch):
    events = []
    token = CancellationToken()
    token.cancel("user cancelled")
    job, registry, progress = _job(tmp_path, monkeypatch, events, cancellation=token)
    with pytest.raises(CancelledError, match="user cancelled"):
        job.run()
    assert events == []
    assert registry.closed
    assert progress[-1].state is JobState.CANCELLED


def test_capture_library_has_no_module_level_signal_or_process_registry():
    import traffictracer.capture.pipeline as pipeline
    assert not hasattr(pipeline, "signal")
    assert not hasattr(pipeline, "_active_procs")


def test_packet_capture_stop_error_does_not_skip_restore(tmp_path, monkeypatch):
    from traffictracer.capture.tshark import PacketCaptureError
    import traffictracer.capture.job as module

    events = []
    job, registry, progress = _job(tmp_path, monkeypatch, events)

    def fail_tun_stop(capture):
        process = capture.process
        events.append(f"stop:{process.role}")
        process.returncode = 1
        if process.role == "tun":
            raise PacketCaptureError(
                "CAPTURE_PERMISSION_DENIED", "permission denied", interface="Meta"
            )

    monkeypatch.setattr(module, "stop_packet_capture", fail_tun_stop)
    with pytest.raises(PacketCaptureError) as caught:
        job.run()
    assert caught.value.code == "CAPTURE_PERMISSION_DENIED"
    assert events[-3:] == ["stop:physical", "stop:tun", "tracing:restore"]
    assert registry.closed
    assert progress[-1].state is JobState.FAILED


def test_cdp_cancellation_closes_browser_before_terminating_process(tmp_path, monkeypatch):
    from dataclasses import replace
    import time
    import traffictracer.capture.job as module

    events = []
    token = CancellationToken()
    job, registry, progress = _job(
        tmp_path,
        monkeypatch,
        events,
        cancellation=token,
        recovery_store=FakeRecoveryStore(tmp_path),
    )
    job.spec = replace(
        job.spec,
        options=replace(job.spec.options, collect_cdp=True),
    )
    job.runtime = replace(job.runtime, enable_cdp=True)

    class CancellingCollector:
        def __init__(self, debugging_port, cancellation):
            self.token = cancellation

        def connect(self):
            events.append("cdp:connect")

        def setup(self):
            events.append("cdp:setup")

        def navigate(self, url, load_timeout):
            events.append("cdp:navigate")

        def collect(self, seconds):
            events.append("cdp:collect")
            self.token.cancel("cancel during CDP")
            self.token.checkpoint()

        def close_browser(self):
            events.append("cdp:Browser.close")

        def close(self):
            events.append("cdp:close")

    monkeypatch.setattr(module, "SyncCDPCollector", CancellingCollector)
    started = time.monotonic()
    with pytest.raises(CancelledError, match="cancel during CDP"):
        job.run()
    assert time.monotonic() - started < 2.0
    assert events.index("cdp:Browser.close") < events.index("stop:chrome")
    assert events[-1] == "tracing:restore"
    assert not (tmp_path / RECOVERY_JOURNAL_NAME).exists()
    assert registry.closed
    assert progress[-1].state is JobState.CANCELLED


def test_restore_failure_keeps_journal_for_worker_recovery(tmp_path, monkeypatch):
    events = []
    job, registry, progress = _job(
        tmp_path,
        monkeypatch,
        events,
        recovery_store=FakeRecoveryStore(tmp_path),
    )

    class RestoreFails(FakeMihomo):
        def restore_tracing(self, state):
            self.events.append("tracing:restore-failed")
            raise RuntimeError("controller unavailable")

    job.mihomo = RestoreFails(events)
    with pytest.raises(RuntimeError, match="controller unavailable"):
        job.run()
    journal = RecoveryJournal.load(tmp_path / RECOVERY_JOURNAL_NAME)
    assert journal.tracing.enabled is False
    assert journal.tracing.output == ""
    assert registry.closed
    assert progress[-1].state is JobState.FAILED
