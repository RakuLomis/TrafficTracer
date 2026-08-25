"""Lifecycle tests for the job-scoped single-domain capture."""

import json
from pathlib import Path

import pytest

from traffictracer.capture.job import CaptureJob, CaptureRuntime, CaptureSessionContext
from traffictracer.capture.quiescence import (
    ChromeCleanupIncomplete,
    ChromeQuiescenceReport,
)
from traffictracer.jobs.cancellation import (
    CancellationToken,
    CancelledError,
    InterruptedError,
)
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

    def trace_barrier(self):
        self.events.append("tracing:barrier")
        return {
            "session_id": "session-1",
            "event_seq": 42,
            "ts": "2026-08-12T00:00:00Z",
            "output": "/tmp/trace.jsonl",
        }

    def get_proxy_info(self):
        self.events.append("proxy:info")
        return []

    def get_proxy_protocol_snapshot(self):
        self.events.append("proxy:protocol")
        return {
            "mode": "strict_single",
            "status": "single",
            "protocols": ["hysteria2"],
            "expected_protocol": "hysteria2",
            "selections": [],
        }


    def restore_tracing(self, state):
        self.events.append("tracing:restore")


class FakeRecoveryStore:
    def __init__(self, root):
        self.root = root

    def artifact_path(self, session_id, relative_path):
        raise AssertionError("capture recovery must not perform a global Session lookup")

    def artifact_path_for_session(self, session_id, session_dir, relative_path):
        assert session_id == "session-1"
        assert session_dir == self.root
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
        "proxy:protocol",
        "start:tun",
        "start:physical",
        "launch:chrome",
        "wait",
        "stop:chrome",
        "repair:netlog",
        "stop:physical",
        "stop:tun",
        "tracing:barrier",
        "wait",
        "tracing:barrier",
        "tracing:restore",
    ]
    assert [event.stage for event in progress] == [
        "preparing",
        "core.configure",
        "core.configure",
        "core.configure",
        "capture.packets",
        "capture.packets",
        "capture.browser",
        "capture.browser",
        "cleanup",
        "finished",
    ]
    assert [event.timing["operation"] for event in progress] == [
        "capture.prepare_paths",
        "core.trace_status",
        "core.trace_enable",
        "core.protocol_snapshot",
        "capture.tshark_tun_start",
        "capture.tshark_physical_start",
        "capture.chrome_launch",
        "capture.observation",
        "capture.cleanup",
        "finished",
    ]
    assert (tmp_path / "captures" / "example.com" / "visit_1").is_dir()
    context_path = next((tmp_path / "logs").glob("capture_context_*.json"))
    context = json.loads(context_path.read_text(encoding="utf-8"))
    assert context["interfaces"] == {"tun": "Meta", "physical": "eth0"}
    assert context["inbound"] == {
        "mode": "tun",
        "interface": "Meta",
        "expected_core_name": "DEFAULT-TUN",
    }
    assert context["proxy_protocol"]["protocols"] == ["hysteria2"]
    assert context["proxy_protocol"]["runtime_observation"] == {
        "protocols": [], "proxy_dial_events": 0, "unknown_protocol_events": 0,
        "validation_source": "bounded_mihomo_trace",
        "consistency": "not_observed"}
    assert context["trace_boundary"]["source"] == "mihomo_barrier"
    assert context["trace_boundary"]["event_seq"] == 42
    assert context["trace_boundary_initial"]["event_seq"] == 42
    assert context["trace_boundary"]["settle_seconds"] == 0.5
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
    assert events[-6:] == [
        "stop:physical", "stop:tun", "tracing:barrier", "wait",
        "tracing:barrier", "tracing:restore",
    ]
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


def test_pre_interrupted_job_uses_cleanup_and_reports_interrupted(
    tmp_path, monkeypatch
):
    events = []
    token = CancellationToken()
    token.interrupt("pause batch")
    job, registry, progress = _job(
        tmp_path, monkeypatch, events, cancellation=token
    )
    with pytest.raises(InterruptedError, match="pause batch"):
        job.run()
    assert events == []
    assert registry.closed
    assert progress[-1].state is JobState.INTERRUPTED


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
    assert events[-6:] == [
        "stop:physical", "stop:tun", "tracing:barrier", "wait",
        "tracing:barrier", "tracing:restore",
    ]
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
        def __init__(self, debugging_port, cancellation, cache_mode="warm"):
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


def test_youtube_playback_uses_one_fixed_window_and_persists_quality(
    tmp_path, monkeypatch,
):
    from dataclasses import replace
    import traffictracer.capture.job as module
    from traffictracer.playback import PlaybackPolicy

    events = []
    job, registry, progress = _job(tmp_path, monkeypatch, events)
    job.spec = replace(
        job.spec,
        url="https://www.youtube.com/watch?v=example",
        domain="youtube.com",
        duration_seconds=35,
        playback=PlaybackPolicy(
            "youtube",
            "click_visible_skip",
            25,
        ),
        options=replace(job.spec.options, collect_cdp=True),
    )
    job.runtime = replace(job.runtime, enable_cdp=True)
    playback_result = {
        "schema_version": 1,
        "provider": "youtube",
        "ad_policy": "click_visible_skip",
        "observation_window_seconds": 35,
        "observed_total_seconds": 35,
        "desired_primary_seconds": 25,
        "primary_content_seconds": 25.2,
        "primary_goal_met": True,
        "quality": "good",
        "reason": None,
        "phase_seconds": {
            "preparation": 5,
            "advertisement": 4.8,
            "primary_content": 25.2,
            "other": 0,
        },
        "skip_attempts": 1,
        "automation_available": True,
        "evaluation_errors": 0,
        "end_reason": "observation_window_elapsed",
        "events": [],
    }

    class PlaybackCollector:
        def __init__(self, **kwargs):
            pass

        def connect(self):
            events.append("cdp:connect")

        def setup(self):
            events.append("cdp:setup")

        def navigate(self, url, load_timeout, *, wait_for_load=True):
            assert wait_for_load is False
            events.append("cdp:navigate-fixed")

        def collect_playback(self, seconds, policy, callback):
            assert seconds == 35
            assert policy.desired_primary_seconds == 25
            callback({
                "elapsed_seconds": 35,
                "phase": "primary_content",
                "primary_content_seconds": 25.2,
                "desired_primary_seconds": 25,
            })
            events.append("cdp:collect-playback")
            return playback_result

        def stop_collecting(self):
            events.append("cdp:stop")

        def get_structured_data(self):
            return {
                "requests": [],
                "metadata": {"playback": playback_result},
            }

        def close_browser(self):
            events.append("cdp:Browser.close")

        def close(self):
            events.append("cdp:close")

    monkeypatch.setattr(module, "SyncCDPCollector", PlaybackCollector)
    result = job.run()
    assert result.state is JobState.COMPLETED
    assert "cdp:collect-playback" in events
    context_path = next((tmp_path / "logs").glob("capture_context_*.json"))
    context = json.loads(context_path.read_text(encoding="utf-8"))
    assert context["playback_policy"]["desired_primary_seconds"] == 25
    assert context["playback"]["primary_goal_met"] is True
    assert registry.closed


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


def _cleanup_incomplete(profile):
    return ChromeCleanupIncomplete(
        ChromeQuiescenceReport(str(profile), True, (987,))
    )


def test_chrome_residual_fails_capture_and_keeps_recovery_journal(
    tmp_path, monkeypatch
):
    import traffictracer.capture.job as module

    events = []
    job, registry, progress = _job(
        tmp_path,
        monkeypatch,
        events,
        recovery_store=FakeRecoveryStore(tmp_path),
    )
    monkeypatch.setattr(
        module,
        "verify_chrome_quiescence",
        lambda process, profile, **kwargs: (_ for _ in ()).throw(
            _cleanup_incomplete(profile)
        ),
    )

    with pytest.raises(ChromeCleanupIncomplete) as raised:
        job.run()
    assert raised.value.code == "CHROME_CLEANUP_INCOMPLETE"
    assert (tmp_path / RECOVERY_JOURNAL_NAME).is_file()
    assert events[-1] == "tracing:restore"
    assert registry.closed
    assert progress[-1].state is JobState.FAILED


def test_cancelled_capture_with_chrome_residual_stays_cancelled_but_keeps_journal(
    tmp_path, monkeypatch
):
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

    def cancel_during_capture(seconds):
        token.cancel("cancel with residual")
        return True

    monkeypatch.setattr(token, "wait", cancel_during_capture)
    monkeypatch.setattr(
        module,
        "verify_chrome_quiescence",
        lambda process, profile, **kwargs: (_ for _ in ()).throw(
            _cleanup_incomplete(profile)
        ),
    )

    with pytest.raises(CancelledError, match="cancel with residual"):
        job.run()
    assert (tmp_path / RECOVERY_JOURNAL_NAME).is_file()
    assert events[-1] == "tracing:restore"
    assert registry.closed
    assert progress[-1].state is JobState.CANCELLED


def test_collector_close_failure_cannot_be_reported_as_capture_success(
    tmp_path, monkeypatch
):
    from dataclasses import replace
    import traffictracer.capture.job as module

    events = []
    job, registry, progress = _job(tmp_path, monkeypatch, events)
    job.spec = replace(
        job.spec,
        options=replace(job.spec.options, collect_cdp=True),
    )
    job.runtime = replace(job.runtime, enable_cdp=True)

    class CloseFailsCollector:
        def __init__(self, **kwargs):
            pass

        def connect(self):
            pass

        def setup(self):
            pass

        def navigate(self, url, load_timeout):
            pass

        def collect(self, seconds):
            pass

        def stop_collecting(self):
            pass

        def get_structured_data(self):
            return {"requests": []}

        def close_browser(self):
            pass

        def close(self):
            raise RuntimeError("collector close failed")

    monkeypatch.setattr(module, "SyncCDPCollector", CloseFailsCollector)

    with pytest.raises(RuntimeError, match="collector close failed"):
        job.run()
    assert registry.closed
    assert progress[-1].state is JobState.FAILED


def test_strict_capture_rejects_mixed_runtime_trace(tmp_path, monkeypatch):
    events = []
    job, registry, progress = _job(tmp_path, monkeypatch, events)
    from dataclasses import replace
    job.spec = replace(
        job.spec, options=replace(job.spec.options, proxy_protocol_mode="strict_single"),
    )
    import traffictracer.capture.job as module
    monkeypatch.setattr(
        module,
        "observed_proxy_protocols",
        lambda *args, **kwargs: {
            "protocols": ["hysteria2", "vless"],
            "proxy_dial_events": 2,
            "unknown_protocol_events": 0,
        },
    )

    with pytest.raises(RuntimeError, match="failed from Mihomo trace"):
        job.run()
    assert "start:tun" in events
    assert events[-1] == "tracing:restore"


def test_strict_capture_does_not_reject_mixed_inventory_before_trace(tmp_path, monkeypatch):
    events = []
    job, registry, progress = _job(
        tmp_path, monkeypatch, events,
    )
    from dataclasses import replace
    job.spec = replace(
        job.spec, options=replace(job.spec.options, proxy_protocol_mode="strict_single"),
    )
    class MixedProtocolMihomo(FakeMihomo):
        def get_proxy_protocol_snapshot(self):
            self.events.append("proxy:protocol")
            return {
                "mode": "strict_single",
                "status": "mixed",
                "protocols": ["hysteria2", "vless"],
                "expected_protocol": "",
                "selections": [],
            }
    job.mihomo = MixedProtocolMihomo(events)

    result = job.run()
    assert result.state is JobState.COMPLETED
    assert "start:tun" in events
    assert events[-1] == "tracing:restore"
