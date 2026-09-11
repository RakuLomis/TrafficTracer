"""TT-045 tests for strictly serial batch execution."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from traffictracer.capture.quiescence import (
    ChromeCleanupIncomplete,
    ChromeQuiescenceReport,
)
from traffictracer.jobs.batch import SerialBatchJob
from traffictracer.jobs.batch_models import (
    ApplicationRetryPolicy,
    BatchChildState,
    BatchJobSpec,
    BatchManifest,
    BatchState,
    BatchTarget,
)
from traffictracer.playback import PlaybackPolicy
from traffictracer.jobs.cancellation import CancellationToken
from traffictracer.jobs.models import CaptureJobResult, JobState
from traffictracer.jobs.progress import JobStage, ProgressReporter


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "test" / "fixtures" / "contracts" / "job-valid-batch.json"


def _spec(tmp_path, count=3, fail_fast=True):
    config = tmp_path / "targets.yaml"
    config.write_text("sites:\n  - fixture: true\n", encoding="utf-8")
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["config_path"] = str(config)
    payload["config_sha256"] = hashlib.sha256(config.read_bytes()).hexdigest()
    payload["output_root"] = str(tmp_path / "sessions")
    payload["fail_fast"] = fail_fast
    base = payload["targets"][0]
    payload["targets"] = [
        {
            **base,
            "index": position * 2 + 1,
            "url": f"https://target-{position}.example.test/",
            "domain": f"target-{position}.example.test",
            "run_label": f"target-{position}",
        }
        for position in range(count)
    ]
    return BatchJobSpec.from_dict(payload)


class _Runnable:
    def __init__(self, action):
        self.action = action

    def run(self):
        return self.action()


def _execute(spec, factory, token=None, outcome_resolver=None):
    events = []
    reporter = ProgressReporter(spec.job_id, events.append, min_interval=0)
    job = SerialBatchJob(
        spec,
        child_factory=factory,
        progress=reporter,
        cancellation=token or CancellationToken(),
        application_outcome_for_session=outcome_resolver,
    )
    result = job.run()
    return job, result, events


def _playback_spec(tmp_path, *, retry_enabled=True):
    spec = _spec(tmp_path, count=1)
    target = replace(
        spec.targets[0],
        playback=PlaybackPolicy(
            provider="youtube",
            ad_policy="click_visible_skip",
            desired_primary_seconds=5,
        ),
    )
    return replace(
        spec,
        targets=(target,),
        application_retry=ApplicationRetryPolicy(
            enabled=retry_enabled,
            max_retries=1,
        ),
    )


def test_three_targets_run_strictly_in_order_with_max_concurrency_one(tmp_path):
    spec = _spec(tmp_path)
    order = []
    active = [0]
    maximum = [0]

    def factory(child, progress, token):
        position = len(order)
        if position:
            checkpoint = BatchManifest.load(
                Path(spec.output_root) / ".batches" / spec.job_id / "batch-manifest.json"
            )
            assert checkpoint.children[position - 1].state is BatchChildState.COMPLETED
        order.append(child.target_source.target_index)

        def run():
            active[0] += 1
            maximum[0] = max(maximum[0], active[0])
            try:
                progress.emit(JobState.CAPTURING, JobStage.CAPTURE_BROWSER, 0.4)
                progress.emit(JobState.CAPTURING, JobStage.CLEANUP, 0.8)
                progress.emit(JobState.ANALYZING, JobStage.ANALYZE_WRITE, 0.95)
                progress.finish(JobState.COMPLETED)
                return CaptureJobResult(
                    child.job_id,
                    JobState.COMPLETED,
                    session_id=str(
                        [
                            "5027aee9-c6e4-41de-8625-7ea0869a3307",
                            "78fdab68-4e5d-4b67-9910-33da00a2632a",
                            "9af6d146-8594-41f4-bb3b-7bd60a7b118a",
                        ][position]
                    ),
                )
            finally:
                active[0] -= 1

        return _Runnable(run)

    job, result, events = _execute(spec, factory)
    assert order == [1, 3, 5]
    assert maximum == [1]
    assert result.state is JobState.COMPLETED
    assert result.completed_targets == 3
    assert [event.progress for event in events] == sorted(
        event.progress for event in events
    )
    assert BatchManifest.load(job.manifest_path).state is BatchState.COMPLETED


def test_retryable_application_failure_gets_one_fresh_preserved_attempt(tmp_path):
    spec = _playback_spec(tmp_path)
    session_ids = [
        "5027aee9-c6e4-41de-8625-7ea0869a3307",
        "78fdab68-4e5d-4b67-9910-33da00a2632a",
    ]
    job_ids = []

    def factory(child, progress, token):
        position = len(job_ids)
        job_ids.append(child.job_id)
        return _Runnable(lambda: CaptureJobResult(
            child.job_id,
            JobState.COMPLETED,
            session_id=session_ids[position],
        ))

    outcomes = {
        session_ids[0]: {
            "state": "failed",
            "reason": "MEDIA_NOT_ADVANCING",
        },
        session_ids[1]: {
            "state": "passed",
            "reason": None,
        },
    }
    job, result, _ = _execute(
        spec,
        factory,
        outcome_resolver=outcomes.get,
    )

    manifest = BatchManifest.load(job.manifest_path)
    child = manifest.children[0]
    assert result.state is JobState.COMPLETED
    assert len(job_ids) == 2
    assert len(set(job_ids)) == 2
    assert result.session_ids == tuple(session_ids)
    assert child.session_id == session_ids[1]
    assert [attempt.session_id for attempt in child.attempts] == session_ids
    assert child.attempts[0].application_outcome.reason == "MEDIA_NOT_ADVANCING"
    assert child.attempts[1].automatic_retry is True
    assert child.attempts[1].application_outcome.state == "passed"


@pytest.mark.parametrize("code", ["BROWSER_PROCESS_EXITED", "CDP_CONNECTION_LOST"])
def test_classified_browser_failure_gets_one_fresh_attempt(tmp_path, code):
    base = _spec(tmp_path, count=1)
    spec = replace(
        base,
        application_retry=ApplicationRetryPolicy(enabled=True, max_retries=1),
    )
    calls = []

    class BrowserFailure(RuntimeError):
        pass

    def factory(child, progress, token):
        position = len(calls)
        calls.append(child.job_id)

        def run():
            if position == 0:
                error = BrowserFailure("browser vanished")
                error.code = code
                raise error
            return CaptureJobResult(child.job_id, JobState.COMPLETED)

        return _Runnable(run)

    job, result, _ = _execute(spec, factory)

    child = BatchManifest.load(job.manifest_path).children[0]
    assert result.state is JobState.COMPLETED
    assert len(calls) == 2
    assert child.attempts[0].state is BatchChildState.FAILED
    assert child.attempts[0].error.code == code
    assert child.attempts[1].state is BatchChildState.COMPLETED
    assert child.attempts[1].automatic_retry is True


@pytest.mark.parametrize(
    ("state", "reason"),
    [
        ("failed", "MAIN_DOCUMENT_NETWORK_ERROR"),
        ("degraded", "CRITICAL_RESOURCE_FAILURE_BURST"),
    ],
)
def test_generic_navigation_failure_gets_one_bounded_retry(
    tmp_path, state, reason
):
    base = _spec(tmp_path, count=1)
    spec = replace(
        base,
        application_retry=ApplicationRetryPolicy(enabled=True, max_retries=1),
    )
    session_ids = [
        "5027aee9-c6e4-41de-8625-7ea0869a3307",
        "78fdab68-4e5d-4b67-9910-33da00a2632a",
    ]
    calls = []

    def factory(child, progress, token):
        position = len(calls)
        calls.append(child.job_id)
        return _Runnable(lambda: CaptureJobResult(
            child.job_id,
            JobState.COMPLETED,
            session_id=session_ids[position],
        ))

    outcomes = {
        session_ids[0]: {
            "state": state,
            "reason": reason,
        },
        session_ids[1]: {
            "state": "passed",
            "reason": None,
        },
    }
    job, result, _ = _execute(
        spec,
        factory,
        outcome_resolver=outcomes.get,
    )

    child = BatchManifest.load(job.manifest_path).children[0]
    assert result.state is JobState.COMPLETED
    assert len(calls) == 2
    assert child.attempts[0].application_outcome.reason == reason
    assert child.attempts[1].automatic_retry is True



@pytest.mark.parametrize(
    ("retry_enabled", "state", "reason"),
    [
        (False, "failed", "MEDIA_NOT_ADVANCING"),
        (True, "degraded", "PRIMARY_DURATION_BELOW_TARGET"),
        (True, "failed", "UNCLASSIFIED_FAILURE"),
        (True, "failed", "MAIN_DOCUMENT_HTTP_ERROR"),
    ],
)
def test_application_retry_never_guesses_or_overrides_opt_in(
    tmp_path, retry_enabled, state, reason
):
    spec = _playback_spec(tmp_path, retry_enabled=retry_enabled)
    session_id = "5027aee9-c6e4-41de-8625-7ea0869a3307"
    calls = []

    def factory(child, progress, token):
        calls.append(child.job_id)
        return _Runnable(lambda: CaptureJobResult(
            child.job_id, JobState.COMPLETED, session_id=session_id
        ))

    job, result, _ = _execute(
        spec,
        factory,
        outcome_resolver=lambda value: {"state": state, "reason": reason},
    )
    manifest = BatchManifest.load(job.manifest_path)
    assert result.state is JobState.COMPLETED
    assert len(calls) == 1
    assert len(manifest.children[0].attempts) == 1


@pytest.mark.parametrize(
    ("stage", "exception", "expected_code"),
    [
        (JobStage.ANALYZE_WRITE, RuntimeError("analysis failed"), "BATCH_CHILD_FAILED"),
        (
            JobStage.CLEANUP,
            ChromeCleanupIncomplete(
                ChromeQuiescenceReport("/tmp/profile", True, (123,))
            ),
            "CHROME_CLEANUP_INCOMPLETE",
        ),
    ],
)
def test_second_child_failure_stops_before_third_and_checkpoints_error(
    tmp_path, stage, exception, expected_code
):
    spec = _spec(tmp_path)
    calls = []

    def factory(child, progress, token):
        position = len(calls)
        calls.append(position)

        def run():
            progress.emit(JobState.CAPTURING, stage, 0.5)
            if position == 1:
                raise exception
            return CaptureJobResult(child.job_id, JobState.COMPLETED)

        return _Runnable(run)

    job, result, _ = _execute(spec, factory)
    manifest = BatchManifest.load(job.manifest_path)
    assert calls == [0, 1]
    assert result.state is JobState.FAILED
    assert manifest.children[1].state is BatchChildState.FAILED
    assert manifest.children[1].error.code == expected_code
    assert manifest.children[2].state is BatchChildState.PENDING


def test_empty_child_exception_persists_non_empty_error(tmp_path):
    spec = _spec(tmp_path, count=1)

    def factory(child, progress, token):
        return _Runnable(
            lambda: (_ for _ in ()).throw(TimeoutError())
        )

    job, result, _ = _execute(spec, factory)
    manifest = BatchManifest.load(job.manifest_path)

    assert result.state is JobState.FAILED
    assert manifest.children[0].error is not None
    assert manifest.children[0].error.message == "TimeoutError"


def test_non_fail_fast_continues_serially_but_parent_finishes_failed(tmp_path):
    spec = _spec(tmp_path, fail_fast=False)
    calls = []

    def factory(child, progress, token):
        position = len(calls)
        calls.append(position)
        return _Runnable(
            lambda: (_ for _ in ()).throw(RuntimeError("second failed"))
            if position == 1
            else CaptureJobResult(child.job_id, JobState.COMPLETED)
        )

    job, result, _ = _execute(spec, factory)
    assert calls == [0, 1, 2]
    assert result.state is JobState.FAILED
    assert BatchManifest.load(job.manifest_path).state is BatchState.FAILED


def test_protocol_invariant_stops_non_fail_fast_batch(tmp_path):
    spec = _spec(tmp_path, fail_fast=False)
    calls = []

    class ProtocolMismatch(RuntimeError):
        code = "PROXY_PROTOCOL_INVARIANT_FAILED"

    def factory(child, progress, token):
        calls.append(child.target_source.target_index)
        return _Runnable(
            lambda: (_ for _ in ()).throw(ProtocolMismatch("mixed runtime protocols"))
        )

    job, result, _ = _execute(spec, factory)
    manifest = BatchManifest.load(job.manifest_path)
    assert len(calls) == 1
    assert result.state is JobState.FAILED
    assert manifest.state is BatchState.FAILED
    assert manifest.children[0].error.code == "PROXY_PROTOCOL_INVARIANT_FAILED"


def test_cancel_waits_for_current_child_checkpoint_and_never_starts_next(tmp_path):
    spec = _spec(tmp_path)
    token = CancellationToken()
    calls = []

    def factory(child, progress, child_token):
        calls.append(child.target_source.target_index)

        def run():
            token.cancel("stop batch")
            token.checkpoint()

        return _Runnable(run)

    events = []
    job = SerialBatchJob(
        spec,
        child_factory=factory,
        progress=ProgressReporter(spec.job_id, events.append, min_interval=0),
        cancellation=token,
    )
    with pytest.raises(Exception, match="stop batch"):
        job.run()
    manifest = BatchManifest.load(job.manifest_path)
    assert calls == [1]
    assert manifest.state is BatchState.CANCELLED
    assert manifest.children[0].state is BatchChildState.CANCELLED
    assert manifest.children[1].state is BatchChildState.PENDING
