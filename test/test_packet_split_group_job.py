import json
from pathlib import Path
from types import SimpleNamespace

from traffictracer.analyze.packet_split_status import (
    PacketSplitInspection,
    PacketSplitStatus,
)
from traffictracer.jobs.cancellation import CancellationToken
from traffictracer.jobs.models import CaptureJobResult, JobState
from traffictracer.jobs.packet_split import (
    PacketSplitGroupSpec,
    PacketSplitPolicy,
    SerialPacketSplitJob,
)
from traffictracer.jobs.progress import ProgressReporter


SCOPE = "20260814-080000-000"
SESSION_ID = "5027aee9-c6e4-41de-8625-7ea0869a3307"


def test_group_job_is_serial_and_completed_sessions_are_idempotently_skipped(
    tmp_path, monkeypatch
):
    scope_dir = tmp_path / SCOPE
    session_dir = scope_dir / "example.com/main-page__example"
    session_dir.mkdir(parents=True)
    manifest = SimpleNamespace(
        session_id=SESSION_ID,
        session_dir=str(session_dir),
        target=SimpleNamespace(url="https://example.com/"),
    )
    state = {"complete": False, "active": 0, "max_active": 0, "calls": 0}

    class Store:
        output_root = tmp_path

        def resolve_scope_id(self, scope_id):
            assert scope_id == SCOPE
            return SimpleNamespace(
                kind="capture_group", exists=True, directory=str(scope_dir)
            )

        def scan_scope(self, scope_id):
            return SimpleNamespace(corrupt=(), sessions=(manifest,))

        def get(self, session_id):
            assert session_id == SESSION_ID
            return manifest

    def inspect(_manifest):
        return PacketSplitInspection(
            PacketSplitStatus.COMPLETE if state["complete"] else PacketSplitStatus.UNSPLIT,
            "test evidence",
            1 if state["complete"] else 0,
        )

    monkeypatch.setattr("traffictracer.jobs.packet_split.inspect_packet_split", inspect)

    class Analysis:
        def __init__(self, spec):
            self.spec = spec

        def run(self):
            state["active"] += 1
            state["max_active"] = max(state["max_active"], state["active"])
            state["calls"] += 1
            state["complete"] = True
            state["active"] -= 1
            return CaptureJobResult(
                self.spec.job_id,
                JobState.COMPLETED,
                session_id=SESSION_ID,
            )

    def factory(spec, progress, cancellation):
        return Analysis(spec)

    def run(job_id):
        spec = PacketSplitGroupSpec(
            job_id=job_id,
            scope_id=SCOPE,
            output_root=str(tmp_path),
            policy=PacketSplitPolicy.MISSING_ONLY,
        )
        return SerialPacketSplitJob(
            spec,
            store=Store(),
            analysis_factory=factory,
            progress=ProgressReporter(job_id, lambda event: None, min_interval=0),
            cancellation=CancellationToken(),
        ).run()

    first = run("3edb7429-5718-48b4-93dc-1b3687b51d66")
    second = run("b57df540-05fa-4b44-a100-f26ad002dbfb")

    assert first.completed_sessions == 1
    assert second.completed_sessions == 0
    assert second.skipped_sessions == 1
    assert state == {"complete": True, "active": 0, "max_active": 1, "calls": 1}
    persisted = json.loads(
        (scope_dir / "packet-split-manifest.json").read_text(encoding="utf-8")
    )
    assert persisted["job_id"] == second.job_id
    assert persisted["sessions"][0]["state"] == "skipped"
