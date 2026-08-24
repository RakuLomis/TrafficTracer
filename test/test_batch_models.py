"""TT-044 contract and persistence tests for serial batch state."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from traffictracer.jobs.batch_models import (
    BatchChildState,
    BatchError,
    BatchJobSpec,
    BatchManifest,
    BatchStage,
    BatchState,
    BatchTarget,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "test" / "fixtures" / "contracts"


def _payload(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _spec():
    return BatchJobSpec.from_dict(_payload("job-valid-batch.json"))


def test_batch_job_and_manifest_fixtures_round_trip():
    job_payload = _payload("job-valid-batch.json")
    assert BatchJobSpec.from_dict(job_payload).to_dict() == job_payload
    manifest_payload = _payload("batch-manifest-v1-valid.json")
    assert BatchManifest.from_dict(manifest_payload).to_dict() == manifest_payload


def test_empty_and_semantically_duplicate_targets_are_rejected():
    spec = _spec()
    with pytest.raises(ValueError, match="must not be empty"):
        replace(spec, targets=())
    duplicate = replace(spec.targets[0], index=99)
    with pytest.raises(ValueError, match="duplicates"):
        replace(spec, targets=(spec.targets[0], duplicate))
    with pytest.raises(ValueError, match="indexes"):
        replace(spec, targets=(spec.targets[0], spec.targets[0]))


def test_config_sha_mismatch_is_detected_without_changing_snapshot(tmp_path):
    config = tmp_path / "targets.yaml"
    config.write_text("sites: []\n", encoding="utf-8")
    spec = replace(
        _spec(),
        config_path=str(config),
        config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(),
    )
    spec.verify_config_sha256()
    config.write_text("sites:\n  - changed: true\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no longer matches"):
        spec.verify_config_sha256()
    assert spec.targets == _spec().targets


def test_manifest_enforces_order_and_legal_transitions():
    created = BatchManifest.create(_spec())
    with pytest.raises(ValueError, match="no running child"):
        created.finish_child(BatchChildState.COMPLETED)
    running = created.begin()
    with pytest.raises(ValueError, match="snapshot order"):
        running.start_child(1)
    first = running.start_child(0).set_stage(BatchStage.QUIESCENCE)
    first = first.set_stage(BatchStage.ANALYSIS)
    checkpoint = first.finish_child(
        BatchChildState.COMPLETED,
        session_id="5027aee9-c6e4-41de-8625-7ea0869a3307",
    )
    assert checkpoint.resume.next_index == 1
    assert checkpoint.children[0].target_index == 1
    second = checkpoint.start_child(1)
    completed = second.finish_child(
        BatchChildState.COMPLETED,
        session_id="78fdab68-4e5d-4b67-9910-33da00a2632a",
    )
    assert completed.state is BatchState.COMPLETED
    assert completed.stage is BatchStage.FINISHED
    with pytest.raises(ValueError, match="cannot begin"):
        completed.begin()


def test_failed_batch_resume_retries_failed_snapshot_position():
    running = BatchManifest.create(_spec()).begin().start_child(0)
    failed = running.finish_child(
        BatchChildState.FAILED,
        error=BatchError("CAPTURE_FAILED", "fixture failure"),
    )
    assert failed.state is BatchState.FAILED
    assert failed.resume.next_index == 0
    resumed = failed.with_resume_policy(fail_fast=False).begin()
    assert resumed.resume.attempt == 1
    assert resumed.fail_fast is False
    assert resumed.children[0].state is BatchChildState.INTERRUPTED
    assert resumed.start_child(0).current_index == 0


def test_successful_reanalysis_reconciles_failed_child_without_recapture():
    session_id = "5027aee9-c6e4-41de-8625-7ea0869a3307"
    running = BatchManifest.create(_spec()).begin().start_child(0)
    failed = running.finish_child(
        BatchChildState.FAILED,
        session_id=session_id,
        error=BatchError("BATCH_CHILD_FAILED", "invalid generated index"),
    )

    reconciled = failed.reconcile_analyzed_session(
        session_id,
        analysis_error_code="ANALYSIS_FAILED",
    )

    assert reconciled.state is BatchState.INTERRUPTED
    assert reconciled.children[0].state is BatchChildState.COMPLETED
    assert reconciled.children[0].error is None
    assert reconciled.resume.next_index == 1


def test_analysis_reconciliation_rejects_non_analysis_failure():
    session_id = "5027aee9-c6e4-41de-8625-7ea0869a3307"
    running = BatchManifest.create(_spec()).begin().start_child(0)
    failed = running.finish_child(
        BatchChildState.FAILED,
        session_id=session_id,
        error=BatchError("BATCH_CHILD_FAILED", "capture failed"),
    )

    with pytest.raises(ValueError, match="retryable analysis failure"):
        failed.reconcile_analyzed_session(
            session_id,
            analysis_error_code="CAPTURE_FAILED",
        )


def test_manifest_persistence_recovers_without_ui_memory(tmp_path):
    manifest = BatchManifest.create(_spec()).begin().start_child(0)
    path = manifest.persist(tmp_path / "batch")
    assert path.name == "batch-manifest.json"
    assert BatchManifest.load(path) == manifest


def test_manifest_decoder_rejects_child_snapshot_drift():
    payload = _payload("batch-manifest-v1-valid.json")
    payload["children"][1]["target_index"] = 99
    with pytest.raises(ValueError, match="exactly match"):
        BatchManifest.from_dict(payload)
