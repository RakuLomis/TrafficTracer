"""Small read-only fixtures for quality selection and artifact auditing."""
import importlib.util
import json
from pathlib import Path

MODULE = Path(__file__).parents[1] / "scripts/review-pipeline-dataset.py"
spec = importlib.util.spec_from_file_location("dataset_review", MODULE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(tmp_path):
    runs = []
    for ordinal in (1, 3, 2):
        sid = f"session-{ordinal}"
        directory = tmp_path / "runs" / str(ordinal) / "timestamp" / "example.test" / "page"
        (directory / "analysis").mkdir(parents=True)
        (directory / "raw").mkdir()
        (directory / "raw/trace.jsonl").write_text("{}\n")
        (directory / "analysis/summary.json").write_text(json.dumps({"activity_outcome": {"state": "passed"}}))
        (directory / "manifest.json").write_text(json.dumps({
            "session_id": sid, "artifacts": [{"path": "raw/trace.jsonl", "size_bytes": 2}]}))
        runs.append({"candidate_ordinal": ordinal, "repetition_index": 1, "target_index": 0,
                     "state": "completed", "observed_protocol": str(ordinal), "session_ids": [sid],
                     "prior_session_ids": ["earlier-attempt"],
                     "quality": {k: {"state": "passed"} for k in ("capture_integrity", "correlation", "application")}})
    manifest = {"pipeline_id": "test", "state": "completed", "targets": [{"index": 0, "url": "https://example.test"}], "runs": runs}
    (tmp_path / "pipeline-manifest.json").write_text(json.dumps(manifest))
    return manifest


def test_review_separates_retry_history_quality_and_artifact_growth(tmp_path):
    fixture(tmp_path)
    before = {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    result = module.review(tmp_path)
    assert result["final_runs"] == 3
    assert result["all_planes_paired_blocks"] == 1
    assert len(result["artifact_discrepancies"]) == 3
    assert all(r["kind"] == "grew" for r in result["artifact_discrepancies"])
    assert before == {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}


def test_business_degradation_does_not_remove_transport_pair(tmp_path):
    manifest = fixture(tmp_path)
    manifest["runs"][1]["quality"]["application"]["state"] = "degraded"
    manifest["runs"][1]["state"] = "degraded"
    (tmp_path / "pipeline-manifest.json").write_text(json.dumps(manifest))
    result = module.review(tmp_path)
    assert result["all_planes_paired_blocks"] == 0
    assert result["capture_correlation_paired_blocks"] == 1


def test_duplicate_candidate_is_not_a_complete_pair(tmp_path):
    manifest = fixture(tmp_path)
    manifest["runs"].append(dict(manifest["runs"][0]))
    (tmp_path / "pipeline-manifest.json").write_text(json.dumps(manifest))
    result = module.review(tmp_path)
    assert result["all_planes_paired_blocks"] == 0
    assert result["capture_correlation_paired_blocks"] == 0


def test_invalid_recorded_size_is_reported_without_crashing(tmp_path):
    fixture(tmp_path)
    manifest = next(tmp_path.glob("runs/*/*/*/*/manifest.json"))
    content = json.loads(manifest.read_text())
    del content["artifacts"][0]["size_bytes"]
    manifest.write_text(json.dumps(content))
    result = module.review(tmp_path)
    assert sum(a["kind"] == "invalid_recorded_size"
               for a in result["artifact_discrepancies"]) == 1


def test_as_of_journal_growth_is_not_immutable_artifact_corruption(tmp_path):
    fixture(tmp_path)
    for manifest in tmp_path.glob("runs/*/*/*/*/manifest.json"):
        content = json.loads(manifest.read_text())
        content["artifacts"][0]["size_semantics"] = "as_of"
        manifest.write_text(json.dumps(content))
    assert module.review(tmp_path)["artifact_discrepancies"] == []
    journal = next(tmp_path.glob("runs/*/*/*/*/raw/trace.jsonl"))
    journal.write_bytes(b"x")
    assert module.review(tmp_path)["artifact_discrepancies"][0]["kind"] == "shrank"
