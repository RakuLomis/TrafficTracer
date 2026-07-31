"""Tests for the versioned Complete job contract."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contracts" / "job.schema.json"
FIXTURE_ROOT = ROOT / "test" / "fixtures" / "contracts"


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def test_job_schema_is_valid_draft_2020_12():
    Draft202012Validator.check_schema(_load(SCHEMA_PATH))


def test_valid_capture_and_analysis_jobs_match_schema():
    validator = Draft202012Validator(_load(SCHEMA_PATH))
    for name in ("job-valid.json", "job-valid-analysis.json"):
        validator.validate(_load(FIXTURE_ROOT / name))


def test_invalid_job_fixtures_are_rejected():
    validator = Draft202012Validator(_load(SCHEMA_PATH))
    for name in (
        "job-invalid-relative-output.json",
        "job-invalid-network.json",
        "job-invalid-duration.json",
    ):
        errors = list(validator.iter_errors(_load(FIXTURE_ROOT / name)))
        assert errors, f"{name} unexpectedly matched the job schema"


def test_capture_job_rejects_unknown_fields():
    payload = _load(FIXTURE_ROOT / "job-valid.json")
    payload["subscription"] = "https://secret.example/subscription"
    errors = list(Draft202012Validator(_load(SCHEMA_PATH)).iter_errors(payload))
    assert errors
