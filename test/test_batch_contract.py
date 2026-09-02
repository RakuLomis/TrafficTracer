"""JSON Schema gates for TT-044 batch specifications and manifests."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from traffictracer.jobs.batch_models import BatchManifest


ROOT = Path(__file__).resolve().parents[1]


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def test_batch_schemas_and_fixtures_are_valid():
    job = _load(ROOT / "contracts" / "job.schema.json")
    manifest = _load(ROOT / "contracts" / "batch-manifest.schema.json")
    Draft202012Validator.check_schema(job)
    Draft202012Validator.check_schema(manifest)
    Draft202012Validator(job).validate(
        _load(ROOT / "test" / "fixtures" / "contracts" / "job-valid-batch.json")
    )
    Draft202012Validator(manifest).validate(
        BatchManifest.from_dict(
            _load(
                ROOT
                / "test"
                / "fixtures"
                / "contracts"
                / "batch-manifest-v1-valid.json"
            )
        ).to_dict()
    )


def test_batch_job_schema_rejects_empty_and_exact_duplicate_targets():
    schema = _load(ROOT / "contracts" / "job.schema.json")
    validator = Draft202012Validator(schema)
    payload = _load(ROOT / "test" / "fixtures" / "contracts" / "job-valid-batch.json")
    payload["targets"] = []
    assert list(validator.iter_errors(payload))
    payload["targets"] = [
        _load(ROOT / "test" / "fixtures" / "contracts" / "job-valid-batch.json")["targets"][0]
    ] * 2
    assert list(validator.iter_errors(payload))
