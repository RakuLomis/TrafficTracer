"""Tests for the Complete Worker JSONL envelope."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contracts" / "worker-api.schema.json"
FIXTURE_ROOT = ROOT / "test" / "fixtures" / "contracts"


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _errors(payload: dict):
    return list(Draft202012Validator(_load(SCHEMA_PATH)).iter_errors(payload))


def test_worker_schema_is_valid_draft_2020_12():
    Draft202012Validator.check_schema(_load(SCHEMA_PATH))


def test_every_worker_envelope_has_a_valid_fixture():
    for name in (
        "worker-request-valid.json",
        "worker-response-valid.json",
        "worker-error-valid.json",
        "worker-notification-valid.json",
    ):
        assert not _errors(_load(FIXTURE_ROOT / name)), name


def test_request_requires_non_null_id():
    payload = _load(FIXTURE_ROOT / "worker-request-valid.json")
    payload["id"] = None
    assert _errors(payload)


def test_response_result_and_error_are_mutually_exclusive():
    payload = _load(FIXTURE_ROOT / "worker-response-valid.json")
    payload["error"] = {"code": "INTERNAL_ERROR", "message": "boom"}
    assert _errors(payload)

    payload = _load(FIXTURE_ROOT / "worker-error-valid.json")
    payload["result"] = None
    assert _errors(payload)


def test_protocol_version_is_required_and_fixed():
    payload = _load(FIXTURE_ROOT / "worker-request-valid.json")
    payload["api_version"] = 1
    assert _errors(payload)

    del payload["api_version"]
    assert _errors(payload)


def test_notifications_cannot_carry_request_ids():
    payload = _load(FIXTURE_ROOT / "worker-notification-valid.json")
    payload["id"] = "unexpected"
    assert _errors(payload)
