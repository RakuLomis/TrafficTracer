"""Tests for the shared Complete contract validation layer."""

import json
from pathlib import Path

import pytest

from traffictracer.contracts import (
    UnknownContractError,
    ValidationError,
    available_contracts,
    get_validator,
    load_schema,
    validate_contract,
    validate_flow,
    validate_job,
    validate_session,
    validate_worker_message,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "test" / "fixtures" / "contracts"


def _fixture(name: str) -> dict:
    with (FIXTURE_ROOT / name).open(encoding="utf-8") as stream:
        return json.load(stream)


@pytest.mark.parametrize(
    ("contract", "fixture"),
    [
        ("job", "job-valid.json"),
        ("job", "job-valid-analysis.json"),
        ("worker_api", "worker-request-valid.json"),
        ("worker_api", "worker-response-valid.json"),
        ("worker_api", "worker-error-valid.json"),
        ("worker_api", "worker-notification-valid.json"),
        ("session", "session-valid.json"),
        ("flow", "flow-valid.json"),
        ("flow", "flow-valid-unmatched-ipv6.json"),
    ],
)
def test_all_golden_fixtures_use_the_shared_validator(contract, fixture):
    payload = _fixture(fixture)
    assert validate_contract(contract, payload) is payload


@pytest.mark.parametrize(
    "fixture",
    [
        "job-invalid-relative-output.json",
        "job-invalid-network.json",
        "job-invalid-duration.json",
    ],
)
def test_all_invalid_job_fixtures_are_rejected(fixture):
    with pytest.raises(ValidationError):
        validate_job(_fixture(fixture))


def test_boundary_helpers_share_the_same_validation_path():
    assert validate_job(_fixture("job-valid.json"))["kind"] == "capture"
    assert validate_worker_message(_fixture("worker-request-valid.json"))["type"] == "request"
    assert validate_session(_fixture("session-valid.json"))["state"] == "completed"
    assert validate_flow(_fixture("flow-valid.json"))["match"]["status"] == "matched"


def test_validation_error_is_stable_structured_and_value_safe():
    payload = _fixture("job-valid-analysis.json")
    payload["output_root"] = "sensitive-relative-output"

    with pytest.raises(ValidationError) as caught:
        validate_job(payload)

    error = caught.value
    assert error.code == "CONTRACT_VALIDATION_FAILED"
    assert error.contract == "job"
    assert error.path == ("output_root",)
    assert error.pointer == "/output_root"
    assert error.rule == "pattern"
    assert "sensitive-relative-output" not in str(error)
    assert error.as_dict() == {
        "code": "CONTRACT_VALIDATION_FAILED",
        "contract": "job",
        "path": ["output_root"],
        "rule": "pattern",
        "message": "value does not match the required pattern",
    }


def test_validation_error_never_echoes_secret_values():
    payload = _fixture("job-valid.json")
    payload["controller"]["secret"] = {"do-not-echo": "token-value"}
    with pytest.raises(ValidationError) as caught:
        validate_job(payload)
    assert "token-value" not in str(caught.value)
    assert caught.value.path == ("controller", "secret")


def test_validators_are_cached_but_loaded_schemas_are_defensive_copies():
    assert get_validator("worker-api") is get_validator("worker_api")
    first = load_schema("job")
    first["title"] = "mutated by caller"
    assert load_schema("job")["title"] != "mutated by caller"


def test_unknown_contract_has_a_deterministic_error():
    assert available_contracts() == (
        "flow",
        "job",
        "session",
        "target_config",
        "worker_api",
    )
    with pytest.raises(UnknownContractError, match="unknown contract 'missing'"):
        validate_contract("missing", {})
