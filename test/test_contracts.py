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
    validate_flow_v2,
    validate_pcap_index,
    validate_job,
    validate_session,
    validate_session_v2,
    validate_worker_message,
)
from traffictracer.version import JOB_SCHEMA_VERSION


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
        ("session_v2", "session-v2-valid.json"),
        ("flow", "flow-valid.json"),
        ("flow_v2", "flow-v2-connection-shared-http2.json"),
        ("flow_v2", "flow-v2-connection-unmatched-ipv6-udp.json"),
        ("flow_v2", "flow-v2-request-repeated-url.json"),
        ("flow_v2", "flow-v2-request-ambiguous.json"),
        ("pcap_index", "pcap-index-v1-valid.json"),
        ("pipeline_manifest", "pipeline-manifest-v1-valid.json"),
        ("pipeline_manifest", "pipeline-manifest-v2-valid.json"),
        ("pipeline_manifest", "pipeline-manifest-v3-valid.json"),
        ("pipeline_manifest", "pipeline-manifest-v5-valid.json"),
        ("pipeline_manifest", "pipeline-manifest-v6-valid.json"),
        ("pipeline_manifest", "pipeline-manifest-v7-valid.json"),
        ("flow", "flow-valid-unmatched-ipv6.json"),
    ],
)
def test_all_golden_fixtures_use_the_shared_validator(contract, fixture):
    payload = _fixture(fixture)
    assert validate_contract(contract, payload) is payload


def test_pipeline_manifest_v7_requires_the_frozen_matrix_schedule():
    payload = _fixture("pipeline-manifest-v7-valid.json")
    del payload["schedule"]

    with pytest.raises(ValidationError) as caught:
        validate_contract("pipeline_manifest", payload)

    assert caught.value.path == ("schedule",)
    assert caught.value.rule == "required"


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
    assert validate_session_v2(_fixture("session-v2-valid.json"))["schema_version"] == 2
    assert validate_flow(_fixture("flow-valid.json"))["match"]["status"] == "matched"
    assert validate_flow_v2(_fixture("flow-v2-connection-shared-http2.json"))["record_type"] == "connection"
    assert validate_pcap_index(_fixture("pcap-index-v1-valid.json"))["split_mode"] == "unique_connections"


def test_flow_v2_allows_transport_network_reconciliation_method():
    payload = _fixture("flow-v2-connection-shared-http2.json")
    payload["match"]["method"] = "transport_network_reconciled"
    assert validate_flow_v2(payload) is payload


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


def test_job_error_uses_batch_kind_branch_for_invalid_optional_playback():
    payload = _fixture("job-valid-batch.json")
    payload["targets"][0]["playback"] = None

    with pytest.raises(ValidationError) as caught:
        validate_job(payload)

    assert caught.value.path == ("targets", 0, "playback")
    assert caught.value.rule == "type"


def test_job_error_uses_capture_kind_branch():
    payload = _fixture("job-valid.json")
    payload["url"] = "not-a-url"

    with pytest.raises(ValidationError) as caught:
        validate_job(payload)

    assert caught.value.path == ("url",)
    assert caught.value.rule == "pattern"


def test_job_error_uses_packet_split_kind_branch():
    payload = {
        "schema_version": JOB_SCHEMA_VERSION,
        "kind": "packet_split_group",
        "job_id": "123e4567-e89b-42d3-a456-426614174000",
        "scope_id": "20260814-120000-000",
        "output_root": "/tmp/sessions",
        "policy": "unsupported",
    }

    with pytest.raises(ValidationError) as caught:
        validate_job(payload)

    assert caught.value.path == ("policy",)
    assert caught.value.rule == "enum"


def test_unknown_job_kind_still_reports_the_discriminator():
    payload = _fixture("job-valid-batch.json")
    payload["kind"] = "unknown"

    with pytest.raises(ValidationError) as caught:
        validate_job(payload)

    assert caught.value.path == ("kind",)
    assert caught.value.rule == "const"


def test_validators_are_cached_but_loaded_schemas_are_defensive_copies():
    assert get_validator("worker-api") is get_validator("worker_api")
    first = load_schema("job")
    first["title"] = "mutated by caller"
    assert load_schema("job")["title"] != "mutated by caller"


def test_unknown_contract_has_a_deterministic_error():
    assert available_contracts() == (
        "batch_manifest",
        "flow",
        "flow_v2",
        "job",
        "packet_split_manifest",
        "pcap_index",
        "pipeline_manifest",
        "session",
        "session_v2",
        "target_config",
        "worker_api",
    )
    with pytest.raises(UnknownContractError, match="unknown contract 'missing'"):
        validate_contract("missing", {})


def test_flow_contract_preserves_complete_browser_attribution():
    payload = _fixture("flow-valid.json")
    payload["primary_url"] = "https://www.youtube.com/"
    payload["url"] = payload["primary_url"]
    payload["urls"] = [
        payload["primary_url"],
        "https://www.youtube.com/app.js",
    ]
    payload["connection_ids"] = [
        "conn-11111111111111111111111111111111",
    ]

    assert validate_flow(payload) is payload
