"""Golden contract tests for Session manifests and correlated flows."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = ROOT / "contracts"
FIXTURE_ROOT = ROOT / "test" / "fixtures" / "contracts"


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _validator(name: str) -> Draft202012Validator:
    schema = _load(CONTRACT_ROOT / name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def test_golden_session_manifest_matches_schema():
    _validator("session.schema.json").validate(_load(FIXTURE_ROOT / "session-valid.json"))


def test_session_v1_and_v2_have_explicit_discriminators():
    legacy = _load(FIXTURE_ROOT / "session-valid.json")
    current = _load(FIXTURE_ROOT / "session-v2-valid.json")
    _validator("session.schema.json").validate(legacy)
    _validator("session-v2.schema.json").validate(current)
    assert list(_validator("session.schema.json").iter_errors(current))
    assert list(_validator("session-v2.schema.json").iter_errors(legacy))


def test_golden_ipv4_and_ipv6_flows_match_schema():
    validator = _validator("flow.schema.json")
    validator.validate(_load(FIXTURE_ROOT / "flow-valid.json"))
    validator.validate(_load(FIXTURE_ROOT / "flow-valid-unmatched-ipv6.json"))


def test_connection_centric_v2_fixtures_cover_shared_ambiguous_and_missing_post():
    validator = _validator("flow-v2.schema.json")
    shared = _load(FIXTURE_ROOT / "flow-v2-connection-shared-http2.json")
    missing_post = _load(FIXTURE_ROOT / "flow-v2-connection-unmatched-ipv6-udp.json")
    request = _load(FIXTURE_ROOT / "flow-v2-request-repeated-url.json")
    ambiguous = _load(FIXTURE_ROOT / "flow-v2-request-ambiguous.json")
    for payload in (shared, missing_post, request, ambiguous):
        validator.validate(payload)

    repeated = dict(request)
    repeated["request_id"] = "7856.13"
    validator.validate(repeated)
    assert repeated["url"] == request["url"]
    assert shared["request_ids"][:2] == [request["request_id"], repeated["request_id"]]
    assert shared["shared"] is True and len(shared["request_ids"]) == 3
    assert missing_post["protocol"] == "udp" and missing_post["post_flow"] is None
    assert ambiguous["connection_id"] is None
    assert len(ambiguous["candidate_connection_ids"]) == 2


def test_pcap_index_is_unique_connection_scoped_and_coverage_is_conservative():
    payload = _load(FIXTURE_ROOT / "pcap-index-v1-valid.json")
    _validator("pcap-index.schema.json").validate(payload)
    connection_ids = [item["connection_id"] for item in payload["connections"]]
    assert len(connection_ids) == len(set(connection_ids))
    assert len(payload["connections"][0]["request_ids"]) == 3
    assert payload["split_mode"] == "unique_connections"
    for name in ("browser_requests", "transport_connections"):
        partition = payload["coverage"][name]
        assert partition["matched"] + partition["ambiguous"] + partition["unmatched"] == partition["total"]


def test_v2_ambiguous_match_requires_multiple_candidates_and_reason():
    payload = _load(FIXTURE_ROOT / "flow-v2-connection-shared-http2.json")
    payload["match"] = {
        "status": "ambiguous",
        "method": "endpoint_time",
        "confidence": 0.5,
        "candidates": payload["match"]["candidates"],
    }
    assert list(_validator("flow-v2.schema.json").iter_errors(payload))


def test_session_manifest_rejects_secret_and_subscription_body():
    validator = _validator("session.schema.json")
    for field, value in (
        ("secret", "must-not-be-persisted"),
        ("subscription", "proxies: [sensitive subscription body]"),
    ):
        payload = _load(FIXTURE_ROOT / "session-valid.json")
        payload[field] = value
        assert list(validator.iter_errors(payload)), field


def test_session_manifest_rejects_escaping_artifact_path():
    payload = _load(FIXTURE_ROOT / "session-valid.json")
    payload["artifacts"][0]["path"] = "analysis/../outside.json"
    assert list(_validator("session.schema.json").iter_errors(payload))


def test_flow_rejects_invalid_ip_port_and_match_confidence():
    validator = _validator("flow.schema.json")
    payload = _load(FIXTURE_ROOT / "flow-valid.json")
    payload["pre_flow"]["src_ip"] = "not-an-ip"
    payload["pre_flow"]["src_port"] = 70000
    payload["match"]["confidence"] = 1.1
    assert len(list(validator.iter_errors(payload))) >= 3


def test_flow_rejects_unknown_persisted_fields():
    payload = _load(FIXTURE_ROOT / "flow-valid.json")
    payload["controller_secret"] = "must-not-be-persisted"
    assert list(_validator("flow.schema.json").iter_errors(payload))
