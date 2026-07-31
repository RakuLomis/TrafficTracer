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


def test_golden_ipv4_and_ipv6_flows_match_schema():
    validator = _validator("flow.schema.json")
    validator.validate(_load(FIXTURE_ROOT / "flow-valid.json"))
    validator.validate(_load(FIXTURE_ROOT / "flow-valid-unmatched-ipv6.json"))


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
