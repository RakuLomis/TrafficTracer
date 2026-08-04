"""Versioned JSON Schema validation for TrafficTracer Complete boundaries."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path
from typing import Any, TypeVar

from jsonschema import FormatChecker
from jsonschema.exceptions import SchemaError
from jsonschema.protocols import Validator
from jsonschema.validators import validator_for


_CONTRACT_ROOT = Path(__file__).resolve().parents[1] / "contracts"
_CONTRACT_FILES = {
    "job": "job.schema.json",
    "worker_api": "worker-api.schema.json",
    "session": "session.schema.json",
    "session_v2": "session-v2.schema.json",
    "flow": "flow.schema.json",
    "flow_v2": "flow-v2.schema.json",
    "pcap_index": "pcap-index.schema.json",
    "target_config": "target-config.schema.json",
}
_CONTRACT_ALIASES = {
    "worker-api": "worker_api",
    "worker": "worker_api",
    "session-v2": "session_v2",
    "flow-v2": "flow_v2",
    "pcap-index": "pcap_index",
}
T = TypeVar("T")


class UnknownContractError(ValueError):
    """Raised when code asks for a contract that is not part of this API version."""


class ValidationError(ValueError):
    """Stable, value-safe description of a contract validation failure."""

    code = "CONTRACT_VALIDATION_FAILED"

    def __init__(
        self,
        contract: str,
        path: tuple[str | int, ...],
        rule: str,
        message: str,
    ) -> None:
        self.contract = contract
        self.path = path
        self.rule = rule
        self.message = message
        super().__init__(self._render())

    @property
    def pointer(self) -> str:
        if not self.path:
            return ""
        escaped = (str(part).replace("~", "~0").replace("/", "~1") for part in self.path)
        return "/" + "/".join(escaped)

    def as_dict(self) -> dict[str, Any]:
        """Return data suitable for a Worker INVALID_PARAMS error payload."""
        return {
            "code": self.code,
            "contract": self.contract,
            "path": list(self.path),
            "rule": self.rule,
            "message": self.message,
        }

    def _render(self) -> str:
        location = self.pointer or "/"
        return f"{self.code}: {self.contract}{location}: {self.message}"


def available_contracts() -> tuple[str, ...]:
    """Return canonical contract names in a deterministic order."""
    return tuple(sorted(_CONTRACT_FILES))


def load_schema(contract: str) -> dict[str, Any]:
    """Load a defensive copy of a bundled contract schema."""
    return deepcopy(_load_schema(_canonical_name(contract)))


def get_validator(contract: str) -> Validator:
    """Return the cached validator for a canonical name or supported alias."""
    return _get_validator(_canonical_name(contract))


def validate_contract(contract: str, payload: T) -> T:
    """Validate a Worker-boundary payload and return it unchanged on success."""
    canonical = _canonical_name(contract)
    errors = list(get_validator(canonical).iter_errors(payload))
    if not errors:
        return payload

    error = sorted(
        _leaf_errors(errors),
        key=lambda item: (
            -len(item.absolute_path),
            tuple(str(part) for part in item.absolute_path),
            tuple(str(part) for part in item.absolute_schema_path),
        ),
    )[0]
    path = tuple(error.absolute_path)
    if error.validator == "required" and isinstance(error.instance, Mapping):
        missing = sorted(set(error.validator_value) - set(error.instance))
        if missing:
            path += (missing[0],)
    raise ValidationError(
        contract=canonical,
        path=path,
        rule=str(error.validator or "schema"),
        message=_safe_message(error),
    )


def validate_job(payload: T) -> T:
    return validate_contract("job", payload)


def validate_worker_message(payload: T) -> T:
    return validate_contract("worker_api", payload)


def validate_session(payload: T) -> T:
    return validate_contract("session", payload)


def validate_flow(payload: T) -> T:
    return validate_contract("flow", payload)


def validate_session_v2(payload: T) -> T:
    return validate_contract("session_v2", payload)


def validate_flow_v2(payload: T) -> T:
    return validate_contract("flow_v2", payload)


def validate_pcap_index(payload: T) -> T:
    return validate_contract("pcap_index", payload)


def validate_target_config(payload: T) -> T:
    return validate_contract("target_config", payload)


def _canonical_name(contract: str) -> str:
    canonical = _CONTRACT_ALIASES.get(contract, contract)
    if canonical not in _CONTRACT_FILES:
        choices = ", ".join(available_contracts())
        raise UnknownContractError(f"unknown contract {contract!r}; expected one of: {choices}")
    return canonical


@lru_cache(maxsize=None)
def _load_schema(contract: str) -> dict[str, Any]:
    path = _CONTRACT_ROOT / _CONTRACT_FILES[contract]
    try:
        with path.open(encoding="utf-8") as stream:
            schema = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"unable to load bundled {contract} contract: {path}") from exc
    if not isinstance(schema, dict):
        raise RuntimeError(f"bundled {contract} contract must be a JSON object: {path}")
    return schema


@lru_cache(maxsize=None)
def _get_validator(contract: str) -> Validator:
    schema = _load_schema(contract)
    validator_class = validator_for(schema)
    try:
        validator_class.check_schema(schema)
    except SchemaError as exc:
        raise RuntimeError(f"bundled {contract} contract is invalid") from exc
    return validator_class(schema, format_checker=FormatChecker())


def _leaf_errors(errors: list[Any]) -> Iterator[Any]:
    for error in errors:
        yield from _leaf_error(error)


def _leaf_error(error: Any) -> Iterator[Any]:
    if not error.context:
        yield error
        return

    if error.validator in {"oneOf", "anyOf"}:
        branches: dict[str, list[Any]] = {}
        for child in error.context:
            branch = str(next(iter(child.schema_path), ""))
            branches.setdefault(branch, []).append(child)
        candidates = [list(_leaf_errors(children)) for children in branches.values()]
        best = min(candidates, key=lambda items: (len(items), _error_sort_key(items)))
        yield from best
        return

    yield from _leaf_errors(list(error.context))


def _error_sort_key(errors: list[Any]) -> tuple[str, ...]:
    return tuple(
        "/".join(str(part) for part in error.absolute_schema_path)
        for error in errors
    )


def _safe_message(error: Any) -> str:
    """Describe a schema rule without echoing potentially sensitive values."""
    rule = error.validator
    if rule == "required":
        return "required property is missing"
    if rule == "additionalProperties":
        if isinstance(error.instance, Mapping) and isinstance(error.schema, Mapping):
            allowed = set(error.schema.get("properties", {}))
            unexpected = sorted(set(error.instance) - allowed)
            if unexpected:
                return "unknown properties are not allowed: " + ", ".join(unexpected)
        return "unknown properties are not allowed"
    messages = {
        "type": "value has an invalid type",
        "enum": "value is not one of the allowed values",
        "const": "value does not match the required constant",
        "pattern": "value does not match the required pattern",
        "format": "value does not match the required format",
        "minimum": "value is below the allowed minimum",
        "maximum": "value exceeds the allowed maximum",
        "minLength": "value is shorter than allowed",
        "maxLength": "value is longer than allowed",
        "minItems": "array has fewer items than allowed",
        "maxItems": "array has more items than allowed",
        "uniqueItems": "array items must be unique",
        "oneOf": "value must match exactly one allowed shape",
        "anyOf": "value does not match an allowed shape",
    }
    return messages.get(rule, "value does not satisfy the contract")
