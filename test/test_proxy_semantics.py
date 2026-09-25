from traffictracer.capture.proxy_semantics import (
    create_runtime_semantics_artifact,
    finish_runtime_semantics_artifact,
    runtime_semantics_summary,
)


def _snapshot(**overrides):
    value = {
        "snapshot_id": "snap-1",
        "config_generation": 7,
        "adapter_instance_id": "adapter-1",
        "protocol": "vless",
        "behavior_fingerprint": "sha256:behavior",
        "coverage": {"status": "partial"},
        "build": {"executable_sha256": "sha256:binary"},
    }
    value.update(overrides)
    return value


def test_equivalent_adapter_replacement_is_not_configuration_drift():
    artifact = create_runtime_semantics_artifact(_snapshot())
    assert artifact["source"] == {
        "component": "mihomo",
        "scope": "runtime_adapter",
        "configured": "accepted_configuration",
        "effective": "applied_defaults_and_normalization",
        "negotiated": "connection_specific_when_available",
        "observed": "connection_bound_trace_when_available",
    }
    completed = finish_runtime_semantics_artifact(
        artifact,
        _snapshot(
            snapshot_id="snap-2",
            config_generation=8,
            adapter_instance_id="adapter-2",
        ),
    )
    assert completed["verification"]["state"] == "adapter_replaced_same_behavior"
    assert completed["verification"]["same_behavior"] is True


def test_behavior_change_is_configuration_drift():
    artifact = create_runtime_semantics_artifact(_snapshot())
    completed = finish_runtime_semantics_artifact(
        artifact,
        _snapshot(behavior_fingerprint="sha256:other"),
    )
    assert completed["verification"]["state"] == "configuration_drift"


def test_end_snapshot_failure_is_explicit_and_summary_omits_full_evidence():
    artifact = create_runtime_semantics_artifact(_snapshot())
    completed = finish_runtime_semantics_artifact(
        artifact, None, error="controller unavailable",
    )
    summary = runtime_semantics_summary(completed)
    assert summary["verification"]["state"] == "end_snapshot_unavailable"
    assert "start" not in summary
    assert "end" not in summary


def test_missing_executable_hash_is_not_treated_as_same_binary():
    start = _snapshot(build={"executable_hash_status": "unavailable"})
    completed = finish_runtime_semantics_artifact(
        create_runtime_semantics_artifact(start),
        _snapshot(build={"executable_hash_status": "unavailable"}),
    )

    assert completed["verification"]["state"] == "binary_identity_unavailable"
    assert completed["verification"]["same_binary"] is None
