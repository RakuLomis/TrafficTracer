import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.analyze.outcomes import (
    egress_evidence_kind,
    post_flow_disposition,
    terminal_error_class,
)


def test_post_flow_disposition_is_mutually_exclusive_and_evidence_bounded():
    assert post_flow_disposition({"post_flow": {"complete": True}}) == "with_post_flow"
    assert post_flow_disposition({
        "post_flow": None, "egress_outcome": "rejected",
    }) == "explicit_no_socket"
    assert post_flow_disposition({
        "post_flow": None,
        "terminal": {"status": "resolve_error", "stage": "resolve"},
    }) == "failed_before_socket"
    assert post_flow_disposition({
        "post_flow": None, "egress_outcome": "pass",
    }) == "unexpected_missing"
    assert post_flow_disposition({
        "post_flow": None, "egress_outcome": "compatible",
    }) == "unexpected_missing"
    assert post_flow_disposition({
        "post_flow": None,
    }, local_endpoint=True) == "local_not_applicable"


def test_egress_evidence_distinguishes_shared_carriers_from_exclusive_sockets():
    assert egress_evidence_kind({
        "post_flow": {"complete": True, "shared": False},
    }) == "exclusive_socket"
    assert egress_evidence_kind({
        "post_flow": {"complete": True, "shared": True},
        "carrier_binding": {
            "carrier_id": "carrier-1",
            "mode": "shared",
            "physical_paths": [{"complete": True}],
        },
    }) == "shared_carrier"


def test_egress_evidence_classifies_shared_carrier_observation_gaps():
    assert egress_evidence_kind({
        "post_flow": None,
        "egress": {"outcome": "proxy", "selected_type": "AnyTLS"},
    }) == "carrier_binding_unavailable"
    assert egress_evidence_kind({
        "post_flow": None,
        "egress": {"outcome": "proxy", "selected_type": "Hysteria2"},
        "carrier_binding": {
            "carrier_id": "carrier-1",
            "mode": "shared",
            "physical_paths": [],
        },
    }) == "carrier_path_unavailable"
    assert egress_evidence_kind({
        "post_flow": None,
        "egress": {"outcome": "proxy", "selected_type": "VLESS"},
    }) == "egress_unavailable"


def test_explicit_core_error_class_wins_over_message_inference():
    assert terminal_error_class(
        status="dial_error", stage="dial", error="opaque",
        explicit="connection_refused",
    ) == ("connection_refused", "core_explicit")

