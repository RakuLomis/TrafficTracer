import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.analyze.outcomes import post_flow_disposition, terminal_error_class


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


def test_explicit_core_error_class_wins_over_message_inference():
    assert terminal_error_class(
        status="dial_error", stage="dial", error="opaque",
        explicit="connection_refused",
    ) == ("connection_refused", "core_explicit")

