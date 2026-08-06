"""Regression tests for page-attributed versus capture-global coverage."""

from traffictracer.analyze.artifacts import layered_coverage


def test_background_core_flows_do_not_inflate_page_scope():
    requests = [{"attribution": {"status": "matched"}}]
    connections = [{
        "match": {"status": "matched"},
        "post_flow": {"complete": True},
        "shared": False,
    }]
    global_core = [
        {"post_flow": {"complete": True}, "shared": False},
        {"post_flow": None, "shared": False},
        {"post_flow": None, "shared": True},
    ]

    coverage = layered_coverage(requests, connections, global_core)

    assert coverage["page_attributed"]["logical_flows"] == {
        "total": 1,
        "with_post_flow": 1,
        "shared": 0,
        "missing_post_flow": 0,
    }
    assert coverage["page_attributed"]["unmatched_reasons"] == {}
    assert coverage["capture_global"]["core_logical_flows"] == {
        "total": 3,
        "with_post_flow": 1,
        "shared": 1,
        "missing_post_flow": 2,
    }
    assert coverage["capture_global"]["unmatched_reasons"] == {
        "missing_post_flow": 2,
    }
    assert coverage["core_logical_flows"] == coverage["capture_global"][
        "core_logical_flows"
    ]
