"""Coverage treatment for packet-empty QUIC/UDP transport candidates."""

from traffictracer.analyze.artifacts import layered_coverage


def test_empty_unmatched_udp_stays_in_transport_not_logical_flow_scope():
    empty_udp = {
        "protocol": "udp",
        "match": {"status": "ambiguous", "unmatched_reason": "multiple_candidates"},
        "post_flow": None,
        "terminal": None,
        "shared": False,
    }
    matched_tcp = {
        "protocol": "tcp",
        "match": {"status": "matched"},
        "mihomo_connection_id": "native-tcp",
        "post_flow": {"complete": True},
        "shared": True,
    }

    coverage = layered_coverage([], [empty_udp, matched_tcp], [])

    assert coverage["transport_connections"] == {
        "total": 2, "matched": 1, "ambiguous": 1, "unmatched": 0,
    }
    assert coverage["page_attributed"]["logical_flows"] == {
        "total": 1,
        "with_post_flow": 1,
        "shared": 1,
        "missing_post_flow": 0,
    }
    assert coverage["page_attributed"]["unmatched_reasons"] == {
        "multiple_candidates": 1,
    }
