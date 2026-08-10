"""Regression tests for canonical browser request resolution."""

from traffictracer.analyze.request_resolver import resolve_visit_requests
from traffictracer.models import AttributedRequest, CorrelatedFlowV2, FlowTuple, VisitCorrelation


def _request(
    request_id: str,
    *,
    cdp_connection_id: int | None,
    response_status: int = 206,
    reused: bool = True,
    timestamp: float = 100.0,
    remote_ip: str = "",
    remote_port: int = 0,
) -> AttributedRequest:
    return AttributedRequest(
        request_id=request_id,
        target_id="target",
        frame_id="frame",
        url=f"https://media.example/video.m4s?range={request_id}",
        resource_type="Media",
        timestamp=timestamp,
        connection_id=cdp_connection_id,
        connection_reused=reused,
        response_status=response_status,
        remote_ip=remote_ip,
        remote_port=remote_port,
    )


def _flow(connection_id: str, request_ids: list[str], port: int) -> CorrelatedFlowV2:
    pre = FlowTuple(
        "tcp", "198.18.0.1", port, "198.18.0.39", 443,
        key=f"tcp|198.18.0.1:{port}|198.18.0.39:443",
        complete=True,
    )
    return CorrelatedFlowV2(
        url="https://media.example/video.m4s",
        resource_type="Media",
        target_type="page",
        relation="cross_site",
        pre_proxy_src=pre.src,
        pre_proxy_dst=pre.dst,
        post_proxy_src="192.0.2.1:50000",
        post_proxy_dst="203.0.113.1:443",
        protocol="HTTPS",
        request_ids=request_ids,
        pre_flow=pre,
        match_status="matched",
        match_confidence=1.0,
        stable_connection_id=connection_id,
        match_method="exact_pre_flow",
    )


def test_positive_response_reuses_unique_cdp_connection():
    connection_id = "conn-11111111111111111111111111111111"
    result = VisitCorrelation(
        visit_url="https://example.com/",
        domain="example.com",
        flows=[_flow(connection_id, ["range.1"], 44001)],
        requests=[
            _request("range.1", cdp_connection_id=338, reused=False),
            _request("range.2", cdp_connection_id=338),
            _request("range.3", cdp_connection_id=338),
        ],
    )

    resolutions = resolve_visit_requests(result, [])

    assert [item.flow.stable_connection_id for item in resolutions] == [
        connection_id, connection_id, connection_id,
    ]
    assert resolutions[1].method == "cdp_connection_reuse"
    assert resolutions[1].evidence == (
        "cdp_connection_id:338",
        "prior_request_id:range.1",
        "cdp_response_received",
        "cdp_connection_reused",
        "unique_transport_connection",
    )


def test_response_endpoint_seeds_connection_and_its_reused_requests():
    connection_id = "conn-11111111111111111111111111111111"
    result = VisitCorrelation(
        visit_url="https://example.com/",
        domain="example.com",
        flows=[_flow(connection_id, [], 44001)],
        requests=[
            _request(
                "seed",
                cdp_connection_id=338,
                reused=False,
                remote_ip="198.18.0.39",
                remote_port=443,
            ),
            _request("reused", cdp_connection_id=338),
        ],
    )

    seed, reused = resolve_visit_requests(result, [])

    assert seed.flow is not None
    assert seed.flow.stable_connection_id == connection_id
    assert seed.method == "cdp_response_endpoint"
    assert reused.flow is not None
    assert reused.flow.stable_connection_id == connection_id
    assert reused.method == "cdp_connection_reuse"


def test_response_endpoint_prefers_unique_active_lifecycle():
    active = _flow("conn-11111111111111111111111111111111", [], 44001)
    future = _flow("conn-22222222222222222222222222222222", [], 44002)
    active.first_observed = 90.0
    active.last_observed = 110.0
    future.first_observed = 120.0
    future.last_observed = 130.0
    result = VisitCorrelation(
        visit_url="https://example.com/",
        domain="example.com",
        flows=[active, future],
        requests=[
            _request(
                "endpoint",
                cdp_connection_id=338,
                reused=False,
                remote_ip="198.18.0.39",
                remote_port=443,
                timestamp=100.0,
            ),
        ],
    )

    resolution = resolve_visit_requests(result, [])[0]

    assert resolution.flow is active
    assert "request_within_transport_lifecycle" in resolution.evidence


def test_response_endpoint_prefers_unique_nearest_preceding_lifecycle():
    older = _flow("conn-11111111111111111111111111111111", [], 44001)
    nearest = _flow("conn-22222222222222222222222222222222", [], 44002)
    older.first_observed = 90.0
    older.last_observed = 95.0
    nearest.first_observed = 96.0
    nearest.last_observed = 99.5
    result = VisitCorrelation(
        visit_url="https://example.com/",
        domain="example.com",
        flows=[older, nearest],
        requests=[
            _request(
                "endpoint",
                cdp_connection_id=338,
                reused=False,
                remote_ip="198.18.0.39",
                remote_port=443,
                timestamp=100.0,
            ),
        ],
    )

    resolution = resolve_visit_requests(result, [])[0]

    assert resolution.flow is nearest
    assert "nearest_preceding_transport_lifecycle" in resolution.evidence
    assert "temporal_gap_ms:500" in resolution.evidence


def test_ambiguous_response_endpoint_is_not_guessed():
    first = _flow("conn-11111111111111111111111111111111", [], 44001)
    second = _flow("conn-22222222222222222222222222222222", [], 44002)
    result = VisitCorrelation(
        visit_url="https://example.com/",
        domain="example.com",
        flows=[first, second],
        requests=[
            _request(
                "endpoint",
                cdp_connection_id=338,
                reused=False,
                remote_ip="198.18.0.39",
                remote_port=443,
            ),
        ],
    )

    resolution = resolve_visit_requests(result, [])[0]

    assert resolution.flow is None
    assert resolution.status == "ambiguous"
    assert resolution.unmatched_reason == "ambiguous_response_endpoint"
    assert len(resolution.candidates) == 2


def test_ambiguous_cdp_connection_is_not_selected():
    first = "conn-11111111111111111111111111111111"
    second = "conn-22222222222222222222222222222222"
    result = VisitCorrelation(
        visit_url="https://example.com/",
        domain="example.com",
        flows=[
            _flow(first, ["range.1"], 44001),
            _flow(second, ["range.2"], 44002),
        ],
        requests=[
            _request("range.1", cdp_connection_id=338, reused=False),
            _request("range.2", cdp_connection_id=338, reused=False),
            _request("range.3", cdp_connection_id=338),
        ],
    )

    resolution = resolve_visit_requests(result, [])[-1]

    assert resolution.flow is None
    assert resolution.status == "ambiguous"
    assert resolution.unmatched_reason == "ambiguous_cdp_connection"
    assert {item.stable_connection_id for item in resolution.candidates} == {
        first, second,
    }


def test_zero_id_or_missing_response_is_never_backfilled():
    connection_id = "conn-11111111111111111111111111111111"
    result = VisitCorrelation(
        visit_url="https://example.com/",
        domain="example.com",
        flows=[_flow(connection_id, ["range.1"], 44001)],
        requests=[
            _request("range.1", cdp_connection_id=338, reused=False),
            _request("zero", cdp_connection_id=0),
            _request("no-response", cdp_connection_id=338, response_status=0),
        ],
    )

    zero, no_response = resolve_visit_requests(result, [])[1:]

    assert zero.flow is None
    assert no_response.flow is None
    assert zero.status == no_response.status == "unmatched"


def test_reused_connection_prefers_unique_nearest_preceding_transport():
    first = "conn-11111111111111111111111111111111"
    second = "conn-22222222222222222222222222222222"
    result = VisitCorrelation(
        visit_url="https://example.com/",
        domain="example.com",
        flows=[
            _flow(first, ["range.1"], 44001),
            _flow(second, ["range.2"], 44002),
        ],
        requests=[
            _request(
                "range.1", cdp_connection_id=338, reused=False,
                timestamp=90.0,
            ),
            _request(
                "range.2", cdp_connection_id=338, reused=False,
                timestamp=99.0,
            ),
            _request("range.3", cdp_connection_id=338, timestamp=100.0),
        ],
    )

    resolution = resolve_visit_requests(result, [])[-1]

    assert resolution.flow is not None
    assert resolution.flow.stable_connection_id == second
    assert resolution.status == "matched"
    assert "nearest_preceding_request" in resolution.evidence
    assert "temporal_gap_ms:1000" in resolution.evidence


def test_redirect_occurrences_with_same_request_id_use_full_url():
    first = _flow(
        "conn-11111111111111111111111111111111", ["redirect.1"], 44001,
    )
    second = _flow(
        "conn-22222222222222222222222222222222", ["redirect.1"], 44002,
    )
    first.url = "https://example.com/"
    second.url = "https://www.example.com/"
    result = VisitCorrelation(
        visit_url="https://example.com/",
        domain="example.com",
        flows=[first, second],
        requests=[
            AttributedRequest(
                "redirect.1", "target", "frame", first.url,
                "Document", 90.0,
            ),
            AttributedRequest(
                "redirect.1", "target", "frame", second.url,
                "Document", 91.0,
            ),
        ],
    )

    resolutions = resolve_visit_requests(result, [])

    assert [item.flow.stable_connection_id for item in resolutions] == [
        first.stable_connection_id,
        second.stable_connection_id,
    ]
