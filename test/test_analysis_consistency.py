"""Tests for cross-index analysis consistency invariants."""

import pytest

from traffictracer.analyze.consistency import (
    AnalysisConsistencyError,
    validate_analysis_consistency,
)


CONNECTION_ID = "conn-11111111111111111111111111111111"
GENERATION_ID = "78fdab68-4e5d-4b67-9910-33da00a2632a"


def _request(*, observation="network", connection_id=CONNECTION_ID):
    return {
        "request_id": "1.1",
        "url": "https://example.com/app.js",
        "connection_id": connection_id,
        "network_observation": observation,
        "attribution": {
            "status": "matched" if connection_id else "unmatched",
        },
    }


def _connection():
    return {
        "connection_id": CONNECTION_ID,
        "mihomo_connection_id": "mihomo-1",
        "request_ids": ["1.1"],
        "urls": ["https://example.com/app.js"],
        "primary_url": "https://example.com/app.js",
        "match": {"status": "matched"},
    }


def _flow():
    return {
        "conn_id": "mihomo-1",
        "request_ids": ["1.1"],
        "connection_ids": [CONNECTION_ID],
        "urls": ["https://example.com/app.js"],
    }


def test_consistency_accepts_one_complete_pipeline():
    result = validate_analysis_consistency(
        [_request()],
        [_connection()],
        [_flow()],
        pcap_payload={
            "analysis_generation_id": GENERATION_ID,
            "connections": [{
                "connection_id": CONNECTION_ID,
                "request_ids": ["1.1"],
            }],
        },
        legacy_payload={
            "example.com": {
                "flows": [{"stable_connection_id": CONNECTION_ID}],
            },
        },
        generation_id=GENERATION_ID,
    )

    assert result == {
        "status": "passed",
        "request_connection_orphans": 0,
        "connection_flow_orphans": 0,
        "pcap_connection_orphans": 0,
        "non_network_with_connection": 0,
        "legacy_projection_mismatches": 0,
    }


def test_consistency_rejects_non_network_request_with_connection():
    with pytest.raises(
        AnalysisConsistencyError,
        match="non-network request has connection_id",
    ):
        validate_analysis_consistency(
            [_request(observation="disk_cache")],
            [_connection()],
            [_flow()],
        )


def test_consistency_allows_local_endpoint_with_connection():
    result = validate_analysis_consistency(
        [_request(observation="local_endpoint")],
        [_connection()],
        [_flow()],
    )

    assert result["status"] == "passed"


def test_consistency_rejects_cross_index_orphans_and_generation_mix():
    with pytest.raises(AnalysisConsistencyError) as error:
        validate_analysis_consistency(
            [_request(connection_id="conn-22222222222222222222222222222222")],
            [_connection()],
            [_flow()],
            pcap_payload={
                "analysis_generation_id": "f2ec1c2c-45ed-4d61-8943-a85b72cb416b",
                "connections": [{
                    "connection_id": "conn-33333333333333333333333333333333",
                    "request_ids": [],
                }],
            },
            generation_id=GENERATION_ID,
        )

    message = str(error.value)
    assert "matched request references missing connection" in message
    assert "pcap index uses a different analysis generation" in message
    assert "pcap references missing connection" in message


def test_consistency_allows_same_url_redirect_stages_with_one_request_id():
    first = {
        **_request(),
        "request_occurrence_id": "78fdab68-4e5d-4b67-9910-33da00a2632a",
        "target_id": "page-1",
        "redirect_index": 0,
        "timing": {"request": 10.0},
    }
    second = {
        **first,
        "request_occurrence_id": "f2ec1c2c-45ed-4d61-8943-a85b72cb416b",
        "redirect_index": 1,
        "timing": {"request": 10.5},
    }
    connection = _connection()
    connection["request_occurrence_ids"] = [
        first["request_occurrence_id"],
        second["request_occurrence_id"],
    ]

    result = validate_analysis_consistency(
        [first, second],
        [connection],
        [_flow()],
    )

    assert result["status"] == "passed"


def test_consistency_rejects_duplicate_request_occurrence():
    request = {
        **_request(),
        "request_occurrence_id": "78fdab68-4e5d-4b67-9910-33da00a2632a",
        "target_id": "page-1",
        "redirect_index": 0,
        "timing": {"request": 10.0},
    }
    connection = _connection()
    connection["request_occurrence_ids"] = [request["request_occurrence_id"]]

    with pytest.raises(
        AnalysisConsistencyError,
        match="duplicate request occurrence",
    ):
        validate_analysis_consistency(
            [request, dict(request)],
            [connection],
            [_flow()],
        )


def test_consistency_rejects_non_contiguous_redirect_indexes():
    first = {
        **_request(),
        "request_occurrence_id": "78fdab68-4e5d-4b67-9910-33da00a2632a",
        "target_id": "page-1",
        "redirect_index": 0,
        "timing": {"request": 10.0},
    }
    third = {
        **first,
        "request_occurrence_id": "f2ec1c2c-45ed-4d61-8943-a85b72cb416b",
        "redirect_index": 2,
        "timing": {"request": 11.0},
    }
    connection = _connection()
    connection["request_occurrence_ids"] = [
        first["request_occurrence_id"],
        third["request_occurrence_id"],
    ]

    with pytest.raises(
        AnalysisConsistencyError,
        match="non-contiguous redirect indexes",
    ):
        validate_analysis_consistency(
            [first, third],
            [connection],
            [_flow()],
        )
