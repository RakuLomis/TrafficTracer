"""Tests for actionable unmatched browser request reasons."""

import json

from traffictracer.analyze.connection_artifacts import persist_connection_artifacts
from traffictracer.models import AttributedRequest, VisitCorrelation


SESSION_ID = "5027aee9-c6e4-41de-8625-7ea0869a3307"


def test_response_without_transport_is_distinct_from_no_response(tmp_path):
    result = VisitCorrelation(
        visit_url="https://example.com/",
        domain="example.com",
        requests=[
            AttributedRequest(
                "returned", "target", "frame",
                "https://cdn.example/video.m4s", "Media", 100.0,
                connection_id=338, response_status=206,
                connection_reused=True,
            ),
            AttributedRequest(
                "beacon", "target", "frame",
                "https://data.example/ping", "XHR", 101.0,
                response_status=0,
            ),
        ],
    )

    artifacts = persist_connection_artifacts(tmp_path, SESSION_ID, [result])
    requests = json.loads(
        artifacts.request_index.read_text(encoding="utf-8")
    )["items"]
    reasons = {
        item["request_id"]: item["attribution"]["unmatched_reason"]
        for item in requests
    }

    assert reasons == {
        "beacon": "no_response",
        "returned": "response_transport_unbound",
    }
