"""Tests for CDP attribution parser."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import tempfile

from traffictracer.analyze.cdp_attribution import parse_cdp_attribution
from traffictracer.models import AttributedRequest


def _write_cdp_json(data: dict) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    return path


def test_parse_basic_requests():
    data = {
        "visit_url": "https://www.bilibili.com",
        "targets": [
            {"target_id": "T1", "type": "page", "url": "https://www.bilibili.com"},
        ],
        "requests": [
            {
                "request_id": "1.1",
                "target_id": "T1",
                "frame_id": "F1",
                "loader_id": "L1",
                "url": "https://www.bilibili.com/",
                "resource_type": "Document",
                "timestamp": 100.0,
                "initiator_type": "other",
                "connection_id": 5,
                "remote_ip": "10.0.0.1",
                "remote_port": 443,
                "connection_reused": False,
                "response_status": 200,
                "from_disk_cache": True,
                "target_type": "page",
            },
            {
                "request_id": "1.2",
                "target_id": "T1",
                "frame_id": "F1",
                "loader_id": "L1",
                "url": "https://cdn.unknown.net/video.m4s",
                "resource_type": "Media",
                "timestamp": 101.0,
                "initiator_type": "script",
                "connection_id": 17,
                "remote_ip": "1.2.3.4",
                "remote_port": 443,
                "connection_reused": True,
                "response_status": 206,
                "target_type": "page",
            },
        ],
        "websockets": [],
    }
    path = _write_cdp_json(data)
    requests = parse_cdp_attribution(path)
    os.unlink(path)

    assert len(requests) == 2
    assert isinstance(requests[0], AttributedRequest)
    assert requests[0].url == "https://www.bilibili.com/"
    assert requests[0].resource_type == "Document"
    assert requests[0].response_status == 200
    assert requests[0].from_disk_cache is True
    assert requests[1].url == "https://cdn.unknown.net/video.m4s"
    assert requests[1].connection_id == 17
    assert requests[1].connection_reused is True


def test_parse_skips_requests_without_url():
    data = {
        "visit_url": "https://example.com",
        "targets": [],
        "requests": [
            {"request_id": "1.1", "target_id": "T1", "frame_id": "",
             "url": "", "resource_type": "Other", "timestamp": 0},
            {"request_id": "1.3", "target_id": "T1", "frame_id": "",
             "url": "data:image/png;base64,AAAA", "resource_type": "Image",
             "timestamp": 1.1},
            {"request_id": "1.4", "target_id": "T1", "frame_id": "",
             "url": "blob:https://example.com/id", "resource_type": "Other",
             "timestamp": 1.2},
            {"request_id": "1.2", "target_id": "T1", "frame_id": "",
             "url": "https://example.com/api", "resource_type": "XHR",
             "timestamp": 1.0},
        ],
        "websockets": [],
    }
    path = _write_cdp_json(data)
    requests = parse_cdp_attribution(path)
    os.unlink(path)

    assert len(requests) == 1
    assert requests[0].url == "https://example.com/api"


def test_parse_file_not_found():
    try:
        parse_cdp_attribution("/nonexistent/cdp.json")
        assert False, "Should raise FileNotFoundError"
    except FileNotFoundError:
        pass


def test_parse_empty_requests():
    data = {"visit_url": "https://example.com", "targets": [],
            "requests": [], "websockets": []}
    path = _write_cdp_json(data)
    requests = parse_cdp_attribution(path)
    os.unlink(path)
    assert requests == []


def test_connection_dedup_by_connection_id():
    """Multiple requests sharing connectionId=17 should all be returned."""
    data = {
        "visit_url": "https://example.com",
        "targets": [{"target_id": "T1", "type": "page", "url": "https://example.com"}],
        "requests": [
            {"request_id": "1.1", "target_id": "T1", "frame_id": "F1",
             "url": "https://a.example.com/1", "resource_type": "XHR",
             "timestamp": 1.0, "connection_id": 17, "remote_ip": "1.2.3.4",
             "remote_port": 443, "connection_reused": True, "target_type": "page"},
            {"request_id": "1.2", "target_id": "T1", "frame_id": "F1",
             "url": "https://b.example.com/2", "resource_type": "Fetch",
             "timestamp": 1.1, "connection_id": 17, "remote_ip": "1.2.3.4",
             "remote_port": 443, "connection_reused": True, "target_type": "page"},
        ],
        "websockets": [],
    }
    path = _write_cdp_json(data)
    requests = parse_cdp_attribution(path)
    os.unlink(path)

    assert len(requests) == 2
    conn_ids = {r.connection_id for r in requests}
    assert conn_ids == {17}


def test_parse_backfills_same_url_redirect_occurrences_from_legacy_cdp():
    data = {
        "requests": [
            {
                "request_id": "redirect.1",
                "target_id": "T1",
                "url": "https://example.com/questions",
                "resource_type": "Document",
                "timestamp": 10.0,
                "response_status": 302,
            },
            {
                "request_id": "redirect.1",
                "target_id": "T1",
                "url": "https://example.com/questions",
                "resource_type": "Document",
                "timestamp": 10.5,
                "response_status": 200,
            },
        ],
    }
    path = _write_cdp_json(data)
    requests = parse_cdp_attribution(path)
    os.unlink(path)

    assert [item.redirect_index for item in requests] == [0, 1]
    assert requests[1].redirect_from_url == "https://example.com/questions"
    assert requests[1].redirect_status == 302


if __name__ == "__main__":
    test_parse_basic_requests()
    test_parse_skips_requests_without_url()
    test_parse_file_not_found()
    test_parse_empty_requests()
    test_connection_dedup_by_connection_id()
    print("\n✓ All CDP attribution tests passed!")
