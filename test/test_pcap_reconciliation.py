"""Tests for final request attribution propagation to PCAP metadata."""

import json

from traffictracer.analyze.pcap_mapping import reconcile_pcap_attribution
from traffictracer.analyze.pcap_splitter import ConnectionPcapResult, PcapSideResult


def test_reconcile_replaces_preliminary_attribution_in_index_and_mapping(tmp_path):
    connection_id = "conn-11111111111111111111111111111111"
    mapping_dir = tmp_path / "pcap" / "0001__media.example_video.m4s"
    mapping_dir.mkdir(parents=True)
    mapping_path = mapping_dir / "mapping.json"
    mapping_path.write_text(json.dumps({
        "connection_id": connection_id,
        "canonical_connection_id": connection_id,
        "primary_url": "https://media.example/video.m4s?range=1",
        "urls": ["https://media.example/video.m4s?range=1"],
        "request_ids": ["range.1"],
        "connections": [{"connection_id": connection_id, "role": "canonical"}],
    }), encoding="utf-8")
    pcap_results = [ConnectionPcapResult(
        connection_id=connection_id,
        protocol="tcp",
        request_ids=("range.1",),
        pre_proxy=PcapSideResult("success", "tcp", packet_count=2),
        post_proxy=PcapSideResult("success", "tcp", packet_count=2),
    )]

    reconcile_pcap_attribution(tmp_path, [{
        "request_id": "range.2",
        "url": "https://media.example/video.m4s?range=2",
        "connection_id": connection_id,
    }], pcap_results)

    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    assert pcap_results[0].request_ids == ("range.2",)
    assert mapping["request_ids"] == ["range.2"]
    assert mapping["urls"] == ["https://media.example/video.m4s?range=2"]
    assert mapping["primary_url"] == "https://media.example/video.m4s?range=2"


def test_reconcile_moves_redirect_request_between_candidate_connections(tmp_path):
    old_connection = "conn-11111111111111111111111111111111"
    final_connection = "conn-22222222222222222222222222222222"
    mapping_dir = tmp_path / "pcap" / "0001__https_www.youtube.com"
    mapping_dir.mkdir(parents=True)
    mapping_path = mapping_dir / "mapping.json"
    mapping_path.write_text(json.dumps({
        "connection_id": final_connection,
        "canonical_connection_id": final_connection,
        "primary_url": "https://www.youtube.com/",
        "urls": ["https://youtube.com/", "https://www.youtube.com/"],
        "request_ids": ["1016557.232"],
        "connections": [
            {"connection_id": final_connection, "role": "canonical"},
            {"connection_id": old_connection, "role": "alternative"},
        ],
    }), encoding="utf-8")
    pre = PcapSideResult("success", "tcp", packet_count=2, byte_count=128)
    post = PcapSideResult("success", "tcp", packet_count=2, byte_count=128)
    pcap_results = [
        ConnectionPcapResult(
            old_connection, "tcp", ("1016557.232",), pre, post,
        ),
        ConnectionPcapResult(final_connection, "tcp", (), pre, post),
    ]

    reconcile_pcap_attribution(tmp_path, [
        {
            "request_id": "1016557.232",
            "url": "https://youtube.com/",
            "connection_id": final_connection,
        },
        {
            "request_id": "1016557.232",
            "url": "https://www.youtube.com/",
            "connection_id": final_connection,
        },
    ], pcap_results)

    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    by_connection = {item.connection_id: item for item in pcap_results}
    assert by_connection[old_connection].request_ids == ()
    assert by_connection[final_connection].request_ids == ("1016557.232",)
    assert by_connection[old_connection].pre_proxy == pre
    assert by_connection[old_connection].post_proxy == post
    assert mapping["request_ids"] == ["1016557.232"]
    assert mapping["urls"] == [
        "https://www.youtube.com/",
        "https://youtube.com/",
    ]
    assert mapping["primary_url"] == "https://www.youtube.com/"


def test_reconcile_clears_connection_with_no_final_requests(tmp_path):
    connection_id = "conn-33333333333333333333333333333333"
    mapping_dir = tmp_path / "pcap" / "0001__https_stale.example"
    mapping_dir.mkdir(parents=True)
    mapping_path = mapping_dir / "mapping.json"
    mapping_path.write_text(json.dumps({
        "connection_id": connection_id,
        "canonical_connection_id": connection_id,
        "primary_url": "https://stale.example/",
        "urls": ["https://stale.example/"],
        "request_ids": ["stale.1"],
        "connections": [{"connection_id": connection_id, "role": "canonical"}],
    }), encoding="utf-8")
    pcap_results = [ConnectionPcapResult(
        connection_id=connection_id,
        protocol="tcp",
        request_ids=("stale.1",),
        pre_proxy=PcapSideResult("success", "tcp", packet_count=2),
        post_proxy=PcapSideResult("success", "tcp", packet_count=2),
    )]

    reconcile_pcap_attribution(tmp_path, [], pcap_results)

    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    assert pcap_results[0].request_ids == ()
    assert mapping["request_ids"] == []
    assert mapping["urls"] == []
    assert mapping["primary_url"] is None
