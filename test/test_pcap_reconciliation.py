"""Tests for final request attribution propagation to PCAP metadata."""

import json

from traffictracer.analyze.pcap_mapping import reconcile_pcap_attribution
from traffictracer.analyze.pcap_splitter import ConnectionPcapResult, PcapSideResult


def test_reconcile_adds_backfilled_request_to_index_and_mapping(tmp_path):
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
    assert pcap_results[0].request_ids == ("range.1", "range.2")
    assert mapping["request_ids"] == ["range.1", "range.2"]
    assert mapping["urls"] == [
        "https://media.example/video.m4s?range=1",
        "https://media.example/video.m4s?range=2",
    ]
