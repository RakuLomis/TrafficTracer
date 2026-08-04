"""Tests for pcap splitter filter generation."""

import sys
import os
from pathlib import Path
import subprocess

import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.analyze.netlog import FiveTupleData
from traffictracer.analyze.pcap_splitter import (
    SPLIT_NONE,
    build_tshark_filter,
    build_flow_tuple_filter,
    split_flows_v2,
    _sanitize_name,
)
from traffictracer.models import CorrelatedFlowV2, FlowTuple, VisitCorrelation


def test_build_filter_src():
    ft = FiveTupleData("192.168.1.100", 41234, "1.2.3.4", 443, "tcp")
    f = build_tshark_filter(ft, "src")
    assert "ip.src==192.168.1.100" in f
    assert "tcp.srcport==41234" in f


def test_build_filter_dst():
    ft = FiveTupleData("192.168.1.100", 41234, "1.2.3.4", 443, "tcp")
    f = build_tshark_filter(ft, "dst")
    assert "ip.src==192.168.1.100" in f
    assert "tcp.port==41234" in f


def test_build_filter_empty():
    ft = FiveTupleData("", 0, "", 0, "")
    f = build_tshark_filter(ft, "src")
    assert f == ""


def test_sanitize_name():
    assert _sanitize_name("https://www.example.com/") == "www.example.com"
    assert _sanitize_name("https://api.example.com") == "api.example.com"
    assert _sanitize_name("http://localhost:8080/path") == "localhost:8080/path"


if __name__ == "__main__":
    test_build_filter_src()
    test_build_filter_dst()
    test_build_filter_empty()
    test_sanitize_name()
    print("\n✓ All pcap splitter tests passed!")


def test_normalized_filter_is_bidirectional_udp_ipv6():
    flow = FlowTuple(
        network="udp", src_ip="2001:db8::1", src_port=50000,
        dst_ip="2001:db8::2", dst_port=443, complete=True, key="key",
    )
    display_filter = build_flow_tuple_filter(flow)
    assert "udp" in display_filter
    assert "ipv6.src==2001:db8::1" in display_filter
    assert "udp.srcport==50000" in display_filter
    assert "ipv6.src==2001:db8::2" in display_filter
    assert "udp.dstport==50000" in display_filter


def _flow(connection_id: str, request_id: str, *, url: str = "https://example.com/a"):
    suffix = int(connection_id[-1], 16)
    pre = FlowTuple(
        "tcp", "198.18.0.1", 44000 + suffix, "9.9.9.9", 443,
        key=f"pre-{connection_id}", complete=True, source="netlog",
    )
    post = FlowTuple(
        "tcp", "192.0.2.10", 54000 + suffix, "203.0.113.20", 443,
        key=f"post-{connection_id}", complete=True, source="mihomo",
    )
    return CorrelatedFlowV2(
        url=url,
        resource_type="Script",
        target_type="page",
        relation="same_site",
        pre_proxy_src=pre.src,
        pre_proxy_dst=pre.dst,
        post_proxy_src=post.src,
        post_proxy_dst=post.dst,
        protocol="HTTP2",
        request_ids=[request_id],
        pre_flow=pre,
        post_flow=post,
        match_status="matched",
        stable_connection_id=connection_id,
    )


def _result(flows):
    return VisitCorrelation(
        visit_url="https://example.com/",
        domain="example.com",
        flows=list(flows),
        cdp_request_count=len(flows),
        netlog_connection_count=len({flow.stable_connection_id for flow in flows}),
    )


def _successful_tshark(calls):
    def run(command, **kwargs):
        calls.append(command)
        if "-w" in command:
            Path(command[-1]).write_bytes(b"pcap" + b"x" * 32)
            return subprocess.CompletedProcess(command, 0)
        return subprocess.CompletedProcess(
            command, 0, stdout="60\n70\n", stderr=""
        )
    return run


def test_unique_connections_split_once_for_many_requests(tmp_path, monkeypatch):
    first = "conn-" + "1" * 32
    flows = [
        _flow(first, f"request-{index}")
        for index in range(8)
    ]
    calls = []
    monkeypatch.setattr(
        "traffictracer.analyze.pcap_splitter.subprocess.run",
        _successful_tshark(calls),
    )

    outputs = split_flows_v2(
        _result(flows), "tun.pcap", "phys.pcap", str(tmp_path)
    )

    assert len(outputs) == 1
    assert len([call for call in calls if "-w" in call]) == 2
    assert len(calls) == 4
    assert set(outputs[0].request_ids) == {
        f"request-{index}" for index in range(8)
    }
    assert {path.name for path in tmp_path.iterdir()} == {first}
    assert all((tmp_path / item.connection_id / "pre.pcap").is_file() for item in outputs)
    assert all((tmp_path / item.connection_id / "post.pcap").is_file() for item in outputs)


def test_repeated_and_long_urls_do_not_create_url_directories(tmp_path, monkeypatch):
    connection_id = "conn-" + "3" * 32
    long_url = "https://example.com/" + "segment/" * 1000
    flows = [
        _flow(connection_id, "one", url=long_url),
        _flow(connection_id, "two", url=long_url),
    ]
    monkeypatch.setattr(
        "traffictracer.analyze.pcap_splitter.subprocess.run",
        _successful_tshark([]),
    )
    outputs = split_flows_v2(
        _result(flows), "tun.pcap", "phys.pcap", str(tmp_path)
    )
    assert [path.name for path in tmp_path.iterdir()] == [connection_id]
    assert outputs[0].request_ids == ("one", "two")


def test_none_mode_never_invokes_tshark(tmp_path, monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("tshark must not run in none mode")

    monkeypatch.setattr(
        "traffictracer.analyze.pcap_splitter.subprocess.run", unexpected
    )
    outputs = split_flows_v2(
        _result([_flow("conn-" + "4" * 32, "one")]),
        "tun.pcap",
        "phys.pcap",
        str(tmp_path),
        split_mode=SPLIT_NONE,
    )
    assert outputs[0].pre_proxy.status == "not_requested"
    assert outputs[0].post_proxy.status == "not_requested"
    assert not list(tmp_path.iterdir())


def test_failed_extract_leaves_no_partial_file(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "traffictracer.analyze.pcap_splitter.subprocess.run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 2),
    )
    connection_id = "conn-" + "5" * 32
    outputs = split_flows_v2(
        _result([_flow(connection_id, "one")]),
        "tun.pcap",
        "phys.pcap",
        str(tmp_path),
    )
    assert outputs[0].pre_proxy.status == "failed"
    assert outputs[0].pre_proxy.error_code == "TSHARK_EXTRACT_FAILED"
    assert not list((tmp_path / connection_id).glob("*"))


def test_empty_extract_leaves_no_partial_file(tmp_path, monkeypatch):
    def empty(command, **kwargs):
        Path(command[-1]).write_bytes(b"x" * 24)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(
        "traffictracer.analyze.pcap_splitter.subprocess.run", empty
    )
    connection_id = "conn-" + "6" * 32
    outputs = split_flows_v2(
        _result([_flow(connection_id, "one")]),
        "tun.pcap",
        "phys.pcap",
        str(tmp_path),
    )
    assert outputs[0].pre_proxy.status == "empty"
    assert not list((tmp_path / connection_id).glob("*"))


def test_success_reports_metrics_and_atomically_renames(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        "traffictracer.analyze.pcap_splitter.subprocess.run",
        _successful_tshark(calls),
    )
    connection_id = "conn-" + "7" * 32
    output = split_flows_v2(
        _result([_flow(connection_id, "one")]),
        "tun.pcap",
        "phys.pcap",
        str(tmp_path),
    )[0]
    assert output.pre_proxy.packet_count == 2
    assert output.pre_proxy.byte_count == 130
    assert Path(output.pre_proxy.path).name == "pre.pcap"
    assert not list((tmp_path / connection_id).glob(".*.tmp"))


def test_invalid_split_mode_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="unsupported PCAP split mode"):
        split_flows_v2(
            _result([_flow("conn-" + "8" * 32, "one")]),
            "tun.pcap",
            "phys.pcap",
            str(tmp_path),
            split_mode="per_request",
        )
