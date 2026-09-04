"""Tests for pcap splitter filter generation."""

import sys
import json
import os
from pathlib import Path
import subprocess

import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.analyze.netlog import FiveTupleData
from traffictracer.analyze.pcap_splitter import (
    SPLIT_NONE,
    build_incomplete_flow_tuple_filter,
    build_tshark_filter,
    build_flow_tuple_filter,
    recover_post_flow_from_pcap,
    split_flows_v2,
    _sanitize_name,
    _unique_carrier_local_endpoint_filters,
)
from traffictracer.models import (
    CarrierBinding,
    CorrelatedFlowV2,
    FlowTerminal,
    FlowTuple,
    VisitCorrelation,
)


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


def test_incomplete_udp_filter_uses_ports_and_destination_not_unspecified_source():
    flow = FlowTuple(
        network="udp", src_ip="::", src_port=56571,
        dst_ip="101.227.12.8", dst_port=443, complete=False,
        source="dialer_socket",
    )

    display_filter = build_incomplete_flow_tuple_filter(flow)

    assert "ipv6.addr==::" not in display_filter
    assert "udp.srcport==56571" in display_filter
    assert "ip.dst==101.227.12.8" in display_filter
    assert "udp.dstport==56571" in display_filter


def test_recover_udp_post_source_from_unique_physical_tuple(monkeypatch):
    flow = FlowTuple(
        network="udp", src_ip="::", src_port=56571,
        dst_ip="101.227.12.8", dst_port=443, complete=False,
        source="dialer_socket", scope="post_proxy",
    )

    def run(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 0,
            stdout=(
                "192.168.5.11\t\t56571\t101.227.12.8\t\t443\n"
                "101.227.12.8\t\t443\t192.168.5.11\t\t56571\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "traffictracer.analyze.pcap_splitter.subprocess.run", run,
    )

    recovered, status = recover_post_flow_from_pcap("phys.pcap", flow)

    assert status == "recovered"
    assert recovered is not None
    assert recovered.complete is True
    assert recovered.src_ip == "192.168.5.11"
    assert recovered.key == (
        "udp|192.168.5.11:56571|101.227.12.8:443"
    )


def test_recover_udp_post_source_rejects_ambiguous_candidates(monkeypatch):
    flow = FlowTuple(
        network="udp", src_ip="", src_port=56571,
        dst_ip="101.227.12.8", dst_port=443, complete=False,
    )

    def run(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 0,
            stdout=(
                "192.168.5.11\t\t56571\t101.227.12.8\t\t443\n"
                "192.168.6.11\t\t56571\t101.227.12.8\t\t443\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "traffictracer.analyze.pcap_splitter.subprocess.run", run,
    )

    recovered, status = recover_post_flow_from_pcap("phys.pcap", flow)

    assert recovered is None
    assert status == "ambiguous"


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
    flow_dir = tmp_path / "0001__https_example.com_a"
    assert {path.name for path in tmp_path.iterdir()} == {flow_dir.name}
    assert (flow_dir / "pre.pcap").is_file()
    assert (flow_dir / "post.pcap").is_file()
    mapping = json.loads((flow_dir / "mapping.json").read_text(encoding="utf-8"))
    assert mapping["connection_id"] == first
    assert mapping["primary_url"] == "https://example.com/a"


def test_shared_hy2_carrier_is_extracted_once_and_referenced(tmp_path, monkeypatch):
    first = "conn-" + "1" * 32
    second = "conn-" + "2" * 32
    carrier_path = FlowTuple(
        "udp", "192.0.2.10", 55000, "203.0.113.20", 443,
        key="udp|192.0.2.10:55000|203.0.113.20:443",
        complete=True, source="dialer_socket", scope="physical", shared=True,
    )
    flows = [
        _flow(first, "request-1", url="https://example.com/a"),
        _flow(second, "request-2", url="https://example.com/b"),
    ]
    for flow in flows:
        flow.post_flow = carrier_path
        flow.post_proxy_src = carrier_path.src
        flow.post_proxy_dst = carrier_path.dst
        flow.carrier_binding = CarrierBinding(
            carrier_id="hy2-carrier-1",
            relation="reused",
            generation=1,
            protocol="hysteria2",
            paths=(carrier_path,),
        )
    calls = []
    monkeypatch.setattr(
        "traffictracer.analyze.pcap_splitter.subprocess.run",
        _successful_tshark(calls),
    )

    outputs = split_flows_v2(
        _result(flows), "tun.pcap", "phys.pcap", str(tmp_path)
    )

    assert len(outputs) == 2
    assert len([call for call in calls if "-w" in call]) == 3
    assert {item.carrier_id for item in outputs} == {"hy2-carrier-1"}
    assert all(item.post_proxy_shared for item in outputs)
    assert outputs[0].post_proxy.path == outputs[1].post_proxy.path
    carrier_file = (
        tmp_path / "carriers" / "carrier-hy2-carrier-1" / "post.pcap"
    )
    assert carrier_file.is_file()
    assert Path(outputs[0].post_proxy.path) == carrier_file


def test_shared_udp_carrier_retries_with_unique_local_endpoint(
    tmp_path, monkeypatch,
):
    connection_id = "conn-" + "b" * 32
    advertised = FlowTuple(
        "udp", "192.0.2.10", 55000, "203.0.113.20", 443,
        key="udp|192.0.2.10:55000|203.0.113.20:443",
        complete=True, source="dialer_socket", scope="physical", shared=True,
    )
    flow = _flow(connection_id, "request-1")
    flow.post_flow = advertised
    flow.carrier_binding = CarrierBinding(
        carrier_id="hy2-carrier-1", relation="reused", generation=1,
        protocol="hysteria2", paths=(advertised,),
    )
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if "-w" in command:
            output = Path(command[-1])
            display_filter = command[command.index("-Y") + 1]
            if "203.0.113.20" in display_filter:
                output.write_bytes(b"x" * 24)
            else:
                output.write_bytes(b"pcap" + b"x" * 32)
            return subprocess.CompletedProcess(command, 0)
        return subprocess.CompletedProcess(
            command, 0, stdout="60\n70\n", stderr="",
        )

    monkeypatch.setattr(
        "traffictracer.analyze.pcap_splitter.subprocess.run", run,
    )

    output = split_flows_v2(
        _result([flow]), "tun.pcap", "phys.pcap", str(tmp_path),
    )[0]

    assert output.post_proxy.status == "success"
    assert output.post_proxy.packet_count == 2
    assert "ip.addr==192.0.2.10" in output.post_proxy.display_filter
    assert "udp.port==55000" in output.post_proxy.display_filter
    post_extracts = [
        call for call in calls
        if "-w" in call and "carriers" in str(call[-1])
    ]
    assert len(post_extracts) == 2


def test_shared_udp_fallback_requires_session_unique_local_endpoint():
    path = FlowTuple(
        "udp", "192.0.2.10", 55000, "203.0.113.20", 443,
        complete=True, scope="physical", shared=True,
    )

    assert _unique_carrier_local_endpoint_filters({
        "carrier-one": (path,),
        "carrier-two": (path,),
    }) == {}


def test_local_endpoint_skips_post_pcap_as_not_applicable(tmp_path, monkeypatch):
    connection_id = "conn-" + "2" * 32
    flow = _flow(
        connection_id,
        "local.1",
        url="https://localhost.weixin.qq.com:14017/api",
    )
    flow.post_flow = None
    flow.post_proxy_src = ""
    flow.post_proxy_dst = "localhost.weixin.qq.com:14017"
    flow.terminal = FlowTerminal(
        status="dial_error",
        stage="dial",
        error="dial tcp 127.0.0.1:14017: connect: connection refused",
    )
    calls = []
    monkeypatch.setattr(
        "traffictracer.analyze.pcap_splitter.subprocess.run",
        _successful_tshark(calls),
    )

    outputs = split_flows_v2(
        _result([flow]), "tun.pcap", "phys.pcap", str(tmp_path),
    )

    assert outputs[0].pre_proxy.status == "success"
    assert outputs[0].post_proxy.status == "not_applicable"
    assert outputs[0].post_proxy.display_filter == ""
    assert len(calls) == 2
    assert not (tmp_path / "0001__https_localhost.weixin.qq.com_14017_api" / "post.pcap").exists()


def test_repeated_and_long_urls_create_one_bounded_resource_directory(
    tmp_path, monkeypatch,
):
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
    names = [path.name for path in tmp_path.iterdir()]
    assert len(names) == 1
    assert names[0].startswith("0001__https_example.com_segment")
    assert len(names[0].encode()) <= 255
    assert outputs[0].request_ids == ("one", "two")


def test_transport_retries_share_one_url_resource_directory(tmp_path, monkeypatch):
    tcp_id = "conn-" + "9" * 32
    quic_id = "conn-" + "a" * 32
    tcp = _flow(
        tcp_id, "media.1",
        url="https://media.example/videoplayback?id=v&rn=1&alr=yes",
    )
    quic = _flow(
        quic_id, "media.2",
        url="https://media.example/videoplayback?id=v&rn=2&alr=yes",
    )
    quic.protocol = "QUIC"
    quic.pre_flow = FlowTuple(
        "udp", quic.pre_flow.src_ip, quic.pre_flow.src_port,
        quic.pre_flow.dst_ip, quic.pre_flow.dst_port,
        key=quic.pre_flow.key, complete=True, source="netlog",
    )
    quic.post_flow = None
    quic.match_status = "ambiguous"
    calls = []
    monkeypatch.setattr(
        "traffictracer.analyze.pcap_splitter.subprocess.run",
        _successful_tshark(calls),
    )
    result = _result([tcp, quic])
    result.visit_url = ""

    outputs = split_flows_v2(
        result, "tun.pcap", "phys.pcap", str(tmp_path),
    )

    directories = list(tmp_path.iterdir())
    assert len(directories) == 1
    mapping = json.loads(
        (directories[0] / "mapping.json").read_text(encoding="utf-8")
    )
    assert mapping["canonical_connection_id"] == tcp_id
    assert [item["role"] for item in mapping["connections"]] == [
        "canonical", "alternative",
    ]
    assert (directories[0] / "pre.pcap").is_file()
    assert (directories[0] / "alternative-01-udp-pre.pcap").is_file()
    assert len(outputs) == 2


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
