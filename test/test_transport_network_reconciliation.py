"""Regression coverage for failed QUIC attempts followed by TCP fallback."""

from parser.constants import (
    SRC_QUIC_SESSION,
    SRC_TCP_STREAM_ATTEMPT,
    SRC_UDP_SOCKET,
)
from parser.dependency_graph import extract_five_tuple
from parser.source_entry import SourceEntry
from traffictracer.analyze.connection_index import rank_connection_candidates
from traffictracer.analyze.correlator import correlate_v2
from traffictracer.analyze.mihomo_log import (
    MihomoConnection,
    TcpConnect,
    TcpProxyDial,
)
from traffictracer.models import FlowTuple, TransportConnection


def _entry(source_id: int, source_type: int, description: str = "") -> SourceEntry:
    entry = SourceEntry(source_id=source_id, source_type=source_type)
    entry.description = description
    return entry


def _flow(network: str) -> FlowTuple:
    return FlowTuple(
        network,
        "198.18.0.1",
        39586,
        "198.18.0.39",
        443,
        key=f"{network}|198.18.0.1:39586|198.18.0.39:443",
        complete=True,
        source="metadata_snapshot",
        scope="logical",
    )


def _transport() -> TransportConnection:
    return TransportConnection(
        netlog_source_id=311,
        url="https://rr1---sn.example.googlevideo.com/videoplayback",
        src_ip="198.18.0.1",
        src_port=39586,
        dst_ip="198.18.0.39",
        dst_port=443,
        protocol="QUIC",
        request_ids=["media.1"],
        network="udp",
        attempted_protocols=["QUIC"],
    )


def _candidate(native_id: str) -> MihomoConnection:
    return MihomoConnection(
        native_id,
        TcpConnect(
            "2026-08-06T10:44:11.899853949Z",
            native_id,
            "198.18.0.1:39586",
            "rr1---sn.example.googlevideo.com:443",
            "rr1---sn.example.googlevideo.com",
            pre_flow=_flow("tcp"),
        ),
        TcpProxyDial(
            "2026-08-06T10:44:12.254997363Z",
            native_id,
            "US",
            "vless",
            "61.220.99.42:24191",
            "192.168.5.101:35506",
            post_flow=FlowTuple(
                "tcp",
                "192.168.5.101",
                35506,
                "61.220.99.42",
                24191,
                key="tcp|192.168.5.101:35506|61.220.99.42:24191",
                complete=True,
                source="dialer_socket",
                scope="physical",
            ),
        ),
        None,
    )


def test_tcp_socket_evidence_wins_over_retained_quic_attempt():
    tcp = _entry(1, SRC_TCP_STREAM_ATTEMPT, "198.18.0.39:443")
    quic = _entry(2, SRC_QUIC_SESSION)

    five_tuple = extract_five_tuple([tcp, quic])

    assert five_tuple.protocol == "QUIC"
    assert five_tuple.network == "tcp"
    assert five_tuple.attempted_protocols == ["QUIC"]


def test_true_quic_without_tcp_fallback_remains_udp():
    udp = _entry(1, SRC_UDP_SOCKET, "198.18.0.39:443")
    quic = _entry(2, SRC_QUIC_SESSION)

    five_tuple = extract_five_tuple([udp, quic])

    assert five_tuple.network == "udp"
    assert five_tuple.protocol == "QUIC"


def test_complete_endpoints_reconcile_quic_label_to_unique_tcp_flow():
    decision = rank_connection_candidates(_transport(), {"tcp-flow": _candidate("tcp-flow")})

    assert decision.status == "matched"
    assert decision.method == "transport_network_reconciled"
    assert decision.selected_native_id == "tcp-flow"
    assert "network_reconciled:udp->tcp" in decision.candidates[0].evidence


def test_endpoint_reconciliation_preserves_ambiguity_for_duplicate_tcp_flows():
    decision = rank_connection_candidates(
        _transport(),
        {"first": _candidate("first"), "second": _candidate("second")},
    )

    assert decision.status == "ambiguous"
    assert decision.reason == "multiple_candidates"
    assert decision.selected_native_id is None


def test_correlator_uses_reconciled_mihomo_tcp_and_post_proxy_tuple():
    result = correlate_v2(
        [_transport()],
        {"tcp-flow": _candidate("tcp-flow")},
        "https://www.youtube.com/watch?v=example",
        "youtube.com",
    )

    flow = result.flows[0]
    assert flow.match_status == "matched"
    assert flow.match_method == "transport_network_reconciled"
    assert flow.pre_flow == _flow("tcp")
    assert flow.post_flow is not None
    assert flow.post_flow.src == "192.168.5.101:35506"
    assert flow.post_flow.dst == "61.220.99.42:24191"
