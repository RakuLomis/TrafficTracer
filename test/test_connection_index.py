"""Tests for stable connection identity and layered candidate ranking."""

from traffictracer.analyze.connection_index import (
    rank_connection_candidates,
    stable_connection_id,
)
from traffictracer.analyze.mihomo_log import MihomoConnection, TcpConnect
from traffictracer.models import FlowTuple, TransportConnection


def _transport(**changes):
    values = {
        "netlog_source_id": 17,
        "url": "https://cdn.example.net/a.js",
        "src_ip": "198.18.0.1",
        "src_port": 44000,
        "dst_ip": "9.9.9.9",
        "dst_port": 443,
        "protocol": "HTTP2",
        "request_ids": ["1.1", "1.2"],
        "first_observed": 100.25,
    }
    values.update(changes)
    return TransportConnection(**values)


def _candidate(native_id, *, src="198.18.0.1:44000", dst="9.9.9.9:443", host="cdn.example.net", pre=None):
    return MihomoConnection(
        native_id,
        TcpConnect("", native_id, src, dst, host, pre_flow=pre),
        None,
        None,
    )


def test_stable_id_is_request_order_independent_and_observation_specific():
    first = _transport()
    reordered = _transport(request_ids=["1.2", "1.1"])
    assert stable_connection_id(first) == stable_connection_id(reordered)
    assert stable_connection_id(first).startswith("conn-")
    assert len(stable_connection_id(first)) == 37
    assert stable_connection_id(first) != stable_connection_id(_transport(first_observed=101.0))


def test_stable_id_extends_only_when_truncated_hash_collides(monkeypatch):
    import traffictracer.analyze.connection_index as module

    prefix = "a" * 32
    monkeypatch.setattr(
        module,
        "_stable_digest",
        lambda canonical: (
            prefix + ("b" * 8 if "100.25" in canonical else "c" * 8) + "d" * 24
        ),
    )
    registry = {}
    first = stable_connection_id(_transport(), collision_registry=registry)
    second = stable_connection_id(
        _transport(first_observed=101.0),
        collision_registry=registry,
    )
    assert first == "conn-" + prefix
    assert second == "conn-" + prefix + "-" + "c" * 8
    assert stable_connection_id(
        _transport(first_observed=101.0),
        collision_registry=registry,
    ) == second


def test_exact_pre_flow_wins_over_endpoint_and_host_fallbacks():
    transport = _transport()
    key = "tcp|198.18.0.1:44000|9.9.9.9:443"
    exact = FlowTuple("tcp", "198.18.0.1", 44000, "9.9.9.9", 443, key=key, complete=True)
    decision = rank_connection_candidates(
        transport,
        {
            "host": _candidate("host", src="10.0.0.1:1", dst="8.8.8.8:443"),
            "endpoint": _candidate("endpoint"),
            "exact": _candidate("exact", pre=exact),
        },
    )
    assert decision.status == "matched"
    assert decision.method == "exact_pre_flow"
    assert decision.selected_native_id == "exact"
    assert [candidate.native_id for candidate in decision.candidates] == ["exact", "endpoint", "host"]


def test_reused_exact_tuple_uses_time_and_preserves_ambiguity_without_it():
    key = "tcp|198.18.0.1:44000|9.9.9.9:443"
    pre = FlowTuple("tcp", "198.18.0.1", 44000, "9.9.9.9", 443, key=key, complete=True)
    near = MihomoConnection("near", TcpConnect("100.2", "near", "x", "y", "", pre_flow=pre), None, None)
    far = MihomoConnection("far", TcpConnect("130.0", "far", "x", "y", "", pre_flow=pre), None, None)
    decision = rank_connection_candidates(_transport(), {"near": near, "far": far})
    assert decision.status == "matched"
    assert decision.selected_native_id == "near"

    undated_a = _candidate("a", pre=pre)
    undated_b = _candidate("b", pre=pre)
    decision = rank_connection_candidates(_transport(), {"a": undated_a, "b": undated_b})
    assert decision.status == "ambiguous"
    assert decision.reason == "multiple_candidates"


def test_endpoint_and_host_fallbacks_require_usable_time_evidence():
    endpoint = _candidate("endpoint", src="10.0.0.1:1")
    endpoint = MihomoConnection(
        endpoint.conn_id,
        TcpConnect("100.4", endpoint.conn_id, endpoint.connect.src, endpoint.connect.dst, endpoint.connect.host),
        None, None,
    )
    decision = rank_connection_candidates(_transport(), {"endpoint": endpoint})
    assert decision.status == "matched"
    assert decision.method == "endpoint_time"
    assert decision.confidence == 0.78
    assert "time_delta_ms:150" in decision.candidates[0].evidence

    host = _candidate("host", src="10.0.0.1:1", dst="8.8.8.8:443")
    host = MihomoConnection(
        host.conn_id,
        TcpConnect("100.2", host.conn_id, host.connect.src, host.connect.dst, host.connect.host),
        None, None,
    )
    decision = rank_connection_candidates(_transport(), {"host": host})
    assert decision.status == "matched"
    assert decision.method == "host_time"


def test_equal_best_candidates_are_ambiguous_not_first_match():
    decision = rank_connection_candidates(
        _transport(),
        {"b": _candidate("b"), "a": _candidate("a")},
    )
    assert decision.status == "ambiguous"
    assert decision.selected_native_id is None
    assert decision.reason == "multiple_candidates"
    assert [candidate.native_id for candidate in decision.candidates[:2]] == ["a", "b"]


def test_quic_host_time_multiple_candidates_remain_ambiguous():
    transport = _transport(
        protocol="QUIC", src_ip="", src_port=0, dst_ip="", dst_port=0,
    )
    candidates = {}
    for native_id in ("quic-a", "quic-b"):
        candidates[native_id] = MihomoConnection(
            native_id,
            TcpConnect("100.2", native_id, "", "", "cdn.example.net"),
            None, None,
        )
    decision = rank_connection_candidates(transport, candidates)
    assert decision.status == "ambiguous"
    assert decision.method == "host_time"
    assert decision.reason == "multiple_candidates"


def test_exact_pre_flow_accepts_incomparable_monotonic_and_utc_clocks():
    key = "tcp|198.18.0.1:44000|9.9.9.9:443"
    pre = FlowTuple(
        "tcp", "198.18.0.1", 44000, "9.9.9.9", 443,
        key=key, complete=True,
    )
    candidate = MihomoConnection(
        "utc",
        TcpConnect(
            "2026-08-05T02:47:08.153618521Z", "utc",
            "198.18.0.1:44000", "cdn.example.net:443",
            "cdn.example.net", pre_flow=pre,
        ),
        None,
        None,
    )
    decision = rank_connection_candidates(
        _transport(first_observed=231263.345188),
        {"utc": candidate},
    )
    assert decision.status == "matched"
    assert decision.method == "exact_pre_flow"
    assert decision.selected_native_id == "utc"
    assert "time_unavailable" in decision.candidates[0].evidence


def test_no_candidate_is_explicitly_unmatched():
    decision = rank_connection_candidates(_transport(), {})
    assert decision.status == "unmatched"
    assert decision.reason == "no_candidate"
