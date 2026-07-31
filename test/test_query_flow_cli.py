"""Compatibility and persisted-Session tests for query_flow.py."""

import json

import query_flow


def _flow(src_port):
    return {
        "network": "tcp",
        "src_ip": "198.18.0.1",
        "src_port": src_port,
        "dst_ip": "1.1.1.1",
        "dst_port": 443,
        "key": f"tcp|198.18.0.1:{src_port}|1.1.1.1:443",
        "complete": True,
        "scope": "logical",
        "source": "test",
        "shared": False,
    }


def test_query_flow_keeps_legacy_positional_trace_interface(tmp_path, capsys):
    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        json.dumps({"type": "tcp_connect", "conn_id": "c1", "pre_flow": _flow(40000)})
        + "\n",
        encoding="utf-8",
    )
    result = query_flow.main([
        str(trace), "tcp", "198.18.0.1", "40000", "1.1.1.1", "443", "--json",
    ])
    assert result == 0
    assert json.loads(capsys.readouterr().out)[0]["connection_id"] == "c1"


def test_query_flow_reads_persisted_session_index_with_pagination(tmp_path, capsys):
    results = tmp_path / "results"
    results.mkdir()
    items = [
        {"flow_id": "tcp:c1", "pre_flow": {key: value for key, value in _flow(40000).items() if key != "key"}},
        {"flow_id": "tcp:c2", "pre_flow": {key: value for key, value in _flow(40000).items() if key != "key"}},
        {"flow_id": "tcp:c3", "pre_flow": {key: value for key, value in _flow(40001).items() if key != "key"}},
    ]
    (results / "flow-index.json").write_text(
        json.dumps({"items": items}), encoding="utf-8"
    )
    result = query_flow.main([
        "--session", str(tmp_path),
        "--network", "tcp",
        "--src-ip", "198.18.0.1",
        "--src-port", "40000",
        "--dst-ip", "1.1.1.1",
        "--dst-port", "443",
        "--offset", "1",
        "--limit", "1",
        "--json",
    ])
    assert result == 0
    assert [item["flow_id"] for item in json.loads(capsys.readouterr().out)] == [
        "tcp:c2"
    ]
