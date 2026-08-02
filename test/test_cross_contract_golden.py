"""Python side of the shared Mihomo tracing golden contract."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from traffictracer.analyze.mihomo_log import (
    parse_tracing_log,
    parse_udp_tracing_log,
)
from traffictracer.version import MIHOMO_EVENT_SCHEMA_VERSION


GOLDEN = Path(__file__).parent / "fixtures" / "tracing"


def _endpoint(address: str, port: int) -> str:
    parsed = ipaddress.ip_address(address)
    return f"[{parsed}]:{port}" if parsed.version == 6 else f"{parsed}:{port}"


def test_shared_tracing_golden_covers_all_contract_cases() -> None:
    coverage = {
        "tcp": False,
        "udp": False,
        "ipv4": False,
        "ipv6": False,
        "shared": False,
        "error": False,
    }
    paths = sorted(GOLDEN.glob("*.jsonl"))
    assert paths
    for path in paths:
        previous = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            assert event["schema_version"] == MIHOMO_EVENT_SCHEMA_VERSION
            assert event["session_id"]
            assert event["event_seq"] > previous
            previous = event["event_seq"]
            coverage[event["network"]] = True
            coverage["error"] |= (
                event.get("status") == "dial_error" and bool(event.get("error"))
            )
            for name in ("pre_flow", "post_flow"):
                flow = event.get(name)
                if flow is None:
                    continue
                for address in (flow["src_ip"], flow["dst_ip"]):
                    coverage[f"ipv{ipaddress.ip_address(address).version}"] = True
                coverage["shared"] |= flow["shared"]
                if flow["complete"]:
                    expected = (
                        f"{flow['network']}|"
                        f"{_endpoint(flow['src_ip'], flow['src_port'])}|"
                        f"{_endpoint(flow['dst_ip'], flow['dst_port'])}"
                    )
                    assert flow["key"] == expected
    assert all(coverage.values()), coverage


def test_shared_tracing_golden_is_consumed_by_python_flow_parsers() -> None:
    tcp = parse_tracing_log(str(GOLDEN / "tcp-ipv4.jsonl"))
    assert tcp["tcp-ipv4-1"].connect.pre_flow.key.startswith("tcp|")
    assert tcp["tcp-ipv4-1"].proxy_dial.post_flow.scope == "post_proxy"

    udp = parse_udp_tracing_log(str(GOLDEN / "udp-ipv6.jsonl"))
    assert udp["udp-ipv6-1"].connect.pre_flow.key.startswith("udp|[")
    assert udp["udp-ipv6-1"].proxy_dial.post_flow.dst_ip == "2001:db8:1::20"

    failed = parse_tracing_log(str(GOLDEN / "dial-error.jsonl"))
    assert failed["tcp-error-1"].close.status == "dial_error"
    assert failed["tcp-error-1"].close.error == "connection refused"
