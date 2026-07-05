"""NetLog 5-tuple extraction — wraps parser/ for TrafficTracer analysis."""

from __future__ import annotations

from typing import NamedTuple

from parser.domain_analyzer import get_domain_connections


class FiveTupleData(NamedTuple):
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str


class DomainConnections(NamedTuple):
    name: str
    site: str
    relation: str
    five_tuples: list[FiveTupleData]


def extract_five_tuples(netlog_path: str, domain: str) -> list[DomainConnections]:
    results = get_domain_connections(netlog_path, domain)
    output: list[DomainConnections] = []

    for item in results:
        tuples: list[FiveTupleData] = []
        for detail in item.get("connection_detail", []):
            local = detail.get("local_address", "")
            remote = detail.get("remote_address", "")
            src_ip, src_port = _parse_addr(local)
            dst_ip, dst_port = _parse_addr(remote)
            tuples.append(FiveTupleData(
                src_ip=src_ip, src_port=src_port,
                dst_ip=dst_ip, dst_port=dst_port,
                protocol="",
            ))
        output.append(DomainConnections(
            name=item["name"],
            site=item["site"],
            relation=item["relation"],
            five_tuples=tuples,
        ))

    return output


def _parse_addr(addr: str) -> tuple[str, int]:
    if not addr:
        return ("", 0)
    if addr.startswith("["):
        idx = addr.rfind("]:")
        if idx == -1:
            return ("", 0)
        host = addr[1:idx]
        port_str = addr[idx + 2:]
    else:
        idx = addr.rfind(":")
        if idx == -1:
            return (addr, 0)
        host = addr[:idx]
        port_str = addr[idx + 1:]
    try:
        port = int(port_str)
    except ValueError:
        return (host, 0)
    return (host, port)
