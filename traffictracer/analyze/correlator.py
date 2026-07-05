"""Correlation engine — matches NetLog 5-tuples to Mihomo connection events."""

from __future__ import annotations

from typing import NamedTuple

from .netlog import FiveTupleData, DomainConnections, _parse_addr
from .mihomo_log import MihomoConnection


class CorrelatedFlow(NamedTuple):
    name: str
    relation: str
    pre_proxy: FiveTupleData
    post_proxy: FiveTupleData


class CorrelationResult(NamedTuple):
    domain: str
    flows: list[CorrelatedFlow]


def correlate(
    netlog_conns: list[DomainConnections],
    mihomo_conns: dict[str, MihomoConnection],
    domain: str,
) -> CorrelationResult:
    flows: list[CorrelatedFlow] = []

    for dc in netlog_conns:
        for ft in dc.five_tuples:
            mconn = _find_matching_mihomo(ft, mihomo_conns)
            if mconn is None:
                continue

            pre_proxy = ft

            post_proxy = FiveTupleData(
                src_ip="", src_port=0,
                dst_ip="", dst_port=0,
                protocol="",
            )
            if mconn.proxy_dial:
                out_ip, out_port = _parse_addr(mconn.proxy_dial.out_src)
                proxy_ip, proxy_port = _parse_addr(mconn.proxy_dial.proxy_addr)
                post_proxy = FiveTupleData(
                    src_ip=out_ip, src_port=out_port,
                    dst_ip=proxy_ip, dst_port=proxy_port,
                    protocol="tcp",
                )
            elif mconn.connect:
                dst_ip, dst_port = _parse_addr(mconn.connect.dst)
                post_proxy = FiveTupleData(
                    src_ip="", src_port=0,
                    dst_ip=dst_ip, dst_port=dst_port,
                    protocol="tcp",
                )

            flows.append(CorrelatedFlow(
                name=dc.name,
                relation=dc.relation,
                pre_proxy=pre_proxy,
                post_proxy=post_proxy,
            ))

    return CorrelationResult(domain=domain, flows=flows)


def _find_matching_mihomo(
    ft: FiveTupleData,
    mihomo_conns: dict[str, MihomoConnection],
) -> MihomoConnection | None:
    netlog_src = f"{ft.src_ip}:{ft.src_port}"
    netlog_dst = f"{ft.dst_ip}:{ft.dst_port}"

    for conn_id, mconn in mihomo_conns.items():
        if mconn.connect is None:
            continue
        m_src = mconn.connect.src
        m_dst = mconn.connect.dst
        if netlog_src == m_src and netlog_dst == m_dst:
            return mconn

    for conn_id, mconn in mihomo_conns.items():
        if mconn.connect is None:
            continue
        m_src = mconn.connect.src
        m_dst = mconn.connect.dst
        if netlog_src == m_src or netlog_src == m_dst:
            return mconn
        if netlog_dst == m_src or netlog_dst == m_dst:
            return mconn

    return None


