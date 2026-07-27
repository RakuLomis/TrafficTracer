"""Correlation engine — matches NetLog 5-tuples to Mihomo connection events."""

from __future__ import annotations

from typing import NamedTuple

from .netlog import FiveTupleData, DomainConnections, _parse_addr
from .mihomo_log import MihomoConnection
from ..models import TransportConnection, VisitCorrelation, CorrelatedFlowV2


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


def correlate_v2(
    transport_conns: list[TransportConnection],
    mihomo_conns: dict[str, MihomoConnection],
    visit_url: str,
    domain: str,
    cdp_request_count: int = 0,
) -> VisitCorrelation:
    flows: list[CorrelatedFlowV2] = []

    for tc in transport_conns:
        mconn = _find_matching_mihomo_v2(tc, mihomo_conns)

        pre_src = f"{tc.src_ip}:{tc.src_port}" if tc.src_ip else ""
        pre_dst = f"{tc.dst_ip}:{tc.dst_port}" if tc.dst_ip else ""

        post_src = ""
        post_dst = ""
        if mconn and mconn.proxy_dial:
            out_ip, out_port = _parse_addr(mconn.proxy_dial.out_src)
            proxy_ip, proxy_port = _parse_addr(mconn.proxy_dial.proxy_addr)
            post_src = f"{out_ip}:{out_port}" if out_ip else ""
            post_dst = f"{proxy_ip}:{proxy_port}" if proxy_ip else ""
        elif mconn and mconn.connect:
            dst_ip, dst_port = _parse_addr(mconn.connect.dst)
            post_dst = f"{dst_ip}:{dst_port}" if dst_ip else ""

        if mconn is None:
            continue

        relation = _infer_relation(tc.url, domain)

        flows.append(CorrelatedFlowV2(
            url=tc.url,
            resource_type="",
            target_type="",
            relation=relation,
            pre_proxy_src=pre_src,
            pre_proxy_dst=pre_dst,
            post_proxy_src=post_src,
            post_proxy_dst=post_dst,
            protocol=tc.protocol,
            request_ids=list(tc.request_ids),
            connection_reused=False,
        ))

    return VisitCorrelation(
        visit_url=visit_url,
        domain=domain,
        flows=flows,
        cdp_request_count=cdp_request_count,
        netlog_connection_count=len(transport_conns),
    )


def _find_matching_mihomo_v2(
    tc: TransportConnection,
    mihomo_conns: dict[str, MihomoConnection],
) -> MihomoConnection | None:
    tc_src = f"{tc.src_ip}:{tc.src_port}"
    tc_dst = f"{tc.dst_ip}:{tc.dst_port}"

    for conn_id, mconn in mihomo_conns.items():
        if mconn.connect is None:
            continue
        if tc_src == mconn.connect.src and tc_dst == mconn.connect.dst:
            return mconn

    for conn_id, mconn in mihomo_conns.items():
        if mconn.connect is None:
            continue
        if tc_src == mconn.connect.src:
            return mconn

    return None


def _infer_relation(url: str, domain: str) -> str:
    from urllib.parse import urlparse
    try:
        host = urlparse(url).netloc.split(":")[0]
    except Exception:
        return "unknown"
    if domain.lower() in host.lower():
        return "same_site"
    return "cross_site"


