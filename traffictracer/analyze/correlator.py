"""Correlation engine — matches NetLog 5-tuples to Mihomo connection events."""

from __future__ import annotations

from typing import NamedTuple

from .netlog import FiveTupleData, DomainConnections, _parse_addr
from .mihomo_log import MihomoConnection, UdpConnect, UdpClose, UdpConnection
from ..models import AttributedRequest, TransportConnection, VisitCorrelation, CorrelatedFlowV2


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
        normalized_key = _flow_key("tcp", tc.src_ip, tc.src_port, tc.dst_ip, tc.dst_port)
        exact = bool(mconn and mconn.connect and mconn.connect.pre_flow and
                     mconn.connect.pre_flow.key == normalized_key)

        pre_src = f"{tc.src_ip}:{tc.src_port}" if tc.src_ip else ""
        pre_dst = f"{tc.dst_ip}:{tc.dst_port}" if tc.dst_ip else ""

        post_src = ""
        post_dst = ""
        if mconn and mconn.proxy_dial and mconn.proxy_dial.post_flow:
            post_src = mconn.proxy_dial.post_flow.src
            post_dst = mconn.proxy_dial.post_flow.dst
        elif mconn and mconn.proxy_dial:
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
            pre_flow=mconn.connect.pre_flow if mconn.connect else None,
            post_flow=mconn.proxy_dial.post_flow if mconn.proxy_dial else None,
            match_status="exact" if exact else "legacy",
            match_confidence=1.0 if exact else 0.5,
            conn_id=mconn.conn_id,
            outer_conn_id=mconn.proxy_dial.outer_conn_id if mconn.proxy_dial else "",
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
    normalized_key = _flow_key("tcp", tc.src_ip, tc.src_port, tc.dst_ip, tc.dst_port)
    for mconn in mihomo_conns.values():
        flow = mconn.connect.pre_flow if mconn.connect else None
        if flow and flow.complete and flow.key == normalized_key:
            return mconn


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


def correlate_cdp_direct(
    requests: list[AttributedRequest],
    mihomo_conns: dict[str, MihomoConnection],
    domain: str,
    covered_request_ids: set[str] | None = None,
    udp_conns: dict[str, UdpConnection] | dict[str, tuple[UdpConnect, UdpClose | None]] | None = None,
) -> list[CorrelatedFlowV2]:
    if covered_request_ids is None:
        covered_request_ids = set()

    endpoints: dict[str, list[AttributedRequest]] = {}
    for req in requests:
        if req.request_id in covered_request_ids:
            continue
        if not req.remote_ip or not req.remote_port:
            continue
        key = f"{req.remote_ip}:{req.remote_port}"
        endpoints.setdefault(key, []).append(req)

    mihomo_by_dst: dict[str, list[MihomoConnection]] = {}
    for mconn in mihomo_conns.values():
        if mconn.connect is None:
            continue
        dst = mconn.connect.dst
        mihomo_by_dst.setdefault(dst, []).append(mconn)

    flows: list[CorrelatedFlowV2] = []
    matched_rids: set[str] = set()

    for endpoint, reqs in endpoints.items():
        candidates = mihomo_by_dst.get(endpoint, [])
        if not candidates:
            continue

        mconn = candidates[0]

        pre_src = mconn.connect.src if mconn.connect else ""
        pre_dst = endpoint

        post_src = ""
        post_dst = ""
        if mconn.proxy_dial:
            out_ip, out_port = _parse_addr(mconn.proxy_dial.out_src)
            proxy_ip, proxy_port = _parse_addr(mconn.proxy_dial.proxy_addr)
            post_src = f"{out_ip}:{out_port}" if out_ip else ""
            post_dst = f"{proxy_ip}:{proxy_port}" if proxy_ip else ""
        elif mconn.connect:
            dst_ip, dst_port = _parse_addr(mconn.connect.dst)
            post_dst = f"{dst_ip}:{dst_port}" if dst_ip else ""

        rep = reqs[0]
        relation = _infer_relation(rep.url, domain)
        rids = [r.request_id for r in reqs]
        matched_rids.update(rids)

        flows.append(CorrelatedFlowV2(
            url=rep.url,
            resource_type=rep.resource_type,
            target_type=rep.target_type,
            relation=relation,
            pre_proxy_src=pre_src,
            pre_proxy_dst=pre_dst,
            post_proxy_src=post_src,
            post_proxy_dst=post_dst,
            protocol="QUIC" if rep.connection_reused else "",
            request_ids=rids,
            connection_reused=rep.connection_reused,
        ))

    if udp_conns:
        flows.extend(_correlate_cdp_udp(requests, udp_conns, domain, covered_request_ids | matched_rids))

    return flows


def _correlate_cdp_udp(
    requests: list[AttributedRequest],
    udp_conns: dict[str, UdpConnection] | dict[str, tuple[UdpConnect, UdpClose | None]],
    domain: str,
    covered_request_ids: set[str],
) -> list[CorrelatedFlowV2]:
    from urllib.parse import urlparse

    udp_by_host: dict[str, list[UdpConnect]] = {}
    rich_by_connect: dict[int, UdpConnection] = {}
    for conn_key, value in udp_conns.items():
        if isinstance(value, UdpConnection):
            uc = value.connect
            if uc is None:
                continue
            rich_by_connect[id(uc)] = value
        else:
            uc, _ = value
        host = uc.host
        if host:
            udp_by_host.setdefault(host, []).append(uc)

    host_requests: dict[str, list[AttributedRequest]] = {}
    for req in requests:
        if req.request_id in covered_request_ids:
            continue
        host = urlparse(req.url).netloc.split(":")[0]
        if not host:
            continue
        host_requests.setdefault(host, []).append(req)

    flows: list[CorrelatedFlowV2] = []
    for host, reqs in host_requests.items():
        uc_list = udp_by_host.get(host, [])
        if not uc_list:
            continue

        uc = uc_list[0]
        rich = rich_by_connect.get(id(uc))
        pre_flow = uc.pre_flow
        post_flow = rich.proxy_dial.post_flow if rich and rich.proxy_dial else None
        pre_src = pre_flow.src if pre_flow else uc.src
        pre_dst = pre_flow.dst if pre_flow else uc.dst
        relation = _infer_relation(reqs[0].url, domain)

        flows.append(CorrelatedFlowV2(
            url=reqs[0].url,
            resource_type=reqs[0].resource_type,
            target_type=reqs[0].target_type,
            relation=relation,
            pre_proxy_src=pre_src,
            pre_proxy_dst=pre_dst,
            post_proxy_src=post_flow.src if post_flow else "",
            post_proxy_dst=post_flow.dst if post_flow else pre_dst,
            protocol="QUIC",
            request_ids=[r.request_id for r in reqs],
            connection_reused=reqs[0].connection_reused,
            pre_flow=pre_flow,
            post_flow=post_flow,
            match_status="host_fallback",
            match_confidence=0.35,
            conn_id=rich.conn_key if rich else uc.conn_key,
            outer_conn_id=rich.proxy_dial.outer_conn_id if rich and rich.proxy_dial else "",
        ))

    return flows


def _flow_key(network: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
    if not (src_ip and src_port and dst_ip and dst_port):
        return ""
    src = f"[{src_ip}]:{src_port}" if ":" in src_ip else f"{src_ip}:{src_port}"
    dst = f"[{dst_ip}]:{dst_port}" if ":" in dst_ip else f"{dst_ip}:{dst_port}"
    return f"{network.lower()}|{src}|{dst}"


def _infer_relation(url: str, domain: str) -> str:
    from urllib.parse import urlparse
    try:
        host = urlparse(url).netloc.split(":")[0]
    except Exception:
        return "unknown"
    if domain.lower() in host.lower():
        return "same_site"
    return "cross_site"


