"""Analysis pipeline — CDP-first with domain-based fallback."""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path

from ..utils import logger, ensure_dir, setup_logging
from ..models import VisitCorrelation
from .netlog import extract_five_tuples, DomainConnections
from .mihomo_log import parse_tracing_log, parse_udp_tracing_log
from .correlator import correlate, correlate_v2, correlate_cdp_direct, CorrelationResult
from .pcap_splitter import split_flows, split_flows_v2
from .cdp_attribution import parse_cdp_attribution
from .netlog_transport import trace_transport


def _fix_netlog(path: str) -> None:
    with open(path, "r", encoding="utf-8") as f:
        data = f.read().rstrip()
    if data.endswith("}]"):
        fixed = data + "\n}\n"
    elif data.endswith("},"):
        fixed = data[:-1] + "\n]}\n"
    elif data.endswith("}"):
        fixed = data + "\n]}\n"
    else:
        fixed = data + "\n]}\n"
    json.loads(fixed)
    with open(path, "w", encoding="utf-8") as f:
        f.write(fixed)
    logger.info("Auto-fixed truncated NetLog: %s", path)


def run_analysis(session_dir: str) -> str:
    setup_logging()

    session = Path(session_dir)
    if not session.exists():
        raise FileNotFoundError(f"Session directory not found: {session_dir}")

    logs_dir = session / "logs"
    captures_dir = session / "captures"
    results_dir = ensure_dir(str(session / "results"))

    all_correlations: dict[str, dict] = {}

    for domain_dir in sorted(captures_dir.iterdir()):
        if not domain_dir.is_dir():
            continue

        domain = domain_dir.name

        for run_dir in sorted(domain_dir.glob("*")):
            if not run_dir.is_dir():
                continue
            run_tag = run_dir.name

            netlog_path = logs_dir / f"netlog_{domain}_{run_tag}.json"
            cdp_path = logs_dir / f"cdp_{domain}_{run_tag}.json"
            trace_path = logs_dir / f"mihomo_trace_{domain}_{run_tag}.jsonl"

            tag = f"{domain}_{run_tag}"

            if not netlog_path.exists():
                logger.warning("No NetLog for %s, skipping", tag)
                continue

            logger.info("Analyzing %s...", tag)

            run_mihomo_conns = parse_tracing_log(str(trace_path)) if trace_path.exists() else {}

            if cdp_path.exists():
                result_v2 = _analyze_cdp_path(
                    str(cdp_path), str(netlog_path), str(trace_path),
                    run_mihomo_conns, domain, tag,
                )
                if result_v2 is not None:
                    existing = all_correlations.get(domain)
                    if existing is None:
                        all_correlations[domain] = _result_v2_to_dict(result_v2)
                    else:
                        existing["flows"].extend(
                            _result_v2_to_dict(result_v2)["flows"]
                        )
                    _try_split_v2(result_v2, run_dir)
                    continue

            logger.info("No CDP data for %s, using domain-based fallback", tag)
            result_v1 = _analyze_domain_path(
                str(netlog_path), run_mihomo_conns, domain, tag,
            )
            if result_v1 is not None:
                v1_dict = {
                    "visit_url": "",
                    "domain": domain,
                    "flows": _result_to_dict(result_v1),
                    "cdp_request_count": 0,
                    "netlog_connection_count": 0,
                }
                existing = all_correlations.get(domain)
                if existing is None:
                    all_correlations[domain] = v1_dict
                else:
                    existing["flows"].extend(v1_dict["flows"])
                _try_split_v1(result_v1, run_dir)

    corr_path = str(results_dir / "correlation.json")
    with open(corr_path, "w", encoding="utf-8") as f:
        json.dump(all_correlations, f, indent=2, ensure_ascii=False)

    logger.info("Correlation results written to %s", corr_path)
    return corr_path


def _analyze_cdp_path(
    cdp_path: str,
    netlog_path: str,
    trace_path: str,
    mihomo_conns: dict,
    domain: str,
    tag: str,
) -> VisitCorrelation | None:
    try:
        with open(cdp_path, "r", encoding="utf-8") as f:
            raw_cdp = json.load(f)
        visit_url = raw_cdp.get("visit_url", "")
    except Exception as e:
        logger.error("Failed to read CDP data for %s: %s", tag, e)
        return None

    try:
        attributed = parse_cdp_attribution(cdp_path)
    except Exception as e:
        logger.error("Failed to parse CDP data for %s: %s", tag, e)
        return None

    try:
        transport_conns = trace_transport(attributed, netlog_path)
    except Exception:
        _fix_netlog(netlog_path)
        try:
            transport_conns = trace_transport(attributed, netlog_path)
        except Exception as e:
            logger.error("Failed to trace transport for %s: %s", tag, e)
            transport_conns = []

    result = correlate_v2(
        transport_conns, mihomo_conns,
        visit_url=visit_url,
        domain=domain,
        cdp_request_count=len(attributed),
    )

    covered_ids: set[str] = set()
    for flow in result.flows:
        covered_ids.update(flow.request_ids)

    udp_conns = None
    if os.path.exists(trace_path):
        try:
            udp_conns = parse_udp_tracing_log(trace_path)
            if udp_conns:
                logger.info("Parsed %d UDP connections for %s", len(udp_conns), tag)
        except Exception:
            pass

    cdp_direct_flows = correlate_cdp_direct(
        attributed, mihomo_conns, domain,
        covered_request_ids=covered_ids,
        udp_conns=udp_conns,
    )
    if cdp_direct_flows:
        logger.info("CDP-direct correlation added %d flows for %s",
                    len(cdp_direct_flows), tag)
        result.flows.extend(cdp_direct_flows)

    return result


def _analyze_domain_path(
    netlog_path: str,
    mihomo_conns: dict,
    domain: str,
    tag: str,
) -> CorrelationResult | None:
    try:
        netlog_conns = extract_five_tuples(netlog_path, domain)
    except Exception:
        _fix_netlog(netlog_path)
        try:
            netlog_conns = extract_five_tuples(netlog_path, domain)
        except Exception as e:
            logger.error("Failed to parse NetLog for %s: %s", tag, e)
            return None

    return correlate(netlog_conns, mihomo_conns, domain)


def _try_split_v2(result: VisitCorrelation, run_dir: Path) -> None:
    tun_pcap = str(run_dir / "tun.pcap")
    phys_pcap = str(run_dir / "phys.pcap")
    flows_base = str(run_dir / "flows")
    if os.path.exists(tun_pcap) and os.path.exists(phys_pcap):
        try:
            split_flows_v2(result, tun_pcap, phys_pcap, flows_base)
        except Exception as e:
            logger.error("pcap splitting failed: %s", e)


def _try_split_v1(result: CorrelationResult, run_dir: Path) -> None:
    tun_pcap = str(run_dir / "tun.pcap")
    phys_pcap = str(run_dir / "phys.pcap")
    flows_base = str(run_dir / "flows")
    if os.path.exists(tun_pcap) and os.path.exists(phys_pcap):
        try:
            split_flows(result, tun_pcap, phys_pcap, flows_base)
        except Exception as e:
            logger.error("pcap splitting failed: %s", e)


def _result_to_dict(result: CorrelationResult) -> list[dict]:
    return [
        {
            "name": f.name,
            "relation": f.relation,
            "pre_proxy": {
                "src": f"{f.pre_proxy.src_ip}:{f.pre_proxy.src_port}" if f.pre_proxy.src_ip else "",
                "dst": f"{f.pre_proxy.dst_ip}:{f.pre_proxy.dst_port}" if f.pre_proxy.dst_ip else "",
                "proto": f.pre_proxy.protocol,
            },
            "post_proxy": {
                "src": f"{f.post_proxy.src_ip}:{f.post_proxy.src_port}" if f.post_proxy.src_ip else "",
                "dst": f"{f.post_proxy.dst_ip}:{f.post_proxy.dst_port}" if f.post_proxy.dst_ip else "",
                "proto": f.post_proxy.protocol,
            },
        }
        for f in result.flows
    ]


def _result_v2_to_dict(result: VisitCorrelation) -> dict:
    return {
        "visit_url": result.visit_url,
        "domain": result.domain,
        "flows": [
            {
                "url": f.url,
                "resource_type": f.resource_type,
                "target_type": f.target_type,
                "relation": f.relation,
                "pre_proxy_src": f.pre_proxy_src,
                "pre_proxy_dst": f.pre_proxy_dst,
                "post_proxy_src": f.post_proxy_src,
                "post_proxy_dst": f.post_proxy_dst,
                "protocol": f.protocol,
                "request_ids": f.request_ids,
                "connection_reused": f.connection_reused,
                "pre_flow": asdict(f.pre_flow) if f.pre_flow else None,
                "post_flow": asdict(f.post_flow) if f.post_flow else None,
                "match_status": f.match_status,
                "match_confidence": f.match_confidence,
                "conn_id": f.conn_id,
                "outer_conn_id": f.outer_conn_id,
            }
            for f in result.flows
        ],
        "cdp_request_count": result.cdp_request_count,
        "netlog_connection_count": result.netlog_connection_count,
    }
