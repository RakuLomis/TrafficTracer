"""Analysis pipeline — CDP-first with domain-based fallback."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..utils import logger, ensure_dir, setup_logging
from ..models import VisitCorrelation
from .netlog import extract_five_tuples, DomainConnections
from .mihomo_log import parse_tracing_log
from .correlator import correlate, correlate_v2, CorrelationResult
from .pcap_splitter import split_flows
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
                    str(cdp_path), str(netlog_path), run_mihomo_conns, domain, tag,
                )
                if result_v2 is not None:
                    existing = all_correlations.get(domain)
                    if existing is None:
                        all_correlations[domain] = _result_v2_to_dict(result_v2)
                    else:
                        existing["flows"].extend(
                            _result_v2_to_dict(result_v2)["flows"]
                        )
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

    corr_path = str(results_dir / "correlation.json")
    with open(corr_path, "w", encoding="utf-8") as f:
        json.dump(all_correlations, f, indent=2, ensure_ascii=False)

    logger.info("Correlation results written to %s", corr_path)
    return corr_path


def _analyze_cdp_path(
    cdp_path: str,
    netlog_path: str,
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
            return None

    return correlate_v2(
        transport_conns, mihomo_conns,
        visit_url=visit_url,
        domain=domain,
        cdp_request_count=len(attributed),
    )


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
            }
            for f in result.flows
        ],
        "cdp_request_count": result.cdp_request_count,
        "netlog_connection_count": result.netlog_connection_count,
    }
