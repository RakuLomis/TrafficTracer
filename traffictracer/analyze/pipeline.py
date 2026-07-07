"""Analysis pipeline — orchestrates NetLog parsing, Mihomo matching, and pcap splitting."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..utils import logger, ensure_dir, setup_logging
from .netlog import extract_five_tuples, DomainConnections
from .mihomo_log import parse_tracing_log
from .correlator import correlate, CorrelationResult
from .pcap_splitter import split_flows


def _fix_netlog(path: str) -> None:
    """Auto-fix truncated Chrome NetLog JSON by appending missing closing brackets."""
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
    import json
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

    all_correlations: dict[str, list[dict]] = {}

    trace_files = sorted(logs_dir.glob("mihomo_trace_*.jsonl"))
    mihomo_conns: dict = {}
    if trace_files:
        for tf in trace_files:
            mihomo_conns.update(parse_tracing_log(str(tf)))
    else:
        logger.warning("No Mihomo trace files found in %s", logs_dir)

    for domain_dir in sorted(captures_dir.iterdir()):
        if not domain_dir.is_dir():
            continue

        domain = domain_dir.name

        for run_dir in sorted(domain_dir.glob("*")):
            if not run_dir.is_dir():
                continue
            run_tag = run_dir.name

            netlog_path = logs_dir / f"netlog_{domain}_{run_tag}.json"

            tag = f"{domain}_{run_tag}"

            if not netlog_path.exists():
                logger.warning("No NetLog for %s, skipping", tag)
                continue

            logger.info("Analyzing %s...", tag)

            try:
                netlog_conns = extract_five_tuples(str(netlog_path), domain)
            except Exception:
                _fix_netlog(str(netlog_path))
                try:
                    netlog_conns = extract_five_tuples(str(netlog_path), domain)
                except Exception as e:
                    logger.error("Failed to parse NetLog for %s: %s", tag, e)
                    continue

            result = correlate(netlog_conns, mihomo_conns, domain)
            all_correlations.setdefault(domain, []).extend(_result_to_dict(result))

            tun_pcap = str(run_dir / "tun.pcap")
            phys_pcap = str(run_dir / "phys.pcap")
            flows_base = str(run_dir / "flows")

            if os.path.exists(tun_pcap) and os.path.exists(phys_pcap):
                try:
                    split_flows(result, tun_pcap, phys_pcap, flows_base)
                except Exception as e:
                    logger.error("pcap splitting failed for %s: %s", tag, e)

    corr_path = str(results_dir / "correlation.json")
    with open(corr_path, "w", encoding="utf-8") as f:
        json.dump(all_correlations, f, indent=2, ensure_ascii=False)

    logger.info("Correlation results written to %s", corr_path)
    return corr_path


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
