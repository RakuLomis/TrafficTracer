"""Analysis pipeline — CDP-first with domain-based fallback."""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
import tempfile
from typing import Callable
from uuid import NAMESPACE_URL, uuid5

from ..jobs.cancellation import CancellationToken
from ..jobs.models import JobState
from ..jobs.progress import JobStage, ProgressReporter
from ..session.atomic import write_json_atomic
from ..utils import logger, ensure_dir, setup_logging
from ..models import VisitCorrelation
from .netlog import extract_five_tuples, DomainConnections
from .mihomo_log import (
    MihomoConnection,
    TcpClose,
    TcpConnect,
    TcpProxyDial,
    UdpConnection,
    parse_tracing_log,
    parse_udp_tracing_log,
    trace_snapshot_info,
)
from .correlator import correlate, correlate_v2, correlate_cdp_direct, CorrelationResult
from .pcap_splitter import (
    ConnectionPcapResult,
    SPLIT_NONE,
    SPLIT_UNIQUE_CONNECTIONS,
    split_flows,
    split_flows_v2,
)
from .cdp_attribution import parse_cdp_attribution
from .netlog_transport import trace_transport
from .connection_artifacts import (
    persist_connection_artifacts,
    persist_pcap_index,
)
from .legacy_projection import build_legacy_projection, merge_legacy_projection


def _fix_netlog(path: str) -> str:
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
    handle, repaired_path = tempfile.mkstemp(
        prefix="traffictracer-netlog-", suffix=".json"
    )
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        stream.write(fixed)
    logger.info("Using repaired temporary NetLog copy for %s", path)
    return repaired_path


def run_analysis(
    session_dir: str,
    *,
    progress: ProgressReporter | None = None,
    cancellation: CancellationToken | None = None,
    split_pcaps: bool = True,
    pcap_split_mode: str | None = None,
    overwrite: bool = True,
    output_dir: str | Path | None = None,
    published_output_dir: str | Path | None = None,
    analysis_generation_id: str | None = None,
) -> str:
    setup_logging()
    token = cancellation or CancellationToken()
    advance = _analysis_stage_emitter(progress, token)

    token.checkpoint()
    session = Path(session_dir)
    if not session.exists():
        raise FileNotFoundError(f"Session directory not found: {session_dir}")

    results_path = _safe_results_path(session, output_dir)
    published_results_path = _safe_results_path(
        session,
        published_output_dir if published_output_dir is not None else results_path,
    )
    results_dir = ensure_dir(str(results_path))

    all_correlations: dict[str, dict] = {}
    connection_results: list[VisitCorrelation] = []
    pcap_results: list[ConnectionPcapResult] = []
    split_mode = _normalize_split_mode(split_pcaps, pcap_split_mode)

    for domain, runs in _analysis_runs(session):
        for run_tag, run_dir, netlog_path, cdp_path, trace_path in runs:

            tag = f"{domain}_{run_tag}"

            if not netlog_path.exists():
                logger.warning("No NetLog for %s, skipping", tag)
                continue

            logger.info("Analyzing %s...", tag)

            advance(JobStage.ANALYZE_CDP, 0.1, tag)
            advance(JobStage.ANALYZE_NETLOG, 0.25, tag)
            advance(JobStage.ANALYZE_MIHOMO, 0.4, tag)
            trace_snapshot = trace_snapshot_info(str(trace_path)) if trace_path.exists() else {"cutoff_event_seq": None}
            trace_cutoff = trace_snapshot["cutoff_event_seq"]
            causal_tail = set(trace_snapshot.get("causal_tail_event_seqs", []))
            run_mihomo_conns = (
                parse_tracing_log(
                    str(trace_path),
                    max_event_seq=trace_cutoff,
                    include_event_seqs=causal_tail,
                )
                if trace_path.exists()
                else {}
            )
            token.checkpoint()

            advance(JobStage.ANALYZE_CORRELATE, 0.6, tag)
            if cdp_path.exists():
                result_v2 = _analyze_cdp_path(
                    str(cdp_path), str(netlog_path), str(trace_path),
                    run_mihomo_conns, domain, tag, trace_cutoff, causal_tail,
                )
                if result_v2 is not None:
                    connection_results.append(result_v2)
                    advance(JobStage.ANALYZE_SPLIT, 0.8, tag)
                    pcap_results.extend(
                        _try_split_v2(
                            result_v2,
                            run_dir,
                            Path(results_dir) / "pcap",
                            split_mode,
                        )
                    )
                    token.checkpoint()
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
                advance(JobStage.ANALYZE_SPLIT, 0.8, tag)
                if split_mode == SPLIT_UNIQUE_CONNECTIONS:
                    _try_split_v1(result_v1, run_dir)
                token.checkpoint()

    if connection_results:
        generation_id = analysis_generation_id or str(
            uuid5(NAMESPACE_URL, f"{session.resolve().as_uri()}#analysis-v2")
        )
        generated = persist_connection_artifacts(
            session,
            _session_id(session),
            connection_results,
            output_dir=results_path,
            generation_id=generation_id,
            pcap_results=pcap_results,
        )
        persist_pcap_index(
            session,
            _session_id(session),
            generated.generation_id,
            split_mode,
            pcap_results,
            output_dir=results_path,
            published_output_dir=published_results_path,
        )
        request_records = json.loads(
            generated.request_index.read_text(encoding="utf-8")
        ).get("items", [])
        connection_records = json.loads(
            generated.connection_index.read_text(encoding="utf-8")
        ).get("items", [])
        merge_legacy_projection(
            all_correlations,
            build_legacy_projection(
                connection_results, request_records, connection_records,
            ),
        )

    advance(JobStage.ANALYZE_WRITE, 0.95, "correlation.json")
    corr_path = str(results_dir / "correlation.json")
    if not overwrite and Path(corr_path).exists():
        raise FileExistsError(f"Analysis result already exists: {corr_path}")
    write_json_atomic(corr_path, all_correlations)
    token.checkpoint()

    logger.info("Correlation results written to %s", corr_path)
    return corr_path


def _analysis_runs(session: Path):
    """Discover normalized raw inputs while retaining legacy Session support."""

    raw = session / "raw"
    if raw.is_dir():
        domain = session.parent.name
        manifest_path = session / "manifest.json"
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            target = payload.get("target", {})
            if isinstance(target, dict) and isinstance(target.get("domain"), str):
                domain = target["domain"]
        except (OSError, json.JSONDecodeError):
            pass
        run_tag = session.name.split("__", 1)[0]
        return [
            (
                domain,
                [
                    (
                        run_tag,
                        raw,
                        raw / "netlog.json",
                        raw / "cdp.json",
                        raw / "mihomo-trace.jsonl",
                    )
                ],
            )
        ]

    logs = session / "logs"
    captures = session / "captures"
    output = []
    for domain_dir in sorted(captures.iterdir()):
        if not domain_dir.is_dir():
            continue
        runs = []
        for run_dir in sorted(path for path in domain_dir.iterdir() if path.is_dir()):
            tag = run_dir.name
            runs.append((tag, run_dir, logs / f"netlog_{domain_dir.name}_{tag}.json", logs / f"cdp_{domain_dir.name}_{tag}.json", logs / f"mihomo_trace_{domain_dir.name}_{tag}.jsonl"))
        output.append((domain_dir.name, runs))
    return output

def _safe_results_path(
    session: Path,
    output_dir: str | Path | None,
) -> Path:
    candidate = (
        Path(output_dir)
        if output_dir is not None
        else session / "results"
    )
    if not candidate.is_absolute():
        candidate = session / candidate
    resolved_session = session.resolve()
    resolved = candidate.resolve(strict=False)
    if resolved == resolved_session or not resolved.is_relative_to(resolved_session):
        raise ValueError("analysis output directory escapes the Session directory")
    return resolved


def _normalize_split_mode(split_pcaps: bool, explicit: str | None) -> str:
    mode = explicit or (
        SPLIT_UNIQUE_CONNECTIONS if split_pcaps else SPLIT_NONE
    )
    if mode not in {SPLIT_NONE, SPLIT_UNIQUE_CONNECTIONS}:
        raise ValueError(f"unsupported PCAP split mode: {mode}")
    return mode


def _session_id(session: Path) -> str:
    manifest_path = session / "manifest.json"
    if manifest_path.is_file():
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            value = payload.get("session_id")
            if isinstance(value, str) and value:
                return value
        except (OSError, json.JSONDecodeError):
            pass
    from uuid import NAMESPACE_URL, uuid5
    return str(uuid5(NAMESPACE_URL, session.resolve().as_uri()))


def _analysis_stage_emitter(
    progress: ProgressReporter | None,
    cancellation: CancellationToken,
) -> Callable[[JobStage, float, str], None]:
    ordered = [
        JobStage.ANALYZE_CDP,
        JobStage.ANALYZE_NETLOG,
        JobStage.ANALYZE_MIHOMO,
        JobStage.ANALYZE_CORRELATE,
        JobStage.ANALYZE_SPLIT,
        JobStage.ANALYZE_WRITE,
    ]
    order = {stage: index for index, stage in enumerate(ordered)}
    last_index = -1

    def advance(stage: JobStage, value: float, message: str) -> None:
        nonlocal last_index
        cancellation.checkpoint()
        index = order[stage]
        if progress is None or index <= last_index:
            return
        progress.emit(JobState.ANALYZING, stage, value, message)
        last_index = index

    return advance


def _analyze_cdp_path(
    cdp_path: str,
    netlog_path: str,
    trace_path: str,
    mihomo_conns: dict,
    domain: str,
    tag: str,
    trace_cutoff: int | None,
    causal_tail: set[int] | None = None,
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
        repaired_path = _fix_netlog(netlog_path)
        try:
            transport_conns = trace_transport(attributed, repaired_path)
        except Exception as e:
            logger.error("Failed to trace transport for %s: %s", tag, e)
            transport_conns = []
        finally:
            Path(repaired_path).unlink(missing_ok=True)

    udp_conns = None
    if os.path.exists(trace_path):
        try:
            udp_conns = parse_udp_tracing_log(
                trace_path,
                max_event_seq=trace_cutoff,
                include_event_seqs=causal_tail,
            )
            if udp_conns:
                logger.info("Parsed %d UDP connections for %s", len(udp_conns), tag)
        except Exception:
            pass

    transport_candidates = dict(mihomo_conns)
    transport_candidates.update(_udp_as_mihomo_candidates(udp_conns or {}))
    result = correlate_v2(
        transport_conns, transport_candidates,
        visit_url=visit_url,
        domain=domain,
        cdp_request_count=len(attributed),
    )

    result.requests = attributed

    covered_ids: set[str] = set()
    for flow in result.flows:
        covered_ids.update(flow.request_ids)

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


def _udp_as_mihomo_candidates(
    connections: dict[str, UdpConnection],
) -> dict[str, MihomoConnection]:
    output: dict[str, MihomoConnection] = {}
    for conn_key, connection in connections.items():
        native_id = conn_key
        connect = connection.connect
        proxy_dial = connection.proxy_dial
        close = connection.close
        output[native_id] = MihomoConnection(
            native_id,
            TcpConnect(
                connect.ts, native_id, connect.src, connect.dst, connect.host,
                pre_flow=connect.pre_flow, event_seq=connect.event_seq,
            ) if connect else None,
            TcpProxyDial(
                proxy_dial.ts, native_id, proxy_dial.proxy,
                proxy_dial.proxy_type, proxy_dial.proxy_addr,
                proxy_dial.out_src, out_dst=proxy_dial.out_dst,
                post_flow=proxy_dial.post_flow,
                outer_conn_id=proxy_dial.outer_conn_id,
                carrier_id=proxy_dial.carrier_id,
                carrier_relation=proxy_dial.carrier_relation,
                carrier_generation=proxy_dial.carrier_generation,
                carrier_protocol=proxy_dial.carrier_protocol,
                carrier_paths=proxy_dial.carrier_paths,
                event_seq=proxy_dial.event_seq,
                leaf_proxy=proxy_dial.leaf_proxy,
                leaf_proxy_type=proxy_dial.leaf_proxy_type,
                egress_outcome=proxy_dial.egress_outcome,
            ) if proxy_dial else None,
            TcpClose(
                close.ts, native_id, close.bytes_up, close.bytes_down,
                close.duration_ms, status=close.status, stage=close.stage,
                error=close.error, event_seq=close.event_seq,
            ) if close else None,
        )
    return output


def _analyze_domain_path(
    netlog_path: str,
    mihomo_conns: dict,
    domain: str,
    tag: str,
) -> CorrelationResult | None:
    try:
        netlog_conns = extract_five_tuples(netlog_path, domain)
    except Exception:
        repaired_path = _fix_netlog(netlog_path)
        try:
            netlog_conns = extract_five_tuples(repaired_path, domain)
        except Exception as e:
            logger.error("Failed to parse NetLog for %s: %s", tag, e)
            return None
        finally:
            Path(repaired_path).unlink(missing_ok=True)

    return correlate(netlog_conns, mihomo_conns, domain)


def _try_split_v2(
    result: VisitCorrelation,
    run_dir: Path,
    output_base: Path,
    split_mode: str,
) -> list[ConnectionPcapResult]:
    tun_pcap = str(run_dir / "tun.pcap")
    phys_pcap = str(run_dir / "phys.pcap")
    effective_mode = split_mode
    if (
        split_mode == SPLIT_UNIQUE_CONNECTIONS
        and not (os.path.exists(tun_pcap) and os.path.exists(phys_pcap))
    ):
        logger.warning(
            "raw PCAP pair missing for %s; derived PCAPs not requested",
            run_dir,
        )
        effective_mode = SPLIT_NONE
    try:
        return split_flows_v2(
            result,
            tun_pcap,
            phys_pcap,
            str(output_base),
            effective_mode,
        )
    except Exception as e:
        logger.error("pcap splitting failed: %s", e)
        return []


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
                "terminal": asdict(f.terminal) if f.terminal else None,
                "match_status": f.match_status,
                "match_confidence": f.match_confidence,
                "conn_id": f.conn_id,
                "netlog_source_id": f.netlog_source_id,
                "first_observed": f.first_observed,
                "last_observed": f.last_observed,
                "outer_conn_id": f.outer_conn_id,
                "stable_connection_id": f.stable_connection_id,
                "match_method": f.match_method,
                "match_candidates": f.match_candidates,
                "match_reason": f.match_reason,
                "match_evidence": f.match_evidence,
            }
            for f in result.flows
        ],
        "cdp_request_count": result.cdp_request_count,
        "netlog_connection_count": result.netlog_connection_count,
    }
