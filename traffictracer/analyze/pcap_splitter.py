"""PCAP splitting with one atomic artifact set per stable connection."""

from __future__ import annotations

from dataclasses import dataclass, replace
import ipaddress
import os
from pathlib import Path
import subprocess
from uuid import uuid4
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from traffictracer.layout import safe_url_slug
from traffictracer.session.atomic import write_json_atomic

from ..models import FlowTuple, VisitCorrelation
from ..utils import logger, ensure_dir
from .correlator import CorrelationResult
from .netlog import FiveTupleData
from .request_observation import flow_targets_loopback


SPLIT_NONE = "none"
SPLIT_UNIQUE_CONNECTIONS = "unique_connections"


@dataclass(frozen=True)
class PcapSideResult:
    status: str
    display_filter: str
    packet_count: int = 0
    byte_count: int = 0
    artifact_id: str | None = None
    path: str | None = None
    error_code: str | None = None

    def to_dict(self) -> dict:
        payload = {
            "status": self.status,
            "display_filter": self.display_filter,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
        }
        if self.artifact_id is not None:
            payload["artifact_id"] = self.artifact_id
        if self.path is not None:
            payload["path"] = self.path
        if self.error_code is not None:
            payload["error_code"] = self.error_code
        return payload


@dataclass(frozen=True)
class ConnectionPcapResult:
    connection_id: str
    protocol: str
    request_ids: tuple[str, ...]
    pre_proxy: PcapSideResult
    post_proxy: PcapSideResult

    def to_dict(self) -> dict:
        return {
            "connection_id": self.connection_id,
            "protocol": self.protocol,
            "request_ids": list(self.request_ids),
            "pre_proxy": self.pre_proxy.to_dict(),
            "post_proxy": self.post_proxy.to_dict(),
        }


def build_tshark_filter(ft: FiveTupleData, direction: str) -> str:
    parts = []
    if ft.src_ip and ft.src_port:
        if direction == "src":
            parts.append(f"ip.src=={ft.src_ip} and tcp.srcport=={ft.src_port}")
        else:
            parts.append(f"ip.src=={ft.src_ip} and tcp.port=={ft.src_port}")
    elif ft.src_ip:
        parts.append(f"ip.addr=={ft.src_ip}")
    return " and ".join(parts) if parts else ""


def build_flow_tuple_filter(flow: FlowTuple) -> str:
    """Build an exact bidirectional TCP/UDP display filter."""
    proto = flow.network.lower()
    if not flow.complete or proto not in {"tcp", "udp"}:
        return ""
    src_field = "ipv6" if ":" in flow.src_ip else "ip"
    dst_field = "ipv6" if ":" in flow.dst_ip else "ip"
    forward = (
        f"{src_field}.src=={flow.src_ip} and {proto}.srcport=={flow.src_port} and "
        f"{dst_field}.dst=={flow.dst_ip} and {proto}.dstport=={flow.dst_port}"
    )
    reverse = (
        f"{dst_field}.src=={flow.dst_ip} and {proto}.srcport=={flow.dst_port} and "
        f"{src_field}.dst=={flow.src_ip} and {proto}.dstport=={flow.src_port}"
    )
    return f"{proto} and (({forward}) or ({reverse}))"


def build_incomplete_flow_tuple_filter(flow: FlowTuple) -> str:
    """Build a bidirectional filter when only the source IP is unavailable."""
    proto = flow.network.lower()
    if (
        proto not in {"tcp", "udp"}
        or not flow.src_port
        or not flow.dst_ip
        or not flow.dst_port
    ):
        return ""
    try:
        destination = ipaddress.ip_address(flow.dst_ip)
    except ValueError:
        return ""
    destination = getattr(destination, "ipv4_mapped", None) or destination
    if destination.is_unspecified:
        return ""
    field = "ipv6" if destination.version == 6 else "ip"
    forward = (
        f"{proto}.srcport=={flow.src_port} and "
        f"{field}.dst=={destination} and {proto}.dstport=={flow.dst_port}"
    )
    reverse = (
        f"{field}.src=={destination} and {proto}.srcport=={flow.dst_port} and "
        f"{proto}.dstport=={flow.src_port}"
    )
    return f"{proto} and (({forward}) or ({reverse}))"


def recover_post_flow_from_pcap(
    input_pcap: str,
    flow: FlowTuple,
) -> tuple[FlowTuple | None, str]:
    """Recover an unspecified UDP source IP from an unambiguous PCAP tuple."""
    if not _post_flow_needs_source_recovery(flow):
        return (flow, "not_needed")
    display_filter = build_incomplete_flow_tuple_filter(flow)
    if not display_filter:
        return (None, "insufficient_tuple")
    command = [
        "tshark", "-r", input_pcap, "-Y", display_filter,
        "-T", "fields", "-E", "separator=/t",
        "-e", "ip.src", "-e", "ipv6.src", "-e", f"{flow.network}.srcport",
        "-e", "ip.dst", "-e", "ipv6.dst", "-e", f"{flow.network}.dstport",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return (None, "tshark_unavailable")
    if completed.returncode != 0:
        return (None, "inspect_failed")

    destination = _normalize_ip(flow.dst_ip)
    candidates: set[str] = set()
    for line in completed.stdout.splitlines():
        fields = line.split("\t")
        fields.extend([""] * (6 - len(fields)))
        src_ip = _normalize_ip(fields[0] or fields[1])
        dst_ip = _normalize_ip(fields[3] or fields[4])
        src_port = _parse_port(fields[2])
        dst_port = _parse_port(fields[5])
        if (
            src_port == flow.src_port
            and dst_port == flow.dst_port
            and dst_ip == destination
            and src_ip
        ):
            candidates.add(src_ip)
        elif (
            dst_port == flow.src_port
            and src_port == flow.dst_port
            and src_ip == destination
            and dst_ip
        ):
            candidates.add(dst_ip)

    if not candidates:
        return (None, "not_found")
    if len(candidates) != 1:
        return (None, "ambiguous")
    source = candidates.pop()
    recovered = replace(
        flow,
        src_ip=source,
        key=_flow_key(
            flow.network, source, flow.src_port,
            destination, flow.dst_port,
        ),
        complete=True,
    )
    return (recovered, "recovered")


def _build_filter_from_addr(src: str, dst: str) -> str:
    src_ip, src_port = _split_addr(src)
    dst_ip, dst_port = _split_addr(dst)
    addr = (
        src_ip if _normalize_ip(src_ip) else
        dst_ip if _normalize_ip(dst_ip) else ""
    )
    port = src_port or dst_port
    if addr and port:
        family = "ipv6" if ":" in addr else "ip"
        return f"({family}.addr=={addr} and (tcp.port=={port} or udp.port=={port}))"
    if addr:
        family = "ipv6" if ":" in addr else "ip"
        return f"{family}.addr=={addr}"
    return ""


def _post_flow_needs_source_recovery(flow: FlowTuple) -> bool:
    return (
        flow.network.lower() == "udp"
        and bool(flow.src_port and flow.dst_ip and flow.dst_port)
        and not _normalize_ip(flow.src_ip)
    )


def _normalize_ip(value: str) -> str:
    if not value:
        return ""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return ""
    address = getattr(address, "ipv4_mapped", None) or address
    return "" if address.is_unspecified else str(address)


def _parse_port(value: str) -> int:
    try:
        port = int(value.split(",", 1)[0])
    except (TypeError, ValueError):
        return 0
    return port if 1 <= port <= 65535 else 0


def _flow_key(
    network: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
) -> str:
    src = f"[{src_ip}]:{src_port}" if ":" in src_ip else f"{src_ip}:{src_port}"
    dst = f"[{dst_ip}]:{dst_port}" if ":" in dst_ip else f"{dst_ip}:{dst_port}"
    return f"{network.lower()}|{src}|{dst}"


def _split_addr(addr: str) -> tuple[str, int]:
    if not addr:
        return ("", 0)
    if addr.startswith("["):
        idx = addr.rfind("]:")
        if idx == -1:
            return ("", 0)
        return (addr[1:idx], int(addr[idx + 2:]) if addr[idx + 2:].isdigit() else 0)
    idx = addr.rfind(":")
    if idx == -1:
        return (addr, 0)
    host = addr[:idx]
    port_str = addr[idx + 1:]
    return (host, int(port_str) if port_str.isdigit() else 0)


def split_flows(
    result: CorrelationResult,
    tun_pcap: str,
    phys_pcap: str,
    output_base: str,
) -> None:
    """Legacy v1 URL-based splitter retained for read/reanalysis compatibility."""
    for index, flow in enumerate(result.flows):
        flow_dir = ensure_dir(str(Path(output_base) / f"legacy-{index:04d}"))
        pre_filter = build_tshark_filter(flow.pre_proxy, "src")
        if pre_filter:
            _run_legacy_extract(tun_pcap, pre_filter, str(Path(flow_dir) / "pre_proxy.pcap"))
        post_filter = build_tshark_filter(flow.post_proxy, "src")
        if post_filter:
            _run_legacy_extract(phys_pcap, post_filter, str(Path(flow_dir) / "post_proxy.pcap"))


def split_flows_v2(
    result: VisitCorrelation,
    tun_pcap: str,
    phys_pcap: str,
    output_base: str,
    split_mode: str = SPLIT_UNIQUE_CONNECTIONS,
) -> list[ConnectionPcapResult]:
    if split_mode not in {SPLIT_NONE, SPLIT_UNIQUE_CONNECTIONS}:
        raise ValueError(f"unsupported PCAP split mode: {split_mode}")

    unique: dict[str, list[Any]] = {}
    for flow in result.flows:
        if flow.stable_connection_id:
            unique.setdefault(flow.stable_connection_id, []).append(flow)

    request_urls = {request.request_id: request.url for request in result.requests}
    entries: list[dict] = []
    for connection_id, connection_flows in sorted(unique.items()):
        flow = max(
            connection_flows,
            key=lambda item: (
                bool(item.pre_flow and item.pre_flow.complete),
                bool(item.post_flow and item.post_flow.complete),
            ),
        )
        post_not_applicable = any(
            flow_targets_loopback(item) for item in connection_flows
        )
        post_recovery_status = "not_applicable" if post_not_applicable else "not_needed"
        if not post_not_applicable and flow.post_flow is not None:
            recovered, post_recovery_status = recover_post_flow_from_pcap(
                phys_pcap, flow.post_flow,
            )
            if recovered is not None and post_recovery_status == "recovered":
                for connection_flow in connection_flows:
                    candidate = connection_flow.post_flow
                    if candidate is None or not _same_partial_flow(
                        candidate, flow.post_flow,
                    ):
                        continue
                    connection_flow.post_flow = recovered
                    connection_flow.post_proxy_src = recovered.src
                    connection_flow.post_proxy_dst = recovered.dst
                    if "post_source_recovered_from_phys_pcap" not in (
                        connection_flow.match_evidence
                    ):
                        connection_flow.match_evidence.append(
                            "post_source_recovered_from_phys_pcap"
                        )
                flow = max(
                    connection_flows,
                    key=lambda item: (
                        bool(item.pre_flow and item.pre_flow.complete),
                        bool(item.post_flow and item.post_flow.complete),
                    ),
                )
        protocol = (
            flow.pre_flow.network
            if flow.pre_flow and flow.pre_flow.network in {"tcp", "udp"}
            else (
                "udp"
                if flow.protocol.lower().startswith(("udp", "quic"))
                else "tcp"
            )
        )
        pre_filter = (
            build_flow_tuple_filter(flow.pre_flow)
            if flow.pre_flow and flow.pre_flow.complete
            else _build_filter_from_addr(flow.pre_proxy_src, flow.pre_proxy_dst)
        )
        if post_not_applicable:
            post_filter = ""
        elif flow.post_flow and flow.post_flow.complete:
            post_filter = build_flow_tuple_filter(flow.post_flow)
        elif flow.post_flow and _post_flow_needs_source_recovery(flow.post_flow):
            post_filter = build_incomplete_flow_tuple_filter(flow.post_flow)
        else:
            post_filter = _build_filter_from_addr(
                flow.post_proxy_src, flow.post_proxy_dst,
            )
        request_ids = sorted({
            request_id
            for connection_flow in connection_flows
            for request_id in connection_flow.request_ids
        })
        urls = sorted({
            request_urls[item]
            for item in request_ids
            if item in request_urls
        })
        primary_url = urls[0] if urls else (
            flow.url or result.visit_url or f"https://{result.domain}/"
        )
        entries.append({
            "connection_id": connection_id,
            "flow": flow,
            "protocol": protocol,
            "pre_filter": pre_filter,
            "post_filter": post_filter,
            "post_recovery_status": post_recovery_status,
            "post_not_applicable": post_not_applicable,
            "request_ids": request_ids,
            "urls": urls,
            "primary_url": primary_url,
        })

    if split_mode == SPLIT_NONE:
        return [ConnectionPcapResult(
            connection_id=entry["connection_id"],
            protocol=entry["protocol"],
            request_ids=tuple(entry["request_ids"]),
            pre_proxy=PcapSideResult(
                "not_requested", entry["pre_filter"],
            ),
            post_proxy=PcapSideResult(
                (
                    "not_applicable"
                    if entry["post_not_applicable"]
                    else "not_requested"
                ),
                entry["post_filter"],
            ),
        ) for entry in entries]

    groups: dict[str, list[dict]] = {}
    for entry in entries:
        groups.setdefault(
            _resource_key(entry["primary_url"]), [],
        ).append(entry)

    outputs: list[ConnectionPcapResult] = []
    for ordinal, resource_entries in enumerate(groups.values(), start=1):
        primary_url = resource_entries[0]["primary_url"]
        resource_dir = Path(output_base) / (
            f"{ordinal:04d}__{safe_url_slug(primary_url)}"
        )
        resource_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        extracted: list[tuple[dict, ConnectionPcapResult]] = []
        for candidate_ordinal, entry in enumerate(resource_entries, start=1):
            stem = f".candidate-{candidate_ordinal:02d}"
            connection_id = entry["connection_id"]
            pre = _extract_side(
                tun_pcap, entry["pre_filter"],
                resource_dir / f"{stem}-pre.pcap",
                f"pcap-{connection_id[5:]}-pre",
            )
            if entry["post_not_applicable"]:
                post = PcapSideResult("not_applicable", "")
            elif entry["post_recovery_status"] == "ambiguous":
                post = PcapSideResult(
                    "failed",
                    entry["post_filter"],
                    error_code="POST_FLOW_SOURCE_AMBIGUOUS",
                )
            else:
                post = _extract_side(
                    phys_pcap, entry["post_filter"],
                    resource_dir / f"{stem}-post.pcap",
                    f"pcap-{connection_id[5:]}-post",
                )
            extracted.append((entry, ConnectionPcapResult(
                connection_id=connection_id,
                protocol=entry["protocol"],
                request_ids=tuple(entry["request_ids"]),
                pre_proxy=pre,
                post_proxy=post,
            )))

        ranked = sorted(extracted, key=_resource_candidate_rank)
        canonical_id = ranked[0][1].connection_id
        finalized: dict[str, ConnectionPcapResult] = {}
        alternatives = 0
        for entry, item in extracted:
            canonical = item.connection_id == canonical_id
            if canonical:
                prefix = ""
            else:
                alternatives += 1
                prefix = f"alternative-{alternatives:02d}-{item.protocol}-"
            finalized[item.connection_id] = replace(
                item,
                pre_proxy=_rename_side(
                    item.pre_proxy,
                    resource_dir / f"{prefix}pre.pcap",
                ),
                post_proxy=_rename_side(
                    item.post_proxy,
                    resource_dir / f"{prefix}post.pcap",
                ),
            )
        ordered = [finalized[entry["connection_id"]] for entry in resource_entries]
        outputs.extend(ordered)
        write_json_atomic(resource_dir / "mapping.json", {
            "connection_id": canonical_id,
            "canonical_connection_id": canonical_id,
            "primary_url": primary_url,
            "urls": sorted({
                url for entry in resource_entries for url in entry["urls"]
            }),
            "request_ids": sorted({
                request_id
                for entry in resource_entries
                for request_id in entry["request_ids"]
            }),
            "connections": [
                {
                    "connection_id": item.connection_id,
                    "protocol": item.protocol,
                    "role": (
                        "canonical"
                        if item.connection_id == canonical_id
                        else "alternative"
                    ),
                    "pre_status": item.pre_proxy.status,
                    "post_status": item.post_proxy.status,
                }
                for item in ordered
            ],
        })
    return outputs


def _same_partial_flow(first: FlowTuple, second: FlowTuple) -> bool:
    return (
        first.network.lower() == second.network.lower()
        and first.src_port == second.src_port
        and _normalize_ip(first.dst_ip) == _normalize_ip(second.dst_ip)
        and first.dst_port == second.dst_port
    )


def _resource_candidate_rank(
    pair: tuple[dict, ConnectionPcapResult],
) -> tuple:
    entry, item = pair
    flow = entry["flow"]
    return (
        -int(item.pre_proxy.status == "success" and item.pre_proxy.packet_count > 0),
        -int(item.post_proxy.status == "success" and item.post_proxy.packet_count > 0),
        -int(flow.match_status == "matched"),
        -int(bool(flow.post_flow and flow.post_flow.complete)),
        item.connection_id,
    )


def _rename_side(side: PcapSideResult, destination: Path) -> PcapSideResult:
    if not side.path:
        return side
    source = Path(side.path)
    os.replace(source, destination)
    return replace(side, path=str(destination))


def _resource_key(url: str) -> str:
    parsed = urlsplit(url)
    query = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key not in {"rn", "alr"}
    ]
    return urlunsplit((
        parsed.scheme.lower(), parsed.netloc.lower(), parsed.path,
        urlencode(sorted(query)), "",
    ))


def _extract_side(
    input_pcap: str,
    display_filter: str,
    output_path: Path,
    artifact_id: str,
) -> PcapSideResult:
    if not display_filter:
        return PcapSideResult("not_requested", "")
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = output_path.with_name(f".{output_path.name}.{uuid4().hex}.tmp")
    command = ["tshark", "-r", input_pcap, "-Y", display_filter, "-w", str(temporary)]
    logger.info("tshark extract for %s", artifact_id)
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        temporary.unlink(missing_ok=True)
        return PcapSideResult(
            "failed",
            display_filter,
            error_code="TSHARK_UNAVAILABLE",
        )
    if completed.returncode != 0:
        temporary.unlink(missing_ok=True)
        return PcapSideResult("failed", display_filter, error_code="TSHARK_EXTRACT_FAILED")
    if not temporary.is_file() or temporary.stat().st_size <= 24:
        temporary.unlink(missing_ok=True)
        return PcapSideResult("empty", display_filter)
    try:
        metrics = subprocess.run(
            ["tshark", "-r", str(temporary), "-T", "fields", "-e", "frame.len"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        temporary.unlink(missing_ok=True)
        return PcapSideResult(
            "failed",
            display_filter,
            error_code="TSHARK_UNAVAILABLE",
        )
    if metrics.returncode != 0:
        temporary.unlink(missing_ok=True)
        return PcapSideResult("failed", display_filter, error_code="PCAP_INSPECT_FAILED")
    lengths = [int(line) for line in metrics.stdout.splitlines() if line.strip().isdigit()]
    if not lengths:
        temporary.unlink(missing_ok=True)
        return PcapSideResult("empty", display_filter)
    os.replace(temporary, output_path)
    return PcapSideResult(
        "success", display_filter,
        packet_count=len(lengths),
        byte_count=sum(lengths),
        artifact_id=artifact_id,
        path=str(output_path),
    )


def _run_legacy_extract(input_pcap: str, display_filter: str, output_path: str) -> None:
    subprocess.run(
        ["tshark", "-r", input_pcap, "-Y", display_filter, "-w", output_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )


def _sanitize_name(name: str) -> str:
    """Retain the v1 helper for callers reading legacy URL-based layouts."""
    import re

    name = name.replace("https://", "").replace("http://", "").rstrip("/")
    name = name.split("?")[0]
    name = re.sub(r'[<>"|?*\\%]', "_", name)
    if len(name) > 120:
        name = name[:120]
    return name.rstrip("/_.")
