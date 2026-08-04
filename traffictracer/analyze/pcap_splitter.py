"""PCAP splitting with one atomic artifact set per stable connection."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
from uuid import uuid4
from typing import Any

from ..models import FlowTuple, VisitCorrelation
from ..utils import logger, ensure_dir
from .correlator import CorrelationResult
from .netlog import FiveTupleData


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


def _build_filter_from_addr(src: str, dst: str) -> str:
    src_ip, src_port = _split_addr(src)
    dst_ip, dst_port = _split_addr(dst)
    addr = src_ip or dst_ip
    port = src_port or dst_port
    if addr and port:
        family = "ipv6" if ":" in addr else "ip"
        return f"({family}.addr=={addr} and (tcp.port=={port} or udp.port=={port}))"
    if addr:
        family = "ipv6" if ":" in addr else "ip"
        return f"{family}.addr=={addr}"
    return ""


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

    outputs: list[ConnectionPcapResult] = []
    for connection_id, connection_flows in sorted(unique.items()):
        flow = max(
            connection_flows,
            key=lambda item: (
                bool(item.pre_flow and item.pre_flow.complete),
                bool(item.post_flow and item.post_flow.complete),
            ),
        )
        protocol = "udp" if flow.protocol.lower().startswith(("udp", "quic")) else "tcp"
        pre_filter = (
            build_flow_tuple_filter(flow.pre_flow)
            if flow.pre_flow and flow.pre_flow.complete
            else _build_filter_from_addr(flow.pre_proxy_src, flow.pre_proxy_dst)
        )
        post_filter = (
            build_flow_tuple_filter(flow.post_flow)
            if flow.post_flow and flow.post_flow.complete
            else _build_filter_from_addr(flow.post_proxy_src, flow.post_proxy_dst)
        )
        if split_mode == SPLIT_NONE:
            pre = PcapSideResult("not_requested", pre_filter)
            post = PcapSideResult("not_requested", post_filter)
        else:
            connection_dir = Path(output_base) / connection_id
            pre = _extract_side(
                tun_pcap, pre_filter, connection_dir / "pre.pcap",
                f"pcap-{connection_id[5:]}-pre",
            )
            post = _extract_side(
                phys_pcap, post_filter, connection_dir / "post.pcap",
                f"pcap-{connection_id[5:]}-post",
            )
        outputs.append(ConnectionPcapResult(
            connection_id=connection_id,
            protocol=protocol,
            request_ids=tuple(sorted({
                request_id
                for connection_flow in connection_flows
                for request_id in connection_flow.request_ids
            })),
            pre_proxy=pre,
            post_proxy=post,
        ))
    return outputs


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
