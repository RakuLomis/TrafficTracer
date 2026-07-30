"""pcap splitting — filter per-flow pcaps using tshark display filters."""

from __future__ import annotations

import subprocess
from pathlib import Path
from urllib.parse import urlparse

from ..utils import logger, ensure_dir
from ..models import FlowTuple, VisitCorrelation
from .correlator import CorrelationResult
from .netlog import FiveTupleData


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
    forward = (f"{src_field}.src=={flow.src_ip} and {proto}.srcport=={flow.src_port} and "
               f"{dst_field}.dst=={flow.dst_ip} and {proto}.dstport=={flow.dst_port}")
    reverse = (f"{dst_field}.src=={flow.dst_ip} and {proto}.srcport=={flow.dst_port} and "
               f"{src_field}.dst=={flow.src_ip} and {proto}.dstport=={flow.src_port}")
    return f"{proto} and (({forward}) or ({reverse}))"


def _build_filter_from_addr(src: str, dst: str) -> str:
    parts = []
    src_ip, src_port = _split_addr(src)
    dst_ip, dst_port = _split_addr(dst)

    addr = src_ip or dst_ip
    port = src_port or dst_port

    if addr and port:
        parts.append(
            f"(ip.addr=={addr} and (tcp.port=={port} or udp.port=={port}))"
        )
    elif addr:
        parts.append(f"ip.addr=={addr}")
    return " and ".join(parts)


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
    for flow in result.flows:
        rel_name = _sanitize_name(flow.name)
        flow_dir = ensure_dir(str(Path(output_base) / rel_name))

        pre_filter = build_tshark_filter(flow.pre_proxy, "src")
        if pre_filter:
            pre_path = str(Path(flow_dir) / "pre_proxy.pcap")
            _run_tshark_extract(tun_pcap, pre_filter, pre_path)

        post_filter = build_tshark_filter(flow.post_proxy, "src")
        if post_filter:
            post_path = str(Path(flow_dir) / "post_proxy.pcap")
            _run_tshark_extract(phys_pcap, post_filter, post_path)


def split_flows_v2(
    result: VisitCorrelation,
    tun_pcap: str,
    phys_pcap: str,
    output_base: str,
) -> None:
    for flow in result.flows:
        rel_name = _sanitize_name(flow.url)
        flow_dir = ensure_dir(str(Path(output_base) / rel_name))

        pre_filter = (build_flow_tuple_filter(flow.pre_flow) if flow.pre_flow and flow.pre_flow.complete
                      else _build_filter_from_addr(flow.pre_proxy_src, flow.pre_proxy_dst))
        if pre_filter:
            pre_path = str(Path(flow_dir) / "pre_proxy.pcap")
            _run_tshark_extract(tun_pcap, pre_filter, pre_path)

        post_filter = (build_flow_tuple_filter(flow.post_flow) if flow.post_flow and flow.post_flow.complete
                       else _build_filter_from_addr(flow.post_proxy_src, flow.post_proxy_dst))
        if post_filter:
            post_path = str(Path(flow_dir) / "post_proxy.pcap")
            _run_tshark_extract(phys_pcap, post_filter, post_path)


def _run_tshark_extract(input_pcap: str, display_filter: str,
                         output_path: str) -> None:
    cmd = ["tshark", "-r", input_pcap, "-Y", display_filter, "-w", output_path]
    logger.info("tshark: %s", " ".join(cmd))
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=False)


def _sanitize_name(name: str) -> str:
    import re
    name = name.replace("https://", "").replace("http://", "").rstrip("/")
    name = name.split("?")[0]
    name = re.sub(r'[<>\"|?*\\%]', "_", name)
    if len(name) > 120:
        name = name[:120]
    return name.rstrip("/_.")
