"""pcap splitting — filter per-flow pcaps using tshark display filters."""

from __future__ import annotations

import subprocess
from pathlib import Path
from urllib.parse import urlparse

from ..utils import logger, ensure_dir
from ..models import VisitCorrelation
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


def _build_filter_from_addr(src: str, dst: str) -> str:
    parts = []
    src_ip, src_port = _split_addr(src)
    dst_ip, dst_port = _split_addr(dst)
    if src_ip and src_port:
        parts.append(f"ip.addr=={src_ip} and tcp.port=={src_port}")
    elif dst_ip and dst_port:
        parts.append(f"ip.addr=={dst_ip} and tcp.port=={dst_port}")
    elif dst_ip:
        parts.append(f"ip.addr=={dst_ip}")
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

        pre_filter = _build_filter_from_addr(flow.pre_proxy_src, flow.pre_proxy_dst)
        if pre_filter:
            pre_path = str(Path(flow_dir) / "pre_proxy.pcap")
            _run_tshark_extract(tun_pcap, pre_filter, pre_path)

        post_filter = _build_filter_from_addr(flow.post_proxy_src, flow.post_proxy_dst)
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
    return name.replace("https://", "").replace("http://", "").rstrip("/")
