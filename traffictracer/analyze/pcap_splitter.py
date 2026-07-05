"""pcap splitting — filter per-flow pcaps using tshark display filters."""

from __future__ import annotations

import subprocess
from pathlib import Path

from ..utils import logger, ensure_dir
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


def split_flows(
    result: CorrelationResult,
    tun_pcap: str,
    phys_pcap: str,
    output_base: str,
) -> None:
    for flow in result.flows:
        rel_name = _sanitize_name(flow.name)
        root_name = result.domain
        flow_dir = ensure_dir(str(Path(output_base) / root_name / rel_name))

        pre_filter = build_tshark_filter(flow.pre_proxy, "src")
        if pre_filter:
            pre_path = str(Path(flow_dir) / "pre_proxy.pcap")
            _run_tshark_extract(tun_pcap, pre_filter, pre_path)

        post_filter = build_tshark_filter(flow.post_proxy, "src")
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
