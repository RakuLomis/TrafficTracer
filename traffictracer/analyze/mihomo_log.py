"""Mihomo tracing JSONL log parser for TrafficTracer analysis."""

from __future__ import annotations

import json
from typing import NamedTuple


class TcpConnect(NamedTuple):
    ts: str
    conn_id: str
    src: str
    dst: str
    host: str


class TcpProxyDial(NamedTuple):
    ts: str
    conn_id: str
    proxy: str
    proxy_type: str
    proxy_addr: str
    out_src: str


class TcpClose(NamedTuple):
    ts: str
    conn_id: str
    bytes_up: int
    bytes_down: int
    duration_ms: int


class MihomoConnection(NamedTuple):
    conn_id: str
    connect: TcpConnect | None
    proxy_dial: TcpProxyDial | None
    close: TcpClose | None


def parse_tracing_log(path: str) -> dict[str, MihomoConnection]:
    connections: dict[str, dict[str, TcpConnect | TcpProxyDial | TcpClose | None]] = {}

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            etype = event.get("type", "")
            conn_id = event.get("conn_id", "")
            if not conn_id:
                continue

            if conn_id not in connections:
                connections[conn_id] = {
                    "connect": None, "proxy_dial": None, "close": None,
                }

            if etype == "tcp_connect":
                connections[conn_id]["connect"] = TcpConnect(
                    ts=event.get("ts", ""),
                    conn_id=conn_id,
                    src=event.get("src", ""),
                    dst=event.get("dst", ""),
                    host=event.get("host", ""),
                )
            elif etype == "tcp_proxy_dial":
                connections[conn_id]["proxy_dial"] = TcpProxyDial(
                    ts=event.get("ts", ""),
                    conn_id=conn_id,
                    proxy=event.get("proxy", ""),
                    proxy_type=event.get("proxy_type", ""),
                    proxy_addr=event.get("proxy_addr", ""),
                    out_src=event.get("out_src", ""),
                )
            elif etype == "tcp_close":
                connections[conn_id]["close"] = TcpClose(
                    ts=event.get("ts", ""),
                    conn_id=conn_id,
                    bytes_up=event.get("bytes_up", 0),
                    bytes_down=event.get("bytes_down", 0),
                    duration_ms=event.get("duration_ms", 0),
                )

    return {
        cid: MihomoConnection(
            conn_id=cid,
            connect=conn["connect"],
            proxy_dial=conn["proxy_dial"],
            close=conn["close"],
        )
        for cid, conn in connections.items()
    }
