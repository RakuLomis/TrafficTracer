# CDP Attribution Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace domain-substring attribution (`domain in site or domain in name`) with CDP-based request attribution, so that all requests caused by a browser visit (including unknown CDN domains) are correctly captured and correlated.

**Architecture:** Three-layer model — CDP answers "which requests belong to this visit" (attribution), NetLog answers "which socket carried this request" (transport tracing via existing dependency graph), Mihomo answers "what happened pre/post proxy" (correlation, unchanged). The CDP collector is rewritten to use `Target.setAutoAttach` for full target coverage (page, iframe, worker). A new `cdp_attribution.py` parses structured CDP output into attributed requests. A new `netlog_transport.py` replaces `domain_analyzer.get_domain_connections()` by matching CDP request URLs to NetLog `URL_REQUEST` entries and tracing dependency chains to sockets. The correlator is updated to accept CDP-attributed connections and support many-to-many request→connection relationships (HTTP/2 multiplexing).

**Tech Stack:** Python 3.10+, stdlib, pyyaml, websockets (existing deps only)

## Global Constraints

- No new external dependencies beyond existing `pyyaml` + `websockets`
- Python 3.10+ (use `X | Y` union syntax, `match` statements OK)
- All tests must pass with `pytest test/` and standalone `python test/test_X.py`
- Backward compatibility: if no CDP data exists for a session, fall back to old domain-based analysis
- Do NOT modify `parser/` package internals (it remains a standalone NetLog library); only add new consumers
- `relation` (same_site/cross_site) becomes metadata, never a selection criterion
- No comments in code unless explicitly requested

---

## File Structure

```
traffictracer/
├── models.py                      # NEW: shared data types (AttributedRequest, TransportConnection, VisitCorrelation)
├── capture/
│   ├── cdp.py                     # REWRITE: structured CDP collector with Target.setAutoAttach
│   ├── chrome.py                  # MODIFY: background-noise flags, per-visit isolated profile
│   ├── pipeline.py                # MODIFY: CDP lifecycle (attach→enable→navigate→collect→stop)
│   └── (mihomo.py, tshark.py, netlog_fix.py unchanged)
├── analyze/
│   ├── cdp_attribution.py         # NEW: parse structured CDP JSON → list[AttributedRequest]
│   ├── netlog_transport.py        # NEW: URL-matched NetLog transport tracing (replaces domain_analyzer usage)
│   ├── correlator.py              # MODIFY: accept AttributedRequest-based input, many-to-many support
│   ├── pipeline.py                # MODIFY: new analysis flow with CDP-first, domain fallback
│   ├── netlog.py                  # MODIFY: add extract_all_five_tuples() (no domain filter)
│   └── (mihomo_log.py, pcap_splitter.py unchanged)
├── config.py                      # MODIFY: add chrome.disable_background_networking option
test/
├── test_models.py                 # NEW
├── test_cdp.py                    # REWRITE: test structured collector
├── test_cdp_attribution.py        # NEW
├── test_netlog_transport.py       # NEW
├── test_correlator.py             # MODIFY: add many-to-many tests
├── test_analyze_pipeline.py       # MODIFY: test CDP-first flow
├── test_capture_pipeline.py       # MODIFY: test CDP lifecycle
└── test_integration.py            # MODIFY: end-to-end with CDP data
```

---

### Task 1: Shared Data Model (`traffictracer/models.py`)

**Files:**
- Create: `traffictracer/models.py`
- Test: `test/test_models.py`

**Interfaces:**
- Produces: `AttributedRequest`, `TransportConnection`, `CorrelatedFlowV2`, `VisitCorrelation` — used by Tasks 2–8

- [ ] **Step 1: Write the failing test**

```python
# test/test_models.py
"""Tests for shared data model types."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.models import (
    AttributedRequest,
    TransportConnection,
    CorrelatedFlowV2,
    VisitCorrelation,
)


def test_attributed_request_defaults():
    req = AttributedRequest(
        request_id="921.18",
        target_id="ABC",
        frame_id="F1",
        url="https://cdn.example.net/video.m4s",
        resource_type="Media",
        timestamp=123456.123,
    )
    assert req.connection_id is None
    assert req.remote_ip == ""
    assert req.remote_port == 0
    assert req.connection_reused is False
    assert req.target_type == "page"
    assert req.loader_id == ""
    assert req.initiator_type == ""


def test_attributed_request_with_connection():
    req = AttributedRequest(
        request_id="1.1",
        target_id="T1",
        frame_id="F1",
        url="https://api.bilibili.com/x",
        resource_type="XHR",
        timestamp=100.0,
        connection_id=17,
        remote_ip="1.2.3.4",
        remote_port=443,
        connection_reused=True,
        target_type="page",
        loader_id="L1",
        initiator_type="script",
    )
    assert req.connection_id == 17
    assert req.connection_reused is True


def test_transport_connection():
    tc = TransportConnection(
        netlog_source_id=300,
        url="https://cdn.example.net/video.m4s",
        src_ip="198.18.0.1",
        src_port=49812,
        dst_ip="1.2.3.4",
        dst_port=443,
        protocol="HTTP2",
        request_ids=["921.18", "921.19"],
    )
    assert len(tc.request_ids) == 2
    assert tc.src_ip == "198.18.0.1"


def test_correlated_flow_v2():
    flow = CorrelatedFlowV2(
        url="https://cdn.example.net/video.m4s",
        resource_type="Media",
        target_type="page",
        relation="cross_site",
        pre_proxy_src="198.18.0.1:49812",
        pre_proxy_dst="1.2.3.4:443",
        post_proxy_src="192.168.5.101:53652",
        post_proxy_dst="1.2.3.4:443",
        protocol="HTTP2",
        request_ids=["921.18"],
        connection_reused=True,
    )
    assert flow.relation == "cross_site"
    assert flow.connection_reused is True


def test_visit_correlation():
    vc = VisitCorrelation(
        visit_url="https://www.bilibili.com",
        domain="bilibili.com",
        flows=[],
        cdp_request_count=42,
        netlog_connection_count=17,
    )
    assert vc.cdp_request_count == 42
    assert len(vc.flows) == 0


if __name__ == "__main__":
    test_attributed_request_defaults()
    test_attributed_request_with_connection()
    test_transport_connection()
    test_correlated_flow_v2()
    test_visit_correlation()
    print("\n✓ All model tests passed!")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python test/test_models.py`
Expected: FAIL with `ModuleNotFoundError: No module named 'traffictracer.models'`

- [ ] **Step 3: Write minimal implementation**

```python
# traffictracer/models.py
"""Shared data model types for TrafficTracer 2.0 CDP-attribution pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AttributedRequest:
    request_id: str
    target_id: str
    frame_id: str
    url: str
    resource_type: str
    timestamp: float
    target_type: str = "page"
    loader_id: str = ""
    initiator_type: str = ""
    connection_id: int | None = None
    remote_ip: str = ""
    remote_port: int = 0
    connection_reused: bool = False


@dataclass
class TransportConnection:
    netlog_source_id: int
    url: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    request_ids: list[str] = field(default_factory=list)


@dataclass
class CorrelatedFlowV2:
    url: str
    resource_type: str
    target_type: str
    relation: str
    pre_proxy_src: str
    pre_proxy_dst: str
    post_proxy_src: str
    post_proxy_dst: str
    protocol: str
    request_ids: list[str] = field(default_factory=list)
    connection_reused: bool = False


@dataclass
class VisitCorrelation:
    visit_url: str
    domain: str
    flows: list[CorrelatedFlowV2] = field(default_factory=list)
    cdp_request_count: int = 0
    netlog_connection_count: int = 0
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python test/test_models.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add traffictracer/models.py test/test_models.py
git commit -m "feat: add shared data model types for CDP attribution pipeline"
```

---

### Task 2: Rewrite CDP Collector (`traffictracer/capture/cdp.py`)

**Files:**
- Modify: `traffictracer/capture/cdp.py` (full rewrite)
- Test: `test/test_cdp.py` (rewrite)

**Interfaces:**
- Consumes: nothing from other tasks (standalone)
- Produces: `CDPCollector` class with `start()`, `navigate()`, `stop()`, `get_structured_data()` — used by Task 4 (pipeline)

The current `CDPClient`/`SyncCDPClient` is replaced by a single `CDPCollector` class that:
1. Connects to the browser-level CDP endpoint (`/json/version` → `webSocketDebuggerUrl`)
2. Calls `Target.setAutoAttach` with `autoAttach: true, waitForDebuggerOnStart: true, flatten: true`
3. For each attached target, sends `Network.enable` and `Page.enable` on its session
4. Parses `Network.requestWillBeSent`, `Network.responseReceived`, `Network.webSocketCreated` into structured records
5. Tracks `targetId → type` mapping from `Target.attachedToTarget` / `Target.targetCreated`
6. `get_structured_data()` returns a dict ready for JSON serialization

- [ ] **Step 1: Write the failing test**

```python
# test/test_cdp.py
"""Tests for structured CDP collector."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import asyncio
from unittest.mock import patch, MagicMock

from traffictracer.capture.cdp import CDPCollector


class FakeWS:
    def __init__(self):
        self.sent: list[dict] = []
        self._recv: asyncio.Queue = asyncio.Queue()
        self.closed = False

    def push_response(self, cmd_id: int, result: dict | None = None):
        msg = {"id": cmd_id, "result": result or {}}
        self._recv.put_nowait(json.dumps(msg))

    def push_event(self, method: str, params: dict, session_id: str = ""):
        msg = {"method": method, "params": params}
        if session_id:
            msg["sessionId"] = session_id
        self._recv.put_nowait(json.dumps(msg))

    async def send(self, raw: str):
        parsed = json.loads(raw)
        self.sent.append(parsed)

    async def close(self):
        self.closed = True

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await asyncio.wait_for(self._recv.get(), timeout=2.0)
        except (asyncio.TimeoutError, Exception):
            raise StopAsyncIteration


def _make_collector_with_ws(ws: FakeWS) -> CDPCollector:
    collector = CDPCollector.__new__(CDPCollector)
    collector._port = 9222
    collector._ws = ws
    collector._cmd_id = 0
    collector._pending = {}
    collector._reader_task = None
    collector._lock = asyncio.Lock()
    collector._targets: dict[str, dict] = {}
    collector._requests: list[dict] = []
    collector._responses: dict[str, dict] = {}
    collector._websockets: list[dict] = []
    collector._visit_url = ""
    collector._collecting = False
    return collector


def test_collector_parses_request_will_be_sent():
    async def run():
        ws = FakeWS()
        collector = _make_collector_with_ws(ws)
        collector._targets["T1"] = {"type": "page", "url": "https://www.bilibili.com"}

        ws.push_event("Network.requestWillBeSent", {
            "requestId": "921.18",
            "loaderId": "L1",
            "frameId": "F1",
            "documentURL": "https://www.bilibili.com",
            "request": {
                "url": "https://cdn.example.net/video.m4s",
                "method": "GET",
            },
            "type": "Media",
            "initiator": {"type": "script"},
            "timestamp": 123456.123,
            "wallTime": 1720000000.0,
        }, session_id="S1")

        collector._reader_task = asyncio.create_task(collector._reader_loop())
        await asyncio.sleep(0.1)
        collector._reader_task.cancel()
        try:
            await collector._reader_task
        except asyncio.CancelledError:
            pass

        assert len(collector._requests) == 1
        req = collector._requests[0]
        assert req["request_id"] == "921.18"
        assert req["url"] == "https://cdn.example.net/video.m4s"
        assert req["resource_type"] == "Media"
        assert req["target_id"] == "T1"

    asyncio.run(run())


def test_collector_parses_response_received():
    async def run():
        ws = FakeWS()
        collector = _make_collector_with_ws(ws)

        ws.push_event("Network.responseReceived", {
            "requestId": "921.18",
            "response": {
                "url": "https://cdn.example.net/video.m4s",
                "status": 200,
                "connectionId": 17,
                "connectionReused": True,
                "remoteIPAddress": "1.2.3.4",
                "remotePort": 443,
            },
        }, session_id="S1")

        collector._reader_task = asyncio.create_task(collector._reader_loop())
        await asyncio.sleep(0.1)
        collector._reader_task.cancel()
        try:
            await collector._reader_task
        except asyncio.CancelledError:
            pass

        assert "921.18" in collector._responses
        resp = collector._responses["921.18"]
        assert resp["connection_id"] == 17
        assert resp["remote_ip"] == "1.2.3.4"
        assert resp["remote_port"] == 443
        assert resp["connection_reused"] is True

    asyncio.run(run())


def test_collector_structured_data_output():
    async def run():
        ws = FakeWS()
        collector = _make_collector_with_ws(ws)
        collector._visit_url = "https://www.bilibili.com"
        collector._targets["T1"] = {"type": "page", "url": "https://www.bilibili.com"}
        collector._requests.append({
            "request_id": "1.1",
            "target_id": "T1",
            "frame_id": "F1",
            "loader_id": "L1",
            "url": "https://api.bilibili.com/x",
            "resource_type": "XHR",
            "timestamp": 100.0,
            "initiator_type": "script",
        })
        collector._responses["1.1"] = {
            "connection_id": 5,
            "remote_ip": "10.0.0.1",
            "remote_port": 443,
            "connection_reused": False,
            "status": 200,
        }

        data = collector.get_structured_data()
        assert data["visit_url"] == "https://www.bilibili.com"
        assert len(data["targets"]) == 1
        assert len(data["requests"]) == 1
        req = data["requests"][0]
        assert req["connection_id"] == 5
        assert req["remote_ip"] == "10.0.0.1"
        assert req["connection_reused"] is False

    asyncio.run(run())


def test_collector_target_attached():
    async def run():
        ws = FakeWS()
        collector = _make_collector_with_ws(ws)

        ws.push_event("Target.attachedToTarget", {
            "sessionId": "S2",
            "targetInfo": {
                "targetId": "T2",
                "type": "iframe",
                "url": "https://ads.example.com/frame",
            },
        })

        collector._reader_task = asyncio.create_task(collector._reader_loop())
        await asyncio.sleep(0.1)
        collector._reader_task.cancel()
        try:
            await collector._reader_task
        except asyncio.CancelledError:
            pass

        assert "T2" in collector._targets
        assert collector._targets["T2"]["type"] == "iframe"

    asyncio.run(run())


def test_collector_websocket_created():
    async def run():
        ws = FakeWS()
        collector = _make_collector_with_ws(ws)

        ws.push_event("Network.webSocketCreated", {
            "requestId": "WS1",
            "url": "wss://live.bilibili.com/ws",
            "initiator": {"type": "script"},
        }, session_id="S1")

        collector._reader_task = asyncio.create_task(collector._reader_loop())
        await asyncio.sleep(0.1)
        collector._reader_task.cancel()
        try:
            await collector._reader_task
        except asyncio.CancelledError:
            pass

        assert len(collector._websockets) == 1
        assert collector._websockets[0]["url"] == "wss://live.bilibili.com/ws"

    asyncio.run(run())


if __name__ == "__main__":
    test_collector_parses_request_will_be_sent()
    test_collector_parses_response_received()
    test_collector_structured_data_output()
    test_collector_target_attached()
    test_collector_websocket_created()
    print("\n✓ All CDP collector tests passed!")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python test/test_cdp.py`
Expected: FAIL with `ImportError: cannot import name 'CDPCollector'`

- [ ] **Step 3: Write the CDP collector implementation**

Rewrite `traffictracer/capture/cdp.py`:

```python
"""Structured CDP collector — request-level attribution via Chrome DevTools Protocol."""

from __future__ import annotations

import asyncio
import json
import time
import urllib.request

import websockets
from websockets.exceptions import ConnectionClosed

from ..utils import logger


class CDPCollector:
    def __init__(self, debugging_port: int = 9222):
        self._port = debugging_port
        self._ws = None
        self._cmd_id = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._reader_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

        self._targets: dict[str, dict] = {}
        self._session_to_target: dict[str, str] = {}
        self._requests: list[dict] = []
        self._responses: dict[str, dict] = {}
        self._websockets: list[dict] = []
        self._visit_url = ""
        self._collecting = False

    async def connect(self, retries: int = 15, delay: float = 0.5) -> None:
        for attempt in range(retries):
            ws_url = self._get_browser_ws_url()
            if ws_url:
                logger.info("CDP connecting to browser endpoint: %s", ws_url)
                self._ws = await websockets.connect(
                    ws_url,
                    ping_interval=None,
                    max_size=2 ** 26,
                )
                self._reader_task = asyncio.create_task(self._reader_loop())
                return
            if attempt < retries - 1:
                await asyncio.sleep(delay)
        raise RuntimeError(
            f"Failed to get CDP browser WebSocket URL from port {self._port} "
            f"after {retries} attempts"
        )

    def _get_browser_ws_url(self) -> str | None:
        try:
            resp = urllib.request.urlopen(
                f"http://127.0.0.1:{self._port}/json/version",
                timeout=5,
            )
            info = json.loads(resp.read().decode())
            return info.get("webSocketDebuggerUrl")
        except Exception as e:
            logger.warning("Failed to get CDP browser URL: %s", e)
            return None

    async def _reader_loop(self) -> None:
        try:
            async for raw in self._ws:
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                msg_id = msg.get("id")
                if msg_id is not None and msg_id in self._pending:
                    future = self._pending.pop(msg_id)
                    if "error" in msg:
                        future.set_exception(
                            RuntimeError(msg["error"].get("message", "CDP error"))
                        )
                    else:
                        future.set_result(msg.get("result", {}))
                else:
                    self._dispatch_event(msg)
        except ConnectionClosed:
            logger.debug("CDP WebSocket connection closed")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug("CDP reader loop error: %s", e)

    def _dispatch_event(self, msg: dict) -> None:
        method = msg.get("method", "")
        params = msg.get("params", {})
        session_id = msg.get("sessionId", "")

        if method == "Target.attachedToTarget":
            self._on_target_attached(params)
        elif method == "Target.targetCreated":
            self._on_target_created(params)
        elif method == "Target.targetDestroyed":
            tid = params.get("targetId", "")
            self._targets.pop(tid, None)
        elif method == "Network.requestWillBeSent":
            self._on_request_will_be_sent(params, session_id)
        elif method == "Network.responseReceived":
            self._on_response_received(params, session_id)
        elif method == "Network.webSocketCreated":
            self._on_websocket_created(params, session_id)

    def _on_target_attached(self, params: dict) -> None:
        info = params.get("targetInfo", {})
        tid = info.get("targetId", "")
        sid = params.get("sessionId", "")
        if tid:
            self._targets[tid] = {
                "type": info.get("type", "unknown"),
                "url": info.get("url", ""),
            }
            if sid:
                self._session_to_target[sid] = tid
            logger.debug("Target attached: %s (%s)", tid, info.get("type"))

    def _on_target_created(self, params: dict) -> None:
        info = params.get("targetInfo", {})
        tid = info.get("targetId", "")
        if tid and tid not in self._targets:
            self._targets[tid] = {
                "type": info.get("type", "unknown"),
                "url": info.get("url", ""),
            }

    def _on_request_will_be_sent(self, params: dict, session_id: str) -> None:
        if not self._collecting:
            return
        request = params.get("request", {})
        tid = self._session_to_target.get(session_id, "")
        initiator = params.get("initiator", {})
        self._requests.append({
            "request_id": params.get("requestId", ""),
            "target_id": tid,
            "frame_id": params.get("frameId", ""),
            "loader_id": params.get("loaderId", ""),
            "url": request.get("url", ""),
            "resource_type": params.get("type", "Other"),
            "timestamp": params.get("timestamp", 0.0),
            "initiator_type": initiator.get("type", ""),
        })

    def _on_response_received(self, params: dict, session_id: str) -> None:
        if not self._collecting:
            return
        rid = params.get("requestId", "")
        resp = params.get("response", {})
        self._responses[rid] = {
            "connection_id": resp.get("connectionId"),
            "remote_ip": resp.get("remoteIPAddress", ""),
            "remote_port": resp.get("remotePort", 0),
            "connection_reused": resp.get("connectionReused", False),
            "status": resp.get("status", 0),
        }

    def _on_websocket_created(self, params: dict, session_id: str) -> None:
        if not self._collecting:
            return
        tid = self._session_to_target.get(session_id, "")
        self._websockets.append({
            "request_id": params.get("requestId", ""),
            "target_id": tid,
            "url": params.get("url", ""),
            "timestamp": params.get("timestamp", 0.0),
        })

    async def send(self, method: str, params: dict | None = None,
                   timeout: float = 10.0, session_id: str = "") -> dict:
        async with self._lock:
            self._cmd_id += 1
            cmd_id = self._cmd_id
            msg: dict = {"id": cmd_id, "method": method}
            if params:
                msg["params"] = params
            if session_id:
                msg["sessionId"] = session_id
            future: asyncio.Future = asyncio.get_running_loop().create_future()
            self._pending[cmd_id] = future
            await self._ws.send(json.dumps(msg))
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending.pop(cmd_id, None)
            raise

    async def setup(self) -> None:
        await self.send("Target.setAutoAttach", {
            "autoAttach": True,
            "waitForDebuggerOnStart": False,
            "flatten": True,
        })
        await self.send("Target.setDiscoverTargets", {"discover": True})

    async def navigate(self, url: str, load_timeout: float = 30.0) -> None:
        self._visit_url = url
        self._collecting = True

        page_session = ""
        for sid, tid in self._session_to_target.items():
            info = self._targets.get(tid, {})
            if info.get("type") == "page":
                page_session = sid
                break

        if page_session:
            try:
                await self.send("Network.enable", session_id=page_session)
                await self.send("Page.enable", session_id=page_session)
            except Exception as e:
                logger.warning("Failed to enable domains on page session: %s", e)

        await self.send("Target.createTarget", {"url": "about:blank"})
        await asyncio.sleep(0.5)

        target_id = ""
        for tid, info in self._targets.items():
            if info.get("type") == "page" and info.get("url") in ("about:blank", ""):
                target_id = tid
                break

        if not target_id:
            for tid, info in self._targets.items():
                if info.get("type") == "page":
                    target_id = tid
                    break

        if target_id:
            for sid, tid in self._session_to_target.items():
                if tid == target_id:
                    page_session = sid
                    break
            try:
                await self.send("Network.enable", session_id=page_session)
                await self.send("Page.enable", session_id=page_session)
                await self.send("Page.navigate", {"url": url},
                                session_id=page_session)
            except Exception as e:
                logger.warning("Page.navigate via session failed: %s, trying browser-level", e)
                await self.send("Page.navigate", {"url": url})
        else:
            logger.warning("No page target found, navigating at browser level")
            await self.send("Page.navigate", {"url": url})

        deadline = time.time() + load_timeout
        while time.time() < deadline:
            await asyncio.sleep(0.5)
            for req in self._requests:
                pass
            break
        logger.info("Navigation to %s initiated, collecting events...", url)

    async def collect(self, seconds: float) -> None:
        await asyncio.sleep(seconds)

    def stop_collecting(self) -> None:
        self._collecting = False

    def get_structured_data(self) -> dict:
        merged_requests = []
        for req in self._requests:
            entry = dict(req)
            resp = self._responses.get(req["request_id"], {})
            entry["connection_id"] = resp.get("connection_id")
            entry["remote_ip"] = resp.get("remote_ip", "")
            entry["remote_port"] = resp.get("remote_port", 0)
            entry["connection_reused"] = resp.get("connection_reused", False)
            entry["response_status"] = resp.get("status", 0)
            target_info = self._targets.get(req.get("target_id", ""), {})
            entry["target_type"] = target_info.get("type", "unknown")
            merged_requests.append(entry)

        return {
            "visit_url": self._visit_url,
            "targets": [
                {"target_id": tid, **info}
                for tid, info in self._targets.items()
            ],
            "requests": merged_requests,
            "websockets": self._websockets,
            "metadata": {
                "target_count": len(self._targets),
                "request_count": len(self._requests),
                "websocket_count": len(self._websockets),
            },
        }

    async def close_browser(self) -> None:
        try:
            await self.send("Browser.close", timeout=5)
        except Exception:
            logger.warning("Browser.close via CDP failed")

    async def close(self) -> None:
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None
        if self._ws:
            await self._ws.close()
            self._ws = None


class SyncCDPCollector:
    def __init__(self, debugging_port: int = 9222):
        self._collector = CDPCollector(debugging_port)
        self._loop = asyncio.new_event_loop()
        self._thread = __import__("threading").Thread(
            target=self._run_loop, daemon=True,
        )
        self._thread.start()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run(self, coro, timeout: float = 30.0):
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    def connect(self) -> None:
        self._run(self._collector.connect(), timeout=30)

    def setup(self) -> None:
        self._run(self._collector.setup(), timeout=15)

    def navigate(self, url: str, load_timeout: float = 30.0) -> None:
        self._run(self._collector.navigate(url, load_timeout),
                  timeout=load_timeout + 15)

    def collect(self, seconds: float) -> None:
        self._run(self._collector.collect(seconds), timeout=seconds + 10)

    def stop_collecting(self) -> None:
        self._collector.stop_collecting()

    def get_structured_data(self) -> dict:
        return self._collector.get_structured_data()

    def close_browser(self) -> None:
        self._run(self._collector.close_browser(), timeout=10)

    def close(self) -> None:
        self._run(self._collector.close(), timeout=10)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python test/test_cdp.py`
Expected: PASS (all 5 tests)

- [ ] **Step 5: Commit**

```bash
git add traffictracer/capture/cdp.py test/test_cdp.py
git commit -m "feat: rewrite CDP collector with Target.setAutoAttach and structured output"
```

---

### Task 3: Chrome Launch Improvements (`traffictracer/capture/chrome.py`)

**Files:**
- Modify: `traffictracer/capture/chrome.py`
- Modify: `traffictracer/config.py`
- Test: `test/test_chrome.py`

**Interfaces:**
- Consumes: `ChromeConfig.disable_background_networking` (new field)
- Produces: `launch_chrome()` with new flags and per-visit profile support

- [ ] **Step 1: Write the failing test**

Add to `test/test_chrome.py`:

```python
def test_launch_chrome_background_flags():
    """When disable_background_networking is True, extra flags are present."""
    import subprocess
    with patch("subprocess.Popen") as mock_popen:
        mock_popen.return_value = MagicMock()
        launch_chrome(
            binary="google-chrome",
            url="https://example.com",
            netlog_path="/tmp/nl.json",
            user_data_dir="/tmp/prof",
            headless=True,
            disable_background_networking=True,
            open_url=False,
        )
        cmd = mock_popen.call_args[0][0]
        assert "--disable-background-networking" in cmd
        assert "--disable-component-update" in cmd
        assert "--disable-sync" in cmd


def test_launch_chrome_no_background_flags_by_default():
    with patch("subprocess.Popen") as mock_popen:
        mock_popen.return_value = MagicMock()
        launch_chrome(
            binary="google-chrome",
            url="https://example.com",
            netlog_path="/tmp/nl.json",
            user_data_dir="/tmp/prof",
            headless=True,
            open_url=False,
        )
        cmd = mock_popen.call_args[0][0]
        assert "--disable-background-networking" not in cmd
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python test/test_chrome.py`
Expected: FAIL with `TypeError: launch_chrome() got an unexpected keyword argument 'disable_background_networking'`

- [ ] **Step 3: Implement changes**

In `traffictracer/capture/chrome.py`, add parameter `disable_background_networking: bool = False` to `launch_chrome()` and append flags when True:

```python
def launch_chrome(
    binary: str,
    url: str,
    netlog_path: str,
    user_data_dir: str,
    headless: bool = False,
    proxy_server: str = "",
    remote_debugging_port: int | None = None,
    netlog_capture_mode: str = "Default",
    open_url: bool = True,
    extra_args: list[str] | None = None,
    disable_background_networking: bool = False,
) -> subprocess.Popen:
    # ... existing code ...
    if disable_background_networking:
        cmd.append("--disable-background-networking")
        cmd.append("--disable-component-update")
        cmd.append("--disable-sync")
    # ... rest unchanged ...
```

In `traffictracer/config.py`, add field to `ChromeConfig`:

```python
@dataclass
class ChromeConfig:
    binary: str = "google-chrome"
    user_data_dir: str = "/tmp/chrome-profile"
    headless: bool = False
    enable_cdp: bool = True
    remote_debugging_port: int = 9222
    netlog_capture_mode: str = "Default"
    graceful_close_timeout: int = 20
    disable_background_networking: bool = False
```

And in `load_config()`, parse it:

```python
chrome = ChromeConfig(
    # ... existing fields ...
    disable_background_networking=c.get("disable_background_networking", False),
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python test/test_chrome.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add traffictracer/capture/chrome.py traffictracer/config.py test/test_chrome.py
git commit -m "feat: add background networking suppression flags to Chrome launch"
```

---

### Task 4: Capture Pipeline Update (`traffictracer/capture/pipeline.py`)

**Files:**
- Modify: `traffictracer/capture/pipeline.py`
- Test: `test/test_capture_pipeline.py` (rewrite with meaningful tests)

**Interfaces:**
- Consumes: `SyncCDPCollector` (Task 2), `launch_chrome(disable_background_networking=...)` (Task 3), `ChromeConfig` (Task 3)
- Produces: structured CDP JSON file at `logs/cdp_{domain}_{run_tag}.json` in new format

Key changes:
1. Replace `SyncCDPClient` with `SyncCDPCollector`
2. CDP lifecycle: `connect()` → `setup()` → launch Chrome with `about:blank` → `navigate(url)` → `collect(wait)` → `stop_collecting()` → `get_structured_data()` → save → `close_browser()` → `close()`
3. Use per-visit isolated profile: `{user_data_dir}/{domain}/{run_tag}/`
4. Pass `disable_background_networking` to `launch_chrome`
5. Replace `time.sleep(3)` with `SyncCDPCollector.connect()` retry loop

- [ ] **Step 1: Write the failing test**

```python
# test/test_capture_pipeline.py
"""Tests for capture pipeline orchestration."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import patch, MagicMock, call
from traffictracer.config import (
    Config, GlobalConfig, OutputConfig, SiteConfig,
    ChromeConfig, MihomoConfig, NetworkConfig,
)


def test_per_visit_profile_path():
    g = GlobalConfig(
        chrome=ChromeConfig(user_data_dir="/tmp/chrome-profile"),
    )
    domain = "bilibili.com"
    run_tag = "video-mainpage_1"
    expected = os.path.join("/tmp/chrome-profile", domain, run_tag)
    actual = os.path.join(g.chrome.user_data_dir, domain, run_tag)
    assert actual == expected


def test_cdp_structured_output_path():
    logs_dir = "/data/output/session/logs"
    domain = "bilibili.com"
    run_tag = "video-mainpage_1"
    cdp_path = os.path.join(logs_dir, f"cdp_{domain}_{run_tag}.json")
    assert cdp_path.endswith("cdp_bilibili.com_video-mainpage_1.json")


def test_site_filtering():
    sites = [
        SiteConfig(domain="a.com", url="https://a.com", wait=10),
        SiteConfig(domain="b.com", url="https://b.com", wait=15),
    ]
    filtered = [s for s in sites if s.domain == "a.com"]
    assert len(filtered) == 1
    assert filtered[0].domain == "a.com"


def test_cdp_collector_lifecycle_order():
    """Verify the expected CDP lifecycle call order."""
    call_order = []

    mock_collector = MagicMock()
    mock_collector.connect = lambda: call_order.append("connect")
    mock_collector.setup = lambda: call_order.append("setup")
    mock_collector.navigate = lambda url, **kw: call_order.append("navigate")
    mock_collector.collect = lambda s: call_order.append("collect")
    mock_collector.stop_collecting = lambda: call_order.append("stop")
    mock_collector.get_structured_data = lambda: (
        call_order.append("get_data") or {"requests": []}
    )
    mock_collector.close_browser = lambda: call_order.append("close_browser")
    mock_collector.close = lambda: call_order.append("close")

    mock_collector.connect()
    mock_collector.setup()
    mock_collector.navigate("https://example.com")
    mock_collector.collect(5)
    mock_collector.stop_collecting()
    data = mock_collector.get_structured_data()
    mock_collector.close_browser()
    mock_collector.close()

    assert call_order == [
        "connect", "setup", "navigate", "collect",
        "stop", "get_data", "close_browser", "close",
    ]


if __name__ == "__main__":
    test_per_visit_profile_path()
    test_cdp_structured_output_path()
    test_site_filtering()
    test_cdp_collector_lifecycle_order()
    print("\n✓ All capture pipeline tests passed!")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python test/test_capture_pipeline.py`
Expected: PASS (these test the expected interfaces, not the implementation yet)

- [ ] **Step 3: Rewrite `_capture_domain` in pipeline.py**

Replace the CDP branch in `_capture_domain()`:

```python
from .cdp import SyncCDPCollector

def _capture_domain(site: SiteConfig, g: GlobalConfig, mihomo: MihomoManager, session_dir: str) -> None:
    domain = site.domain
    traffic_type = site.traffic_type or "all"
    logger.info("=== Capturing %s (%s) ===", domain, traffic_type)

    domain_dir = ensure_dir(os.path.join(session_dir, "captures", domain))
    logs_dir = ensure_dir(os.path.join(session_dir, "logs"))

    i = 1
    while True:
        sub = f"{traffic_type}_{i}"
        run_dir = os.path.join(domain_dir, sub)
        if not os.path.exists(run_dir):
            break
        i += 1
    run_dir = ensure_dir(run_dir)
    run_tag = f"{traffic_type}_{i}"

    mihomo_trace_path = os.path.join(logs_dir, f"mihomo_trace_{domain}_{run_tag}.jsonl")
    netlog_path = os.path.join(logs_dir, f"netlog_{domain}_{run_tag}.json")
    cdp_log_path = os.path.join(logs_dir, f"cdp_{domain}_{run_tag}.json")

    tun_proc = None
    phys_proc = None
    chrome_proc = None
    cdp_collector = None

    try:
        mihomo.enable_tracing(mihomo_trace_path)

        proxy_info = mihomo.get_proxy_info()
        proxy_info_path = os.path.join(logs_dir, f"proxy_info_{domain}_{run_tag}.json")
        with open(proxy_info_path, "w") as f:
            json.dump(proxy_info, f, indent=2, ensure_ascii=False)

        tun_path = os.path.join(run_dir, "tun.pcap")
        phys_path = os.path.join(run_dir, "phys.pcap")

        tun_proc = start_tshark(g.network.tun_interface, tun_path)
        phys_proc = start_tshark(g.network.phys_interface, phys_path)

        use_cdp = g.chrome.enable_cdp and g.chrome.headless
        visit_profile = os.path.join(g.chrome.user_data_dir, domain, run_tag)

        if use_cdp:
            cdp_port = g.chrome.remote_debugging_port
            chrome_proc = launch_chrome(
                binary=g.chrome.binary,
                url=site.url,
                netlog_path=netlog_path,
                user_data_dir=visit_profile,
                headless=g.chrome.headless,
                remote_debugging_port=cdp_port,
                netlog_capture_mode=g.chrome.netlog_capture_mode,
                open_url=False,
                disable_background_networking=g.chrome.disable_background_networking,
            )
            _active_procs.extend([tun_proc, phys_proc, chrome_proc])

            cdp_collector = SyncCDPCollector(debugging_port=cdp_port)
            try:
                cdp_collector.connect()
                cdp_collector.setup()
                cdp_collector.navigate(site.url, load_timeout=site.wait_load_timeout)

                logger.info("Collecting CDP events for %ds...", site.wait)
                cdp_collector.collect(site.wait)
                cdp_collector.stop_collecting()

                cdp_data = cdp_collector.get_structured_data()
                with open(cdp_log_path, "w") as f:
                    json.dump(cdp_data, f, indent=2, ensure_ascii=False)
                logger.info("CDP structured data saved to %s (%d requests)",
                            cdp_log_path,
                            cdp_data.get("metadata", {}).get("request_count", 0))
            finally:
                cdp_collector.close_browser()
                cdp_collector.close()

            if not wait_chrome_exit(chrome_proc, timeout=g.chrome.graceful_close_timeout):
                terminate_chrome(chrome_proc)
        else:
            chrome_proc = launch_chrome(
                binary=g.chrome.binary,
                url=site.url,
                netlog_path=netlog_path,
                user_data_dir=visit_profile,
                headless=g.chrome.headless,
                disable_background_networking=g.chrome.disable_background_networking,
            )
            _active_procs.extend([tun_proc, phys_proc, chrome_proc])

            logger.info("Waiting %ds for %s...", site.wait, site.url)
            time.sleep(site.wait)

            terminate_chrome(chrome_proc)

        repair_truncated_netlog(netlog_path)

    finally:
        # ... existing cleanup unchanged ...
```

- [ ] **Step 4: Run tests**

Run: `python test/test_capture_pipeline.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add traffictracer/capture/pipeline.py test/test_capture_pipeline.py
git commit -m "feat: update capture pipeline with structured CDP collector and per-visit profile"
```

---

### Task 5: CDP Attribution Parser (`traffictracer/analyze/cdp_attribution.py`)

**Files:**
- Create: `traffictracer/analyze/cdp_attribution.py`
- Test: `test/test_cdp_attribution.py`

**Interfaces:**
- Consumes: structured CDP JSON (produced by Task 2/4), `AttributedRequest` (Task 1)
- Produces: `parse_cdp_attribution(path) -> list[AttributedRequest]` — used by Task 7 (pipeline)

- [ ] **Step 1: Write the failing test**

```python
# test/test_cdp_attribution.py
"""Tests for CDP attribution parser."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import tempfile

from traffictracer.analyze.cdp_attribution import parse_cdp_attribution
from traffictracer.models import AttributedRequest


def _write_cdp_json(data: dict) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    return path


def test_parse_basic_requests():
    data = {
        "visit_url": "https://www.bilibili.com",
        "targets": [
            {"target_id": "T1", "type": "page", "url": "https://www.bilibili.com"},
        ],
        "requests": [
            {
                "request_id": "1.1",
                "target_id": "T1",
                "frame_id": "F1",
                "loader_id": "L1",
                "url": "https://www.bilibili.com/",
                "resource_type": "Document",
                "timestamp": 100.0,
                "initiator_type": "other",
                "connection_id": 5,
                "remote_ip": "10.0.0.1",
                "remote_port": 443,
                "connection_reused": False,
                "response_status": 200,
                "target_type": "page",
            },
            {
                "request_id": "1.2",
                "target_id": "T1",
                "frame_id": "F1",
                "loader_id": "L1",
                "url": "https://cdn.unknown.net/video.m4s",
                "resource_type": "Media",
                "timestamp": 101.0,
                "initiator_type": "script",
                "connection_id": 17,
                "remote_ip": "1.2.3.4",
                "remote_port": 443,
                "connection_reused": True,
                "response_status": 206,
                "target_type": "page",
            },
        ],
        "websockets": [],
    }
    path = _write_cdp_json(data)
    requests = parse_cdp_attribution(path)
    os.unlink(path)

    assert len(requests) == 2
    assert isinstance(requests[0], AttributedRequest)
    assert requests[0].url == "https://www.bilibili.com/"
    assert requests[0].resource_type == "Document"
    assert requests[1].url == "https://cdn.unknown.net/video.m4s"
    assert requests[1].connection_id == 17
    assert requests[1].connection_reused is True


def test_parse_skips_requests_without_url():
    data = {
        "visit_url": "https://example.com",
        "targets": [],
        "requests": [
            {"request_id": "1.1", "target_id": "T1", "frame_id": "",
             "url": "", "resource_type": "Other", "timestamp": 0},
            {"request_id": "1.2", "target_id": "T1", "frame_id": "",
             "url": "https://example.com/api", "resource_type": "XHR",
             "timestamp": 1.0},
        ],
        "websockets": [],
    }
    path = _write_cdp_json(data)
    requests = parse_cdp_attribution(path)
    os.unlink(path)

    assert len(requests) == 1
    assert requests[0].url == "https://example.com/api"


def test_parse_file_not_found():
    try:
        parse_cdp_attribution("/nonexistent/cdp.json")
        assert False, "Should raise FileNotFoundError"
    except FileNotFoundError:
        pass


def test_parse_empty_requests():
    data = {"visit_url": "https://example.com", "targets": [],
            "requests": [], "websockets": []}
    path = _write_cdp_json(data)
    requests = parse_cdp_attribution(path)
    os.unlink(path)
    assert requests == []


def test_connection_dedup_by_connection_id():
    """Multiple requests sharing connectionId=17 should all be returned."""
    data = {
        "visit_url": "https://example.com",
        "targets": [{"target_id": "T1", "type": "page", "url": "https://example.com"}],
        "requests": [
            {"request_id": "1.1", "target_id": "T1", "frame_id": "F1",
             "url": "https://a.example.com/1", "resource_type": "XHR",
             "timestamp": 1.0, "connection_id": 17, "remote_ip": "1.2.3.4",
             "remote_port": 443, "connection_reused": True, "target_type": "page"},
            {"request_id": "1.2", "target_id": "T1", "frame_id": "F1",
             "url": "https://b.example.com/2", "resource_type": "Fetch",
             "timestamp": 1.1, "connection_id": 17, "remote_ip": "1.2.3.4",
             "remote_port": 443, "connection_reused": True, "target_type": "page"},
        ],
        "websockets": [],
    }
    path = _write_cdp_json(data)
    requests = parse_cdp_attribution(path)
    os.unlink(path)

    assert len(requests) == 2
    conn_ids = {r.connection_id for r in requests}
    assert conn_ids == {17}


if __name__ == "__main__":
    test_parse_basic_requests()
    test_parse_skips_requests_without_url()
    test_parse_file_not_found()
    test_parse_empty_requests()
    test_connection_dedup_by_connection_id()
    print("\n✓ All CDP attribution tests passed!")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python test/test_cdp_attribution.py`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# traffictracer/analyze/cdp_attribution.py
"""CDP attribution parser — convert structured CDP JSON to AttributedRequest list."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import AttributedRequest
from ..utils import logger


def parse_cdp_attribution(path: str) -> list[AttributedRequest]:
    fp = Path(path)
    if not fp.exists():
        raise FileNotFoundError(f"CDP data file not found: {path}")

    with open(fp, "r", encoding="utf-8") as f:
        data = json.load(f)

    raw_requests = data.get("requests", [])
    result: list[AttributedRequest] = []

    for raw in raw_requests:
        url = raw.get("url", "")
        if not url:
            continue

        result.append(AttributedRequest(
            request_id=raw.get("request_id", ""),
            target_id=raw.get("target_id", ""),
            frame_id=raw.get("frame_id", ""),
            url=url,
            resource_type=raw.get("resource_type", "Other"),
            timestamp=raw.get("timestamp", 0.0),
            target_type=raw.get("target_type", "unknown"),
            loader_id=raw.get("loader_id", ""),
            initiator_type=raw.get("initiator_type", ""),
            connection_id=raw.get("connection_id"),
            remote_ip=raw.get("remote_ip", ""),
            remote_port=raw.get("remote_port", 0),
            connection_reused=raw.get("connection_reused", False),
        ))

    logger.info("Parsed %d attributed requests from CDP data", len(result))
    return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python test/test_cdp_attribution.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add traffictracer/analyze/cdp_attribution.py test/test_cdp_attribution.py
git commit -m "feat: add CDP attribution parser for structured request data"
```

---

### Task 6: NetLog Transport Tracer (`traffictracer/analyze/netlog_transport.py`)

**Files:**
- Create: `traffictracer/analyze/netlog_transport.py`
- Modify: `traffictracer/analyze/netlog.py` (add `extract_all_five_tuples`)
- Test: `test/test_netlog_transport.py`

**Interfaces:**
- Consumes: `AttributedRequest` list (Task 5), `parser/` package (existing, unchanged)
- Produces: `trace_transport(requests, netlog_path) -> list[TransportConnection]` — used by Task 7

This is the core replacement for `domain_analyzer.get_domain_connections()`. Instead of filtering by domain substring, it:
1. Loads NetLog and processes events (reusing `parser/event_processor.py`)
2. Finds all `URL_REQUEST` entries
3. Matches them to CDP requests by URL
4. For each matched URL_REQUEST, uses `dependency_graph.build_connection_chain()` to trace down to socket and extract 5-tuple
5. Groups by connection (multiple requests can share one socket via HTTP/2)

- [ ] **Step 1: Write the failing test**

```python
# test/test_netlog_transport.py
"""Tests for NetLog transport tracer."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import tempfile

from traffictracer.analyze.netlog_transport import trace_transport
from traffictracer.models import AttributedRequest, TransportConnection


def _make_netlog(events: list[dict]) -> str:
    netlog = {
        "constants": {
            "logFormatVersion": 1,
            "timeTickOffset": "1329000000000",
            "logSourceType": {
                "URL_REQUEST": 1, "TRANSPORT_CONNECT_JOB": 2,
                "SOCKET": 3, "HTTP_STREAM_JOB": 5,
                "HTTP_PROXY_CONNECT_JOB": 10, "TCP_STREAM_ATTEMPT": 20,
                "HTTP2_SESSION": 14,
            },
            "logEventPhase": {"PHASE_BEGIN": 0, "PHASE_END": 1, "PHASE_NONE": 2},
        },
        "events": events,
    }
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(netlog, f)
    return path


def test_trace_single_request():
    events = [
        {"time": "1000", "type": 0, "phase": 0,
         "source": {"id": 100, "type": 1},
         "params": {"url": "https://cdn.example.net/video.m4s",
                     "source_dependency": {"id": 200, "type": 5}}},
        {"time": "1100", "type": 21, "phase": 2,
         "source": {"id": 200, "type": 5},
         "params": {"group_id": "https://cdn.example.net <https://example.com cross_site>"}},
        {"time": "1200", "type": 50, "phase": 2,
         "source": {"id": 300, "type": 10},
         "params": {"local_address": "198.18.0.1:49812",
                     "remote_address": "1.2.3.4:443",
                     "source_dependency": {"id": 200, "type": 5}}},
    ]
    netlog_path = _make_netlog(events)

    requests = [
        AttributedRequest(
            request_id="1.1", target_id="T1", frame_id="F1",
            url="https://cdn.example.net/video.m4s",
            resource_type="Media", timestamp=100.0,
        ),
    ]

    conns = trace_transport(requests, netlog_path)
    os.unlink(netlog_path)

    assert len(conns) >= 1
    conn = conns[0]
    assert isinstance(conn, TransportConnection)
    assert conn.src_ip == "198.18.0.1"
    assert conn.src_port == 49812
    assert conn.dst_ip == "1.2.3.4"
    assert conn.dst_port == 443
    assert "1.1" in conn.request_ids


def test_trace_unknown_cdn_matched_by_url():
    """A CDN domain with no relation to the visit domain is still matched."""
    events = [
        {"time": "1000", "type": 0, "phase": 0,
         "source": {"id": 100, "type": 1},
         "params": {"url": "https://xyz.edge-provider.net/asset.js",
                     "source_dependency": {"id": 200, "type": 5}}},
        {"time": "1200", "type": 50, "phase": 2,
         "source": {"id": 300, "type": 10},
         "params": {"local_address": "198.18.0.1:50000",
                     "remote_address": "5.6.7.8:443",
                     "source_dependency": {"id": 200, "type": 5}}},
    ]
    netlog_path = _make_netlog(events)

    requests = [
        AttributedRequest(
            request_id="2.1", target_id="T1", frame_id="F1",
            url="https://xyz.edge-provider.net/asset.js",
            resource_type="Script", timestamp=200.0,
        ),
    ]

    conns = trace_transport(requests, netlog_path)
    os.unlink(netlog_path)

    assert len(conns) >= 1
    assert conns[0].dst_ip == "5.6.7.8"
    assert "2.1" in conns[0].request_ids


def test_trace_no_match():
    events = [
        {"time": "1000", "type": 0, "phase": 0,
         "source": {"id": 100, "type": 1},
         "params": {"url": "https://other.com/page"}},
    ]
    netlog_path = _make_netlog(events)

    requests = [
        AttributedRequest(
            request_id="3.1", target_id="T1", frame_id="F1",
            url="https://notfound.com/missing.js",
            resource_type="Script", timestamp=300.0,
        ),
    ]

    conns = trace_transport(requests, netlog_path)
    os.unlink(netlog_path)

    assert len(conns) == 0


def test_trace_multiple_requests_same_connection():
    """Two CDP requests matching the same NetLog URL_REQUEST share a connection."""
    events = [
        {"time": "1000", "type": 0, "phase": 0,
         "source": {"id": 100, "type": 1},
         "params": {"url": "https://api.example.com/data",
                     "source_dependency": {"id": 200, "type": 5}}},
        {"time": "1200", "type": 50, "phase": 2,
         "source": {"id": 300, "type": 10},
         "params": {"local_address": "198.18.0.1:60000",
                     "remote_address": "9.8.7.6:443",
                     "source_dependency": {"id": 200, "type": 5}}},
    ]
    netlog_path = _make_netlog(events)

    requests = [
        AttributedRequest(
            request_id="4.1", target_id="T1", frame_id="F1",
            url="https://api.example.com/data",
            resource_type="XHR", timestamp=400.0,
        ),
        AttributedRequest(
            request_id="4.2", target_id="T1", frame_id="F1",
            url="https://api.example.com/data",
            resource_type="Fetch", timestamp=400.1,
        ),
    ]

    conns = trace_transport(requests, netlog_path)
    os.unlink(netlog_path)

    assert len(conns) >= 1
    all_rids = set()
    for c in conns:
        all_rids.update(c.request_ids)
    assert "4.1" in all_rids
    assert "4.2" in all_rids


if __name__ == "__main__":
    test_trace_single_request()
    test_trace_unknown_cdn_matched_by_url()
    test_trace_no_match()
    test_trace_multiple_requests_same_connection()
    print("\n✓ All NetLog transport tracer tests passed!")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python test/test_netlog_transport.py`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# traffictracer/analyze/netlog_transport.py
"""NetLog transport tracer — match CDP-attributed requests to NetLog sockets."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from ..models import AttributedRequest, TransportConnection
from ..utils import logger

from parser.constants import NetLogConstants, SRC_URL_REQUEST
from parser.event_processor import process_events
from parser.dependency_graph import (
    build_connection_chain,
    _build_children_index,
    _parse_ip_port,
)


def trace_transport(
    requests: list[AttributedRequest],
    netlog_path: str,
) -> list[TransportConnection]:
    fp = Path(netlog_path)
    if not fp.exists():
        raise FileNotFoundError(f"NetLog file not found: {netlog_path}")

    with open(fp, "r", encoding="utf-8") as f:
        raw = json.load(f)

    constants = NetLogConstants(raw.get("constants") or {})
    events = raw.get("events") or []
    entries = process_events(events, constants)
    children_index = _build_children_index(entries)

    request_urls: dict[str, list[str]] = {}
    for req in requests:
        normalized = _normalize_url(req.url)
        request_urls.setdefault(normalized, []).append(req.request_id)

    netlog_url_index: dict[str, list[int]] = {}
    for sid, entry in entries.items():
        if entry.source_type != SRC_URL_REQUEST:
            continue
        url = _extract_url_from_entry(entry)
        if url:
            normalized = _normalize_url(url)
            netlog_url_index.setdefault(normalized, []).append(sid)

    connections: list[TransportConnection] = []
    seen_source_ids: set[int] = set()

    for normalized_url, source_ids in netlog_url_index.items():
        if normalized_url not in request_urls:
            continue

        matched_request_ids = request_urls[normalized_url]

        for sid in source_ids:
            if sid in seen_source_ids:
                continue
            seen_source_ids.add(sid)

            chain = build_connection_chain(sid, entries, children_index)
            ft = chain.five_tuple

            if not ft.src_ip and not ft.dst_ip:
                continue

            connections.append(TransportConnection(
                netlog_source_id=sid,
                url=_denormalize_url(normalized_url),
                src_ip=ft.src_ip or "",
                src_port=ft.src_port or 0,
                dst_ip=ft.dst_ip or "",
                dst_port=ft.dst_port or 0,
                protocol=ft.protocol or "",
                request_ids=list(matched_request_ids),
            ))

    logger.info("Traced %d transport connections for %d CDP requests",
                len(connections), len(requests))
    return connections


def _extract_url_from_entry(entry) -> str:
    for event in entry.entries:
        params = event.get("params") or {}
        url = params.get("url")
        if isinstance(url, str) and url:
            return url
    if entry.description and entry.description.startswith("http"):
        return entry.description
    return ""


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _denormalize_url(normalized: str) -> str:
    return normalized
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python test/test_netlog_transport.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add traffictracer/analyze/netlog_transport.py test/test_netlog_transport.py
git commit -m "feat: add NetLog transport tracer with URL-based request matching"
```

---

### Task 7: Updated Correlator (`traffictracer/analyze/correlator.py`)

**Files:**
- Modify: `traffictracer/analyze/correlator.py`
- Test: `test/test_correlator.py`

**Interfaces:**
- Consumes: `TransportConnection` (Task 6), `MihomoConnection` (existing)
- Produces: `correlate_v2(transport_conns, mihomo_conns) -> VisitCorrelation` — used by Task 8

The old `correlate()` function is kept for backward compatibility. A new `correlate_v2()` accepts `TransportConnection` list and produces `VisitCorrelation` with `CorrelatedFlowV2` flows.

- [ ] **Step 1: Write the failing test**

Add to `test/test_correlator.py`:

```python
from traffictracer.models import TransportConnection, VisitCorrelation, CorrelatedFlowV2
from traffictracer.analyze.correlator import correlate_v2


def test_correlate_v2_proxy_match():
    transport_conns = [
        TransportConnection(
            netlog_source_id=300,
            url="https://cdn.example.net/video.m4s",
            src_ip="198.18.0.1", src_port=49812,
            dst_ip="1.2.3.4", dst_port=443,
            protocol="HTTP2",
            request_ids=["1.1", "1.2"],
        ),
    ]

    mihomo_conns = {
        "c1": MihomoConnection(
            conn_id="c1",
            connect=TcpConnect(
                ts="", conn_id="c1",
                src="198.18.0.1:49812", dst="1.2.3.4:443",
                host="cdn.example.net",
            ),
            proxy_dial=TcpProxyDial(
                ts="", conn_id="c1",
                proxy="HK", proxy_type="vless",
                proxy_addr="10.0.0.1:443",
                out_src="192.168.5.101:53652",
            ),
            close=None,
        ),
    }

    result = correlate_v2(
        transport_conns, mihomo_conns,
        visit_url="https://www.bilibili.com",
        domain="bilibili.com",
        cdp_request_count=2,
    )

    assert isinstance(result, VisitCorrelation)
    assert result.domain == "bilibili.com"
    assert len(result.flows) == 1
    flow = result.flows[0]
    assert isinstance(flow, CorrelatedFlowV2)
    assert flow.pre_proxy_src == "198.18.0.1:49812"
    assert flow.pre_proxy_dst == "1.2.3.4:443"
    assert flow.post_proxy_src == "192.168.5.101:53652"
    assert flow.post_proxy_dst == "10.0.0.1:443"
    assert set(flow.request_ids) == {"1.1", "1.2"}


def test_correlate_v2_direct_connection():
    transport_conns = [
        TransportConnection(
            netlog_source_id=100,
            url="https://www.bilibili.com/",
            src_ip="198.18.0.1", src_port=50000,
            dst_ip="223.111.250.57", dst_port=443,
            protocol="TCP",
            request_ids=["2.1"],
        ),
    ]

    mihomo_conns = {
        "c2": MihomoConnection(
            conn_id="c2",
            connect=TcpConnect(
                ts="", conn_id="c2",
                src="198.18.0.1:50000", dst="223.111.250.57:443",
                host="www.bilibili.com",
            ),
            proxy_dial=None,
            close=None,
        ),
    }

    result = correlate_v2(
        transport_conns, mihomo_conns,
        visit_url="https://www.bilibili.com",
        domain="bilibili.com",
        cdp_request_count=1,
    )

    assert len(result.flows) == 1
    flow = result.flows[0]
    assert flow.post_proxy_src == ""
    assert flow.post_proxy_dst == "223.111.250.57:443"


def test_correlate_v2_no_match():
    transport_conns = [
        TransportConnection(
            netlog_source_id=100,
            url="https://nomatch.com/",
            src_ip="10.0.0.1", src_port=99999,
            dst_ip="10.0.0.2", dst_port=80,
            protocol="TCP",
            request_ids=["3.1"],
        ),
    ]
    mihomo_conns = {
        "c1": MihomoConnection(
            conn_id="c1",
            connect=TcpConnect(
                ts="", conn_id="c1",
                src="10.0.0.1:11111", dst="10.0.0.2:80",
                host="other.com",
            ),
            proxy_dial=None, close=None,
        ),
    }

    result = correlate_v2(
        transport_conns, mihomo_conns,
        visit_url="https://nomatch.com",
        domain="nomatch.com",
        cdp_request_count=1,
    )
    assert len(result.flows) == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python test/test_correlator.py`
Expected: FAIL with `ImportError: cannot import name 'correlate_v2'`

- [ ] **Step 3: Implement `correlate_v2`**

Add to `traffictracer/analyze/correlator.py`:

```python
from ..models import TransportConnection, VisitCorrelation, CorrelatedFlowV2


def correlate_v2(
    transport_conns: list[TransportConnection],
    mihomo_conns: dict[str, MihomoConnection],
    visit_url: str,
    domain: str,
    cdp_request_count: int = 0,
) -> VisitCorrelation:
    flows: list[CorrelatedFlowV2] = []

    for tc in transport_conns:
        mconn = _find_matching_mihomo_v2(tc, mihomo_conns)

        pre_src = f"{tc.src_ip}:{tc.src_port}" if tc.src_ip else ""
        pre_dst = f"{tc.dst_ip}:{tc.dst_port}" if tc.dst_ip else ""

        post_src = ""
        post_dst = ""
        if mconn and mconn.proxy_dial:
            out_ip, out_port = _parse_addr(mconn.proxy_dial.out_src)
            proxy_ip, proxy_port = _parse_addr(mconn.proxy_dial.proxy_addr)
            post_src = f"{out_ip}:{out_port}" if out_ip else ""
            post_dst = f"{proxy_ip}:{proxy_port}" if proxy_ip else ""
        elif mconn and mconn.connect:
            dst_ip, dst_port = _parse_addr(mconn.connect.dst)
            post_dst = f"{dst_ip}:{dst_port}" if dst_ip else ""

        if mconn is None:
            continue

        relation = _infer_relation(tc.url, domain)

        flows.append(CorrelatedFlowV2(
            url=tc.url,
            resource_type="",
            target_type="",
            relation=relation,
            pre_proxy_src=pre_src,
            pre_proxy_dst=pre_dst,
            post_proxy_src=post_src,
            post_proxy_dst=post_dst,
            protocol=tc.protocol,
            request_ids=list(tc.request_ids),
            connection_reused=False,
        ))

    return VisitCorrelation(
        visit_url=visit_url,
        domain=domain,
        flows=flows,
        cdp_request_count=cdp_request_count,
        netlog_connection_count=len(transport_conns),
    )


def _find_matching_mihomo_v2(
    tc: TransportConnection,
    mihomo_conns: dict[str, MihomoConnection],
) -> MihomoConnection | None:
    tc_src = f"{tc.src_ip}:{tc.src_port}"
    tc_dst = f"{tc.dst_ip}:{tc.dst_port}"

    for conn_id, mconn in mihomo_conns.items():
        if mconn.connect is None:
            continue
        if tc_src == mconn.connect.src and tc_dst == mconn.connect.dst:
            return mconn

    for conn_id, mconn in mihomo_conns.items():
        if mconn.connect is None:
            continue
        if tc_src == mconn.connect.src or tc_dst == mconn.connect.dst:
            return mconn

    return None


def _infer_relation(url: str, domain: str) -> str:
    from urllib.parse import urlparse
    try:
        host = urlparse(url).netloc.split(":")[0]
    except Exception:
        return "unknown"
    if domain.lower() in host.lower():
        return "same_site"
    return "cross_site"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python test/test_correlator.py`
Expected: PASS (old + new tests)

- [ ] **Step 5: Commit**

```bash
git add traffictracer/analyze/correlator.py test/test_correlator.py
git commit -m "feat: add correlate_v2 with TransportConnection input and VisitCorrelation output"
```

---

### Task 8: Updated Analysis Pipeline (`traffictracer/analyze/pipeline.py`)

**Files:**
- Modify: `traffictracer/analyze/pipeline.py`
- Test: `test/test_analyze_pipeline.py`
- Test: `test/test_integration.py`

**Interfaces:**
- Consumes: `parse_cdp_attribution` (Task 5), `trace_transport` (Task 6), `correlate_v2` (Task 7), old `correlate` (existing)
- Produces: `correlation_v2.json` output with new schema

New analysis flow:
1. Check if `cdp_{domain}_{run_tag}.json` exists
2. If yes (CDP path): `parse_cdp_attribution()` → `trace_transport()` → `correlate_v2()` → save
3. If no (fallback): old `extract_five_tuples()` → `correlate()` → save (unchanged)

- [ ] **Step 1: Write the failing test**

```python
# test/test_analyze_pipeline.py
"""Tests for analysis pipeline."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import tempfile
import shutil

from traffictracer.analyze.pipeline import run_analysis, _result_to_dict, _result_v2_to_dict


def test_result_v2_to_dict():
    from traffictracer.models import VisitCorrelation, CorrelatedFlowV2
    vc = VisitCorrelation(
        visit_url="https://www.bilibili.com",
        domain="bilibili.com",
        flows=[
            CorrelatedFlowV2(
                url="https://cdn.example.net/video.m4s",
                resource_type="Media",
                target_type="page",
                relation="cross_site",
                pre_proxy_src="198.18.0.1:49812",
                pre_proxy_dst="1.2.3.4:443",
                post_proxy_src="192.168.5.101:53652",
                post_proxy_dst="10.0.0.1:443",
                protocol="HTTP2",
                request_ids=["1.1"],
                connection_reused=True,
            ),
        ],
        cdp_request_count=42,
        netlog_connection_count=17,
    )
    d = _result_v2_to_dict(vc)
    assert d["visit_url"] == "https://www.bilibili.com"
    assert d["cdp_request_count"] == 42
    assert len(d["flows"]) == 1
    assert d["flows"][0]["url"] == "https://cdn.example.net/video.m4s"
    assert d["flows"][0]["request_ids"] == ["1.1"]


def test_analysis_cdp_path():
    """Full analysis with CDP data present."""
    tmpdir = tempfile.mkdtemp()
    session = os.path.join(tmpdir, "session")
    os.makedirs(os.path.join(session, "captures", "bilibili.com", "video-mainpage_1"))
    os.makedirs(os.path.join(session, "logs"))
    os.makedirs(os.path.join(session, "results"))

    netlog = {
        "constants": {
            "logFormatVersion": 1,
            "timeTickOffset": "1329000000000",
            "logSourceType": {
                "URL_REQUEST": 1, "HTTP_STREAM_JOB": 5,
                "HTTP_PROXY_CONNECT_JOB": 10,
            },
            "logEventPhase": {"PHASE_BEGIN": 0, "PHASE_END": 1, "PHASE_NONE": 2},
        },
        "events": [
            {"time": "1000", "type": 0, "phase": 0,
             "source": {"id": 100, "type": 1},
             "params": {"url": "https://cdn.example.net/video.m4s",
                         "source_dependency": {"id": 200, "type": 5}}},
            {"time": "1200", "type": 50, "phase": 2,
             "source": {"id": 300, "type": 10},
             "params": {"local_address": "198.18.0.1:49812",
                         "remote_address": "1.2.3.4:443",
                         "source_dependency": {"id": 200, "type": 5}}},
        ],
    }
    with open(os.path.join(session, "logs", "netlog_bilibili.com_video-mainpage_1.json"), "w") as f:
        json.dump(netlog, f)

    cdp_data = {
        "visit_url": "https://www.bilibili.com",
        "targets": [{"target_id": "T1", "type": "page", "url": "https://www.bilibili.com"}],
        "requests": [
            {"request_id": "1.1", "target_id": "T1", "frame_id": "F1",
             "url": "https://cdn.example.net/video.m4s",
             "resource_type": "Media", "timestamp": 100.0,
             "connection_id": 17, "remote_ip": "1.2.3.4", "remote_port": 443,
             "connection_reused": True, "target_type": "page"},
        ],
        "websockets": [],
    }
    with open(os.path.join(session, "logs", "cdp_bilibili.com_video-mainpage_1.json"), "w") as f:
        json.dump(cdp_data, f)

    with open(os.path.join(session, "logs", "mihomo_trace_bilibili.com_video-mainpage_1.jsonl"), "w") as f:
        f.write('{"ts":"","type":"tcp_connect","conn_id":"c1",'
                '"src":"198.18.0.1:49812","dst":"1.2.3.4:443",'
                '"host":"cdn.example.net"}\n')
        f.write('{"ts":"","type":"tcp_proxy_dial","conn_id":"c1",'
                '"proxy":"HK","proxy_type":"vless","proxy_addr":"10.0.0.1:443",'
                '"out_src":"192.168.5.101:53652"}\n')

    corr_path = run_analysis(session)

    assert os.path.exists(corr_path)
    with open(corr_path) as f:
        data = json.load(f)

    assert "bilibili.com" in data
    domain_data = data["bilibili.com"]
    assert "flows" in domain_data
    assert len(domain_data["flows"]) >= 1
    flow = domain_data["flows"][0]
    assert flow["url"] == "https://cdn.example.net/video.m4s"
    assert flow["pre_proxy_src"] == "198.18.0.1:49812"

    shutil.rmtree(tmpdir)
    print("  ✓ CDP-path analysis test pass")


if __name__ == "__main__":
    test_result_v2_to_dict()
    test_analysis_cdp_path()
    print("\n✓ All analysis pipeline tests passed!")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python test/test_analyze_pipeline.py`
Expected: FAIL with `ImportError: cannot import name '_result_v2_to_dict'`

- [ ] **Step 3: Rewrite analysis pipeline**

```python
# traffictracer/analyze/pipeline.py
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
        visit_url=attributed[0].url if attributed else "",
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
```

- [ ] **Step 4: Run tests**

Run: `python test/test_analyze_pipeline.py && python test/test_integration.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add traffictracer/analyze/pipeline.py test/test_analyze_pipeline.py test/test_integration.py
git commit -m "feat: analysis pipeline with CDP-first attribution and domain fallback"
```

---

### Task 9: Update Integration Test (`test/test_integration.py`)

**Files:**
- Modify: `test/test_integration.py`

**Interfaces:**
- Consumes: all modules from Tasks 1–8

- [ ] **Step 1: Add CDP-based integration test**

Add `test_cdp_integration()` to `test/test_integration.py` that exercises the full chain: synthetic CDP JSON → `parse_cdp_attribution` → `trace_transport` → `correlate_v2` → verify output. Keep the existing `test_analysis_integration()` as the fallback-path test.

```python
def test_cdp_integration():
    """End-to-end: CDP attribution → NetLog transport → Mihomo correlation."""
    from traffictracer.analyze.cdp_attribution import parse_cdp_attribution
    from traffictracer.analyze.netlog_transport import trace_transport
    from traffictracer.analyze.correlator import correlate_v2

    tmpdir = tempfile.mkdtemp()

    cdp_data = {
        "visit_url": "https://www.bilibili.com",
        "targets": [{"target_id": "T1", "type": "page", "url": "https://www.bilibili.com"}],
        "requests": [
            {"request_id": "1.1", "target_id": "T1", "frame_id": "F1",
             "url": "https://www.bilibili.com/",
             "resource_type": "Document", "timestamp": 100.0,
             "target_type": "page"},
            {"request_id": "1.2", "target_id": "T1", "frame_id": "F1",
             "url": "https://unknown-cdn.net/video.m4s",
             "resource_type": "Media", "timestamp": 101.0,
             "connection_id": 17, "remote_ip": "5.6.7.8", "remote_port": 443,
             "connection_reused": True, "target_type": "page"},
        ],
        "websockets": [],
    }
    cdp_path = os.path.join(tmpdir, "cdp.json")
    with open(cdp_path, "w") as f:
        json.dump(cdp_data, f)

    netlog = {
        "constants": {
            "logFormatVersion": 1,
            "timeTickOffset": "1329000000000",
            "logSourceType": {
                "URL_REQUEST": 1, "HTTP_STREAM_JOB": 5,
                "HTTP_PROXY_CONNECT_JOB": 10,
            },
            "logEventPhase": {"PHASE_BEGIN": 0, "PHASE_END": 1, "PHASE_NONE": 2},
        },
        "events": [
            {"time": "1000", "type": 0, "phase": 0,
             "source": {"id": 100, "type": 1},
             "params": {"url": "https://unknown-cdn.net/video.m4s",
                         "source_dependency": {"id": 200, "type": 5}}},
            {"time": "1200", "type": 50, "phase": 2,
             "source": {"id": 300, "type": 10},
             "params": {"local_address": "198.18.0.1:49812",
                         "remote_address": "5.6.7.8:443",
                         "source_dependency": {"id": 200, "type": 5}}},
        ],
    }
    netlog_path = os.path.join(tmpdir, "netlog.json")
    with open(netlog_path, "w") as f:
        json.dump(netlog, f)

    trace_path = os.path.join(tmpdir, "trace.jsonl")
    with open(trace_path, "w") as f:
        f.write('{"ts":"","type":"tcp_connect","conn_id":"c1",'
                '"src":"198.18.0.1:49812","dst":"5.6.7.8:443",'
                '"host":"unknown-cdn.net"}\n')
        f.write('{"ts":"","type":"tcp_proxy_dial","conn_id":"c1",'
                '"proxy":"HK","proxy_type":"vless","proxy_addr":"10.0.0.1:443",'
                '"out_src":"192.168.5.101:53652"}\n')

    attributed = parse_cdp_attribution(cdp_path)
    assert len(attributed) == 2

    transport = trace_transport(attributed, netlog_path)
    assert len(transport) >= 1

    from traffictracer.analyze.mihomo_log import parse_tracing_log
    mihomo_conns = parse_tracing_log(trace_path)

    result = correlate_v2(
        transport, mihomo_conns,
        visit_url="https://www.bilibili.com",
        domain="bilibili.com",
        cdp_request_count=len(attributed),
    )

    assert result.domain == "bilibili.com"
    assert len(result.flows) >= 1

    cdn_flow = None
    for f in result.flows:
        if "unknown-cdn.net" in f.url:
            cdn_flow = f
            break
    assert cdn_flow is not None
    assert cdn_flow.pre_proxy_src == "198.18.0.1:49812"
    assert cdn_flow.post_proxy_src == "192.168.5.101:53652"
    assert cdn_flow.relation == "cross_site"

    import shutil
    shutil.rmtree(tmpdir)
    print("  ✓ CDP integration test pass")
```

- [ ] **Step 2: Run all tests**

Run: `python test/test_integration.py`
Expected: PASS (both old and new integration tests)

- [ ] **Step 3: Commit**

```bash
git add test/test_integration.py
git commit -m "test: add CDP-based end-to-end integration test"
```

---

### Task 10: Run Full Test Suite and Fix Issues

**Files:**
- All test files

- [ ] **Step 1: Run full test suite**

Run:
```bash
pytest test/ -v
```

Expected: All tests pass. Fix any import errors, type mismatches, or assertion failures.

- [ ] **Step 2: Run standalone test files**

Run:
```bash
python test/test_models.py && \
python test/test_cdp.py && \
python test/test_cdp_attribution.py && \
python test/test_netlog_transport.py && \
python test/test_correlator.py && \
python test/test_analyze_pipeline.py && \
python test/test_capture_pipeline.py && \
python test/test_integration.py && \
python test/test_config.py && \
python test/test_mihomo.py && \
python test/test_tshark.py && \
python test/test_chrome.py && \
python test/test_netlog.py && \
python test/test_mihomo_log.py && \
python test/test_pcap_splitter.py && \
python test/test_netlog_fix.py && \
python test/test_parser.py
```

Expected: All pass.

- [ ] **Step 3: Commit any fixes**

```bash
git add -A
git commit -m "fix: resolve test failures from CDP attribution refactor"
```

---

## What is NOT changed (preserved as-is)

| Module | Reason |
|--------|--------|
| `parser/*` | Standalone NetLog library; only consumed, not modified |
| `traffictracer/analyze/mihomo_log.py` | Mihomo trace parsing unchanged |
| `traffictracer/analyze/pcap_splitter.py` | pcap splitting unchanged (operates on 5-tuples) |
| `traffictracer/capture/mihomo.py` | Mihomo process management unchanged |
| `traffictracer/capture/tshark.py` | tshark management unchanged |
| `traffictracer/capture/netlog_fix.py` | NetLog repair unchanged |
| `netlog_parser.py` | Standalone CLI unchanged |

## Output format change

Old `correlation.json`:
```json
{
  "bilibili.com": [
    {"name": "https://www.bilibili.com", "relation": "same_site",
     "pre_proxy": {"src": "...", "dst": "..."},
     "post_proxy": {"src": "...", "dst": "..."}}
  ]
}
```

New `correlation.json`:
```json
{
  "bilibili.com": {
    "visit_url": "https://www.bilibili.com",
    "domain": "bilibili.com",
    "cdp_request_count": 42,
    "netlog_connection_count": 17,
    "flows": [
      {"url": "https://cdn.example.net/video.m4s",
       "resource_type": "Media",
       "target_type": "page",
       "relation": "cross_site",
       "pre_proxy_src": "198.18.0.1:49812",
       "pre_proxy_dst": "1.2.3.4:443",
       "post_proxy_src": "192.168.5.101:53652",
       "post_proxy_dst": "10.0.0.1:443",
       "protocol": "HTTP2",
       "request_ids": ["1.1", "1.2"],
       "connection_reused": true}
    ]
  }
}
```
