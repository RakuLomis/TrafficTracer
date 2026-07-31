"""Structured CDP collector — request-level attribution via Chrome DevTools Protocol."""

from __future__ import annotations

import asyncio
import json
import urllib.request

import websockets
from websockets.exceptions import ConnectionClosed

from ..jobs.cancellation import CancellationToken
from ..utils import logger


class CDPCollector:
    def __init__(
        self,
        debugging_port: int = 9222,
        cancellation: CancellationToken | None = None,
    ):
        self._port = debugging_port
        self._cancellation = cancellation
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
        self._setup_complete = False
        self._load_events: dict[str, asyncio.Event] = {}
        self._enabled_sessions: set[str] = set()
        self._enable_tasks: set[asyncio.Task] = set()

    async def connect(self, retries: int = 15, delay: float = 0.5) -> None:
        for attempt in range(retries):
            self._checkpoint()
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
                await self._cancellable_sleep(delay)
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
            logger.debug("Failed to get CDP browser URL (retrying): %s", e)
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
            for sid, target_id in list(self._session_to_target.items()):
                if target_id == tid:
                    self._session_to_target.pop(sid, None)
                    self._load_events.pop(sid, None)
                    self._enabled_sessions.discard(sid)
        elif method == "Network.requestWillBeSent":
            self._on_request_will_be_sent(params, session_id)
        elif method == "Network.responseReceived":
            self._on_response_received(params, session_id)
        elif method == "Network.webSocketCreated":
            self._on_websocket_created(params, session_id)
        elif method == "Page.loadEventFired":
            load_event = self._load_events.get(session_id)
            if load_event is not None:
                load_event.set()

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
                if self._setup_complete:
                    task = asyncio.create_task(
                        self._enable_session(sid, info.get("type", "unknown"))
                    )
                    self._enable_tasks.add(task)
                    task.add_done_callback(self._enable_tasks.discard)
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
        self._setup_complete = True

        for session_id, target_id in list(self._session_to_target.items()):
            target_type = self._targets.get(target_id, {}).get("type", "unknown")
            await self._enable_session(session_id, target_type)

    async def _enable_session(self, session_id: str, target_type: str) -> None:
        if not session_id or session_id in self._enabled_sessions:
            return
        try:
            await self.send("Network.enable", session_id=session_id)
            if target_type in {"page", "iframe"}:
                await self.send("Page.enable", session_id=session_id)
            self._enabled_sessions.add(session_id)
        except Exception as e:
            logger.warning(
                "Failed to enable CDP domains for %s target: %s",
                target_type,
                e,
            )

    async def _wait_for_session(self, target_id: str, timeout: float) -> str:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            self._checkpoint()
            for session_id, attached_target_id in self._session_to_target.items():
                if attached_target_id == target_id:
                    return session_id
            await self._cancellable_sleep(0.05)
        return ""

    async def navigate(self, url: str, load_timeout: float = 30.0) -> None:
        self._checkpoint()
        self._visit_url = url
        self._collecting = True

        result = await self.send("Target.createTarget", {"url": "about:blank"})
        target_id = result.get("targetId", "")
        if not target_id:
            raise RuntimeError("CDP Target.createTarget returned no targetId")

        page_session = await self._wait_for_session(target_id, load_timeout)
        if not page_session:
            raise RuntimeError(
                f"CDP did not attach to page target {target_id} "
                f"within {load_timeout}s"
            )

        await self._enable_session(page_session, "page")
        load_event = asyncio.Event()
        self._load_events[page_session] = load_event
        try:
            await self.send(
                "Page.navigate",
                {"url": url},
                session_id=page_session,
            )
            loop = asyncio.get_running_loop()
            deadline = loop.time() + load_timeout
            while not load_event.is_set() and loop.time() < deadline:
                self._checkpoint()
                try:
                    await asyncio.wait_for(
                        load_event.wait(),
                        timeout=min(0.05, max(0.001, deadline - loop.time())),
                    )
                except asyncio.TimeoutError:
                    pass
            if not load_event.is_set():
                logger.warning(
                    "Page load event not received for %s within %.1fs",
                    url,
                    load_timeout,
                )
        finally:
            self._load_events.pop(page_session, None)

        logger.info("Navigation to %s complete, collecting events...", url)

    async def collect(self, seconds: float) -> None:
        await self._cancellable_sleep(seconds)

    def _checkpoint(self) -> None:
        cancellation = getattr(self, "_cancellation", None)
        if cancellation is not None:
            cancellation.checkpoint()

    async def _cancellable_sleep(self, seconds: float) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(0.0, seconds)
        while True:
            self._checkpoint()
            remaining = deadline - loop.time()
            if remaining <= 0:
                return
            await asyncio.sleep(min(0.05, remaining))

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
        for task in list(self._enable_tasks):
            task.cancel()
        if self._enable_tasks:
            await asyncio.gather(*self._enable_tasks, return_exceptions=True)
        self._enable_tasks.clear()

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
    def __init__(
        self,
        debugging_port: int = 9222,
        cancellation: CancellationToken | None = None,
    ):
        self._collector = CDPCollector(debugging_port, cancellation)
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
