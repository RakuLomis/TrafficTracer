"""Structured CDP collector — request-level attribution via Chrome DevTools Protocol."""

from __future__ import annotations

import asyncio
import json
import math
import urllib.request

import websockets
from websockets.exceptions import ConnectionClosed

from ..jobs.cancellation import CancellationToken
from ..playback import PlaybackPolicy
from ..utils import logger
from .playback import (
    observe_youtube_playback,
    youtube_observation_expression,
)


class CDPCollector:
    def __init__(
        self,
        debugging_port: int = 9222,
        cancellation: CancellationToken | None = None,
        cache_mode: str = "warm",
    ):
        self._port = debugging_port
        self._cancellation = cancellation
        self._cache_mode = cache_mode
        self._ws = None
        self._cmd_id = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._reader_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

        self._targets: dict[str, dict] = {}
        self._session_to_target: dict[str, str] = {}
        self._requests: list[dict] = []
        self._responses: dict[str, dict] = {}
        self._completions: dict[str, dict] = {}
        self._websockets: list[dict] = []
        self._visit_url = ""
        self._collecting = False
        self._setup_complete = False
        self._load_events: dict[str, asyncio.Event] = {}
        self._enabled_sessions: set[str] = set()
        self._enable_tasks: set[asyncio.Task] = set()
        self._warnings: list[dict] = []
        self._navigation: dict = {}
        self._page_session = ""
        self._navigation_started_at: float | None = None
        self._playback: dict | None = None

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
        elif method == "Network.loadingFinished":
            self._on_loading_finished(params)
        elif method == "Network.loadingFailed":
            self._on_loading_failed(params)
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
        request_id = params.get("requestId", "")
        redirect_response = params.get("redirectResponse")
        if isinstance(redirect_response, dict):
            prior = next(
                (
                    item for item in reversed(self._requests)
                    if item.get("request_id") == request_id
                    and "_response" not in item
                ),
                None,
            )
            if prior is not None:
                timestamp = params.get("timestamp", 0.0)
                prior["_response"] = _response_payload(
                    redirect_response, timestamp,
                )
                prior["_completion"] = {
                    "timestamp": timestamp,
                    "failed": False,
                    "canceled": False,
                    "failure_reason": "",
                }
        tid = self._session_to_target.get(session_id, "")
        initiator = params.get("initiator", {})
        self._requests.append({
            "request_id": request_id,
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
        self._responses[rid] = _response_payload(
            resp, params.get("timestamp", 0.0),
        )

    def _on_loading_finished(self, params: dict) -> None:
        if not self._collecting:
            return
        self._completions[params.get("requestId", "")] = {
            "timestamp": params.get("timestamp", 0.0),
            "failed": False,
            "canceled": False,
            "failure_reason": "",
        }

    def _on_loading_failed(self, params: dict) -> None:
        if not self._collecting:
            return
        self._completions[params.get("requestId", "")] = {
            "timestamp": params.get("timestamp", 0.0),
            "failed": True,
            "canceled": bool(params.get("canceled", False)),
            "failure_reason": (
                params.get("blockedReason")
                or params.get("errorText")
                or "loading_failed"
            ),
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
            if self._cache_mode == "cold":
                await self.send(
                    "Network.setCacheDisabled",
                    {"cacheDisabled": True},
                    session_id=session_id,
                )
                await self.send(
                    "Network.setBypassServiceWorker",
                    {"bypass": True},
                    session_id=session_id,
                )
            if target_type in {"page", "iframe"}:
                await self.send("Page.enable", session_id=session_id)
            if target_type == "page":
                await self.send("Runtime.enable", session_id=session_id)
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

    async def navigate(
        self,
        url: str,
        load_timeout: float = 30.0,
        *,
        wait_for_load: bool = True,
    ) -> None:
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
        self._page_session = page_session
        load_event = asyncio.Event()
        navigate_command_timed_out = False
        self._navigation = {"url": url, "status": "started"}
        self._load_events[page_session] = load_event
        try:
            self._navigation_started_at = asyncio.get_running_loop().time()
            try:
                await self.send(
                    "Page.navigate",
                    {"url": url},
                    session_id=page_session,
                )
            except asyncio.TimeoutError:
                navigate_command_timed_out = True
                warning = {
                    "code": "CDP_NAVIGATE_COMMAND_TIMEOUT",
                    "message": "Page.navigate response timed out; collection continued",
                }
                self._warnings.append(warning)
                self._navigation["status"] = "command_timeout"
                logger.warning("%s for %s", warning["message"], url)
            if not wait_for_load:
                if not navigate_command_timed_out:
                    self._navigation["status"] = "command_completed"
                logger.info("Navigation to %s started; observing fixed window", url)
                return
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
                self._navigation["status"] = (
                    "command_and_load_timeout"
                    if navigate_command_timed_out
                    else "load_event_timeout"
                )
                logger.warning(
                    "Page load event not received for %s within %.1fs",
                    url,
                    load_timeout,
                )
            elif navigate_command_timed_out:
                self._navigation["status"] = "loaded_after_command_timeout"
            else:
                self._navigation["status"] = "loaded"
        finally:
            self._load_events.pop(page_session, None)

        logger.info("Navigation to %s complete, collecting events...", url)

    async def collect(self, seconds: float) -> None:
        await self._cancellable_sleep(seconds)

    async def collect_playback(
        self,
        seconds: float,
        policy: PlaybackPolicy,
        progress=None,
    ) -> dict:
        if policy.provider != "youtube":
            raise ValueError("unsupported playback provider")
        if not self._page_session or self._navigation_started_at is None:
            raise RuntimeError("playback collection requires a navigation target")

        async def evaluate() -> dict:
            remaining = (
                self._navigation_started_at + seconds
                - asyncio.get_running_loop().time()
            )
            if remaining <= 0:
                return {}
            result = await self.send(
                "Runtime.evaluate",
                {
                    "expression": youtube_observation_expression(),
                    "returnByValue": True,
                    "awaitPromise": False,
                },
                timeout=min(2.0, max(0.1, remaining)),
                session_id=self._page_session,
            )
            if result.get("exceptionDetails"):
                raise RuntimeError("YouTube playback observation failed")
            remote = result.get("result", {})
            value = remote.get("value")
            if not isinstance(value, dict):
                raise RuntimeError(
                    "YouTube playback observation returned no object"
                )
            return value

        async def interact(action: str, rect) -> bool:
            if action not in {"skip", "play"}:
                raise ValueError("unsupported playback interaction")
            try:
                x = float(rect["center_x"])
                y = float(rect["center_y"])
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError("invalid playback interaction rectangle") from error
            if not math.isfinite(x) or not math.isfinite(y):
                raise ValueError("playback interaction coordinates must be finite")
            for event in (
                {"type": "mouseMoved", "x": x, "y": y},
                {
                    "type": "mousePressed", "x": x, "y": y,
                    "button": "left", "clickCount": 1,
                },
                {
                    "type": "mouseReleased", "x": x, "y": y,
                    "button": "left", "clickCount": 1,
                },
            ):
                remaining = (
                    self._navigation_started_at + seconds
                    - asyncio.get_running_loop().time()
                )
                if remaining <= 0:
                    return False
                await self.send(
                    "Input.dispatchMouseEvent",
                    event,
                    timeout=min(1.0, max(0.1, remaining)),
                    session_id=self._page_session,
                )
            return True

        self._playback = await observe_youtube_playback(
            policy,
            seconds,
            evaluate=evaluate,
            interact=interact,
            started_at=self._navigation_started_at,
            clock=asyncio.get_running_loop().time,
            checkpoint=self._checkpoint,
            progress=progress,
        )
        return dict(self._playback)

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
            entry = {
                key: value
                for key, value in req.items()
                if not key.startswith("_")
            }
            resp = req.get("_response") or self._responses.get(
                req["request_id"], {},
            )
            completion = req.get("_completion") or getattr(
                self, "_completions", {},
            ).get(req["request_id"], {})
            entry["connection_id"] = resp.get("connection_id")
            entry["remote_ip"] = resp.get("remote_ip", "")
            entry["remote_port"] = resp.get("remote_port", 0)
            entry["connection_reused"] = resp.get("connection_reused", False)
            entry["response_status"] = resp.get("status", 0)
            entry["response_timestamp"] = resp.get("timestamp", 0.0)
            entry["completion_timestamp"] = completion.get("timestamp", 0.0)
            entry["failed"] = completion.get("failed", False)
            entry["canceled"] = completion.get("canceled", False)
            entry["failure_reason"] = completion.get("failure_reason", "")
            entry["from_disk_cache"] = resp.get("from_disk_cache", False)
            entry["from_service_worker"] = resp.get(
                "from_service_worker", False,
            )
            entry["from_prefetch_cache"] = resp.get(
                "from_prefetch_cache", False,
            )
            target_info = self._targets.get(req.get("target_id", ""), {})
            entry["target_type"] = target_info.get("type", "unknown")
            merged_requests.append(entry)

        data = {
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
                "navigation": dict(getattr(self, "_navigation", {})),
                "warnings": list(getattr(self, "_warnings", [])),
            },
        }
        playback = getattr(self, "_playback", None)
        if playback is not None:
            data["metadata"]["playback"] = dict(playback)
        return data

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


def _response_payload(response: dict, timestamp: float) -> dict:
    return {
        "connection_id": response.get("connectionId"),
        "remote_ip": response.get("remoteIPAddress", ""),
        "remote_port": response.get("remotePort", 0),
        "connection_reused": response.get("connectionReused", False),
        "status": response.get("status", 0),
        "timestamp": timestamp,
        "from_disk_cache": response.get("fromDiskCache", False),
        "from_service_worker": response.get("fromServiceWorker", False),
        "from_prefetch_cache": response.get("fromPrefetchCache", False),
    }


class SyncCDPCollector:
    def __init__(
        self,
        debugging_port: int = 9222,
        cancellation: CancellationToken | None = None,
        cache_mode: str = "warm",
    ):
        self._collector = CDPCollector(debugging_port, cancellation, cache_mode)
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

    def navigate(
        self,
        url: str,
        load_timeout: float = 30.0,
        *,
        wait_for_load: bool = True,
    ) -> None:
        self._run(self._collector.navigate(
            url, load_timeout, wait_for_load=wait_for_load,
        ),
                  timeout=load_timeout + 15)

    def collect(self, seconds: float) -> None:
        self._run(self._collector.collect(seconds), timeout=seconds + 10)

    def collect_playback(
        self,
        seconds: float,
        policy: PlaybackPolicy,
        progress=None,
    ) -> dict:
        return self._run(
            self._collector.collect_playback(seconds, policy, progress),
            timeout=seconds + 15,
        )

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
