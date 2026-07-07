"""CDP client for Chrome DevTools Protocol — request-level event collection."""

from __future__ import annotations

import asyncio
import json
import threading
import time
import urllib.request

import websockets
from websockets.exceptions import ConnectionClosed

from ..utils import logger


class CDPClient:
    def __init__(self, debugging_port: int = 9222):
        self._port = debugging_port
        self._ws = None
        self._cmd_id = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._events: list[dict] = []
        self._reader_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

    async def connect_to_page(self) -> None:
        ws_url = self._get_ws_url()
        if not ws_url:
            raise RuntimeError(
                f"Failed to get CDP WebSocket URL from port {self._port}"
            )
        logger.info("Connecting CDP to %s", ws_url)
        self._ws = await websockets.connect(
            ws_url,
            ping_interval=None,
            max_size=2 ** 26,
        )
        self._reader_task = asyncio.create_task(self._reader_loop())

    def _get_ws_url(self) -> str | None:
        try:
            resp = urllib.request.urlopen(
                f"http://127.0.0.1:{self._port}/json/version",
                timeout=5,
            )
            data = json.loads(resp.read().decode())
            return data.get("webSocketDebuggerUrl")
        except Exception as e:
            logger.warning("Failed to get CDP URL: %s", e)
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
                    self._events.append(msg)
        except ConnectionClosed:
            logger.debug("CDP WebSocket connection closed")
        except Exception as e:
            logger.debug("CDP reader loop error: %s", e)

    async def send(self, method: str, params: dict | None = None,
                   timeout: float = 10.0) -> dict:
        async with self._lock:
            self._cmd_id += 1
            cmd_id = self._cmd_id
            msg = {"id": cmd_id, "method": method}
            if params:
                msg["params"] = params
            future: asyncio.Future = asyncio.get_event_loop().create_future()
            self._pending[cmd_id] = future
            await self._ws.send(json.dumps(msg))
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending.pop(cmd_id, None)
            raise

    async def enable_domains(self) -> None:
        await self.send("Network.enable")
        await self.send("Page.enable")

    async def navigate(self, url: str,
                       load_timeout: float = 30.0) -> dict:
        await self.send("Page.navigate", {"url": url})
        deadline = time.time() + load_timeout
        while time.time() < deadline:
            for evt in self._events:
                if evt.get("method") == "Page.loadEventFired":
                    return evt
            await asyncio.sleep(0.5)
        logger.warning("Page.loadEventFired not received within %ss", load_timeout)
        return {}

    async def _collect_events(self, seconds: float) -> list[dict]:
        await asyncio.sleep(seconds)
        events = list(self._events)
        return events

    async def close_browser(self) -> None:
        try:
            await self.send("Browser.close", timeout=5)
        except Exception:
            logger.warning("Browser.close via CDP failed, will fallback to terminate")

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


class SyncCDPClient:
    def __init__(self, debugging_port: int = 9222):
        self._client = CDPClient(debugging_port)
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._run(self._client.connect_to_page())

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run(self, coro):
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result()

    def enable_domains(self) -> None:
        return self._run(self._client.enable_domains())

    def navigate(self, url: str, load_timeout: float = 30.0) -> dict:
        return self._run(self._client.navigate(url, load_timeout))

    def collect(self, seconds: float) -> list[dict]:
        return self._run(self._client._collect_events(seconds))

    def close_browser(self) -> None:
        self._run(self._client.close_browser())

    def close(self) -> None:
        self._run(self._client.close())
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
