# CDP Collection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add CDP request-level semantic collection to the capture pipeline, fix Chrome graceful shutdown, and add NetLog JSON repair.

**Architecture:** Async CDP client with sync wrapper using a threaded event loop. Pipeline conditionally branches: CDP path (about:blank launch, CDP navigate, Browser.close) vs legacy path (direct URL launch, sleep, kill). NetLog repair runs after Chrome close in both paths.

**Tech Stack:** Python 3.10+, asyncio, websockets, threading, subprocess, pyyaml

## Global Constraints

- All new config fields must have defaults (backward compatible)
- `enable_cdp: false` must fall back to original pipeline behavior
- `--only` CLI flag unchanged
- Existing output files unchanged; `cdp_*.json` is additive
- All CDP commands must carry a timeout
- Never block on WebSocket close or Network.loadingFinished
- Existing tests must continue to pass

---

### Task 1: Install websockets dependency

**Files:**
- None (pip install)

**Interfaces:**
- Produces: `websockets` package available for import

- [ ] **Step 1: Install websockets**

Run: `pip install websockets`

- [ ] **Step 2: Verify installation**

Run: `python3 -c "import websockets; print(websockets.__version__)"`
Expected: version string printed, no errors

- [ ] **Step 3: Commit**

```bash
# No code changes to commit unless there's a requirements file
git status
```

---

### Task 2: Extend Config with CDP fields

**Files:**
- Modify: `traffictracer/config.py`

**Interfaces:**
- Produces: `ChromeConfig(enable_cdp, remote_debugging_port, netlog_capture_mode, graceful_close_timeout)`, `SiteConfig(wait_load_timeout)`
- Consumed by: Task 5 (chrome.py), Task 6 (pipeline.py)

- [ ] **Step 1: Update ChromeConfig dataclass**

Read `traffictracer/config.py` first (already read).

In `traffictracer/config.py`, add fields to `ChromeConfig`:

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
```

- [ ] **Step 2: Update SiteConfig dataclass**

In `traffictracer/config.py`, add field to `SiteConfig`:

```python
@dataclass
class SiteConfig:
    domain: str
    url: str
    wait: int = 10
    traffic_type: str = "all"
    wait_load_timeout: int = 30
```

- [ ] **Step 3: Update load_config to parse new ChromeConfig fields**

In `load_config()`, update the ChromeConfig construction:

```python
    c = g.get("chrome", {})
    chrome = ChromeConfig(
        binary=c.get("binary", "google-chrome"),
        user_data_dir=c.get("user_data_dir", "/tmp/chrome-profile"),
        headless=c.get("headless", False),
        enable_cdp=c.get("enable_cdp", True),
        remote_debugging_port=c.get("remote_debugging_port", 9222),
        netlog_capture_mode=c.get("netlog_capture_mode", "Default"),
        graceful_close_timeout=c.get("graceful_close_timeout", 20),
    )
```

- [ ] **Step 4: Update load_config to parse new SiteConfig field**

In `load_config()`, update the SiteConfig construction:

```python
        sites.append(SiteConfig(
            domain=s["domain"],
            url=s["url"],
            wait=s.get("wait", 10),
            traffic_type=s.get("traffic_type", "all"),
            wait_load_timeout=s.get("wait_load_timeout", 30),
        ))
```

- [ ] **Step 5: Run existing config tests**

Run: `python3 test/test_config.py`
Expected: "✓ All config tests passed!"

- [ ] **Step 6: Commit**

```bash
git add traffictracer/config.py
git commit -m "feat: add CDP fields to ChromeConfig and SiteConfig"
```

---

### Task 3: Create NetLog repair utility

**Files:**
- Create: `traffictracer/capture/netlog_fix.py`
- Create: `test/test_netlog_fix.py`

**Interfaces:**
- Produces: `validate_json(path) -> bool`, `repair_truncated_netlog(path) -> bool`
- Consumed by: Task 6 (pipeline.py)

- [ ] **Step 1: Write failing tests**

Create `test/test_netlog_fix.py`:

```python
"""Tests for NetLog JSON repair."""
import json
import os
import sys
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.capture.netlog_fix import validate_json, repair_truncated_netlog


def _write_temp(content):
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    tmp.write(content)
    tmp.close()
    return tmp.name


def test_validate_json_valid():
    path = _write_temp('{"a": 1}')
    try:
        assert validate_json(path) is True
    finally:
        os.unlink(path)


def test_validate_json_invalid():
    path = _write_temp('{"a": 1,')
    try:
        assert validate_json(path) is False
    finally:
        os.unlink(path)


def test_repair_already_valid():
    path = _write_temp('{"a": 1}\n')
    try:
        assert repair_truncated_netlog(path) is True
        with open(path) as f:
            assert json.load(f) == {"a": 1}
    finally:
        os.unlink(path)


def test_repair_truncated_with_comma():
    path = _write_temp('{"a": 1,\n"b": 2,')
    try:
        assert repair_truncated_netlog(path) is True
        with open(path) as f:
            assert json.load(f) == {"a": 1, "b": 2}
        # Backup should exist
        bak = path + ".truncated.bak"
        assert os.path.exists(bak)
        os.unlink(bak)
    finally:
        os.unlink(path)


def test_repair_truncated_netlog_style():
    path = _write_temp('{"constants": {"a": 1},\n"events": [\n{"e":1},\n{"e":2},\n')
    try:
        result = repair_truncated_netlog(path)
        with open(path) as f:
            data = json.load(f)
        assert len(data["events"]) == 2
        bak = path + ".truncated.bak"
        assert os.path.exists(bak)
        os.unlink(bak)
    finally:
        os.unlink(path)


def test_repair_unfixable():
    content = 'not json at all {{{'
    path = _write_temp(content)
    try:
        assert repair_truncated_netlog(path) is False
        with open(path) as f:
            assert f.read() == content
        bak = path + ".truncated.bak"
        assert os.path.exists(bak)
        os.unlink(bak)
    finally:
        os.unlink(path)


def test_repair_value_list_truncated():
    path = _write_temp('["events", [')
    try:
        result = repair_truncated_netlog(path)
        bak = path + ".truncated.bak"
        assert os.path.exists(bak)
        os.unlink(bak)
    finally:
        os.unlink(path)


if __name__ == "__main__":
    test_validate_json_valid()
    test_validate_json_invalid()
    test_repair_already_valid()
    test_repair_truncated_with_comma()
    test_repair_truncated_netlog_style()
    test_repair_unfixable()
    test_repair_value_list_truncated()
    print("\n✓ All NetLog fix tests passed!")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 test/test_netlog_fix.py`
Expected: ImportError (module doesn't exist yet)

- [ ] **Step 3: Implement validate_json**

Create `traffictracer/capture/netlog_fix.py`:

```python
"""NetLog JSON validation and truncated repair."""

from __future__ import annotations

import json
from pathlib import Path
import shutil

from ..utils import logger


def validate_json(path: str) -> bool:
    try:
        with open(path, "r", encoding="utf-8") as f:
            json.load(f)
        return True
    except (json.JSONDecodeError, ValueError):
        return False
```

- [ ] **Step 4: Run tests — validate_json tests should pass now**

Run: `python3 test/test_netlog_fix.py`
Expected: at least `test_validate_json_valid` and `test_validate_json_invalid` pass, other tests fail with AttributeError

- [ ] **Step 5: Implement repair_truncated_netlog**

Append to `traffictracer/capture/netlog_fix.py`:

```python
def repair_truncated_netlog(path: str) -> bool:
    if validate_json(path):
        return True

    with open(path, "r", encoding="utf-8") as f:
        original = f.read()

    bak_path = path + ".truncated.bak"
    shutil.copy2(path, bak_path)
    logger.info("Backed up truncated NetLog to %s", bak_path)

    stripped = original.rstrip()
    if stripped.endswith(","):
        stripped = stripped[:-1]

    repaired = stripped + "\n]}\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(repaired)

    if validate_json(path):
        logger.info("NetLog repaired successfully: %s", path)
        return True

    with open(path, "w", encoding="utf-8") as f:
        f.write(original)
    logger.warning("NetLog repair failed, original restored: %s", path)
    return False
```

- [ ] **Step 6: Run all tests**

Run: `python3 test/test_netlog_fix.py`
Expected: "✓ All NetLog fix tests passed!"

- [ ] **Step 7: Commit**

```bash
git add traffictracer/capture/netlog_fix.py test/test_netlog_fix.py
git commit -m "feat: add NetLog JSON validation and truncated repair"
```

---

### Task 4: Create CDP client

**Files:**
- Create: `traffictracer/capture/cdp.py`
- Create: `test/test_cdp.py`

**Interfaces:**
- Produces: `CDPClient` (async), `SyncCDPClient` (sync wrapper)
- SyncCDPClient methods: `__init__(debugging_port)`, `enable_domains()`, `navigate(url)`, `collect(seconds) -> list[dict]`, `close_browser()`, `close()`
- Consumed by: Task 6 (pipeline.py)

- [ ] **Step 1: Write failing tests with mocked WebSocket**

Create `test/test_cdp.py`:

```python
"""Tests for CDP client (mocked WebSocket)."""

import json
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import patch, MagicMock, AsyncMock
import asyncio

from traffictracer.capture.cdp import CDPClient, SyncCDPClient


class FakeWS:
    def __init__(self, send_queue=None):
        self.sent = []
        self._recv_queue = send_queue or []
        self._idx = 0
        self.closed = False

    async def send(self, msg):
        self.sent.append(json.loads(msg))

    async def recv(self):
        if self._idx >= len(self._recv_queue):
            await asyncio.sleep(0.01)
            return json.dumps({"method": "Page.loadEventFired", "params": {}})
        item = json.dumps(self._recv_queue[self._idx])
        self._idx += 1
        return item

    async def close(self):
        self.closed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


def make_mock_info_response(ws_url):
    async def mock_get(*args, **kwargs):
        class FakeResp:
            async def read(self):
                return json.dumps({
                    "webSocketDebuggerUrl": ws_url,
                }).encode()
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
        return FakeResp()
    return mock_get


def test_sync_cdp_client_events_collected():
    events = []

    async def connect_side(client_self):
        events.append(("send", "Network.enable"))
        events.append(("send", "Page.enable"))

    async def navigate_side(client_self, url):
        events.append(("navigate", url))

    def collect_side(client_self, seconds):
        events.append(("collect", seconds))
        return [
            {"method": "Network.requestWillBeSent", "params": {"request": {"url": "https://example.com"}}},
            {"method": "Network.responseReceived", "params": {"response": {"url": "https://example.com", "status": 200}}},
            {"method": "Page.loadEventFired", "params": {}},
        ]

    with patch.object(CDPClient, 'connect_to_page', connect_side):
        with patch.object(CDPClient, 'navigate', navigate_side):
            with patch.object(CDPClient, '_collect_events', collect_side):
                client = SyncCDPClient(debugging_port=9222)
                client.enable_domains()
                client.navigate("https://example.com")
                result = client.collect(5)
                client.close()

    assert len(result) == 3
    assert result[0]["method"] == "Network.requestWillBeSent"
    assert result[1]["method"] == "Network.responseReceived"
    assert result[2]["method"] == "Page.loadEventFired"
    assert ("navigate", "https://example.com") in events
    assert ("collect", 5) in events


def test_cdp_client_send_receives_response():
    recv_queue = [
        {"id": 1, "result": {}},
    ]

    async def run():
        ws = FakeWS(recv_queue)
        client = CDPClient(9222)
        client._ws = ws
        reader_task = asyncio.ensure_future(client._reader_loop())
        await asyncio.sleep(0.05)
        result = await client.send("Network.enable", timeout=2)
        reader_task.cancel()
        try:
            await reader_task
        except asyncio.CancelledError:
            pass
        assert result == {"result": {}}
        assert len(ws.sent) == 1
        assert ws.sent[0]["method"] == "Network.enable"
        assert ws.sent[0]["id"] == 1

    asyncio.run(run())


if __name__ == "__main__":
    test_sync_cdp_client_events_collected()
    test_cdp_client_send_receives_response()
    print("\n✓ All CDP client tests passed!")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 test/test_cdp.py`
Expected: ImportError (module doesn't exist yet)

- [ ] **Step 3: Implement CDPClient (async)**

Create `traffictracer/capture/cdp.py`:

```python
"""CDP client for Chrome DevTools Protocol — request-level event collection."""

from __future__ import annotations

import asyncio
import json
import threading
import time
import urllib.request

import websockets

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
        except websockets.exceptions.ConnectionClosed:
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
```

- [ ] **Step 4: Run tests**

Run: `python3 test/test_cdp.py`
Expected: "✓ All CDP client tests passed!"

- [ ] **Step 5: Commit**

```bash
git add traffictracer/capture/cdp.py test/test_cdp.py
git commit -m "feat: add async CDP client with sync wrapper"
```

---

### Task 5: Extend Chrome manager

**Files:**
- Modify: `traffictracer/capture/chrome.py`
- Modify: `test/test_chrome.py`

**Interfaces:**
- Produces: `launch_chrome(binary, url, netlog_path, user_data_dir, headless, proxy_server, remote_debugging_port, netlog_capture_mode, open_url, extra_args) -> Popen`, `wait_chrome_exit(proc, timeout) -> bool`, `terminate_chrome(proc, timeout) -> None`
- Consumed by: Task 6 (pipeline.py)

- [ ] **Step 1: Update test_chrome.py with new tests**

Read `test/test_chrome.py` first (already read).

Replace `test/test_chrome.py`:

```python
"""Tests for Chrome manager (no live Chrome required)."""

import os
import sys
import subprocess
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.capture.chrome import (
    launch_chrome, terminate_chrome, wait_chrome_exit,
)


def test_terminate_chrome():
    proc = subprocess.Popen(
        ["sleep", "5"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    terminate_chrome(proc)
    assert proc.poll() is not None


def test_terminate_chrome_already_exited():
    proc = subprocess.Popen(
        ["true"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    proc.wait()
    terminate_chrome(proc)
    assert proc.poll() == 0


def test_wait_chrome_exit_exits():
    proc = subprocess.Popen(
        ["sleep", "1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_chrome_exit(proc, timeout=5) is True
    assert proc.poll() is not None


def test_wait_chrome_exit_timeout():
    proc = subprocess.Popen(
        ["sleep", "30"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_chrome_exit(proc, timeout=1) is False
    assert proc.poll() is None
    terminate_chrome(proc)


def test_launch_chrome_minimal():
    proc = launch_chrome(
        binary="echo",
        url="about:blank",
        netlog_path="/tmp/test_netlog.json",
        user_data_dir="/tmp/test-profile",
        headless=True,
        open_url=False,
    )
    proc.wait(timeout=5)
    assert proc.poll() == 0


if __name__ == "__main__":
    test_terminate_chrome()
    test_terminate_chrome_already_exited()
    test_wait_chrome_exit_exits()
    test_wait_chrome_exit_timeout()
    test_launch_chrome_minimal()
    print("\n✓ All Chrome manager tests passed!")
```

- [ ] **Step 2: Run tests to verify failures**

Run: `python3 test/test_chrome.py`
Expected: ImportError for `terminate_chrome`, `wait_chrome_exit` (not defined yet)

- [ ] **Step 3: Implement extended launch_chrome**

Replace `traffictracer/capture/chrome.py`:

```python
"""Chrome browser subprocess management for NetLog capture."""

from __future__ import annotations

import subprocess
from pathlib import Path

from ..utils import logger


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
) -> subprocess.Popen:
    Path(netlog_path).parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        binary,
        f"--user-data-dir={user_data_dir}",
        f"--log-net-log={netlog_path}",
        f"--net-log-capture-mode={netlog_capture_mode}",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    if headless:
        cmd.append("--headless=new")
        cmd.append("--autoplay-policy=no-user-gesture-required")
        cmd.append("--disable-features=PreloadMediaEngagementData,MediaEngagementBypassAutoplayPolicies")
        cmd.append("--disable-background-timer-throttling")
        cmd.append("--mute-audio")
    if proxy_server:
        cmd.append(f"--proxy-server={proxy_server}")
    if remote_debugging_port is not None:
        cmd.append(f"--remote-debugging-port={remote_debugging_port}")
        cmd.append("--remote-allow-origins=*")
    if extra_args:
        cmd.extend(extra_args)
    if open_url:
        cmd.append(url)
    else:
        cmd.append("about:blank")
    logger.info("Launching Chrome: %s (CDP=%s) url=%s", binary,
                remote_debugging_port is not None,
                url if open_url else "about:blank")
    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def wait_chrome_exit(proc: subprocess.Popen, timeout: float = 20) -> bool:
    if proc is None or proc.poll() is not None:
        return True
    logger.info("Waiting for Chrome (PID %d) to exit...", proc.pid)
    try:
        proc.wait(timeout=timeout)
        logger.info("Chrome exited cleanly")
        return True
    except subprocess.TimeoutExpired:
        logger.warning("Chrome did not exit within %ss", timeout)
        return False


def terminate_chrome(proc: subprocess.Popen, timeout: float = 15) -> None:
    if proc is None or proc.poll() is not None:
        return
    logger.info("Terminating Chrome (PID %d)", proc.pid)
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning("Chrome did not respond to SIGTERM, sending SIGKILL")
        proc.kill()
        proc.wait()


def kill_chrome(proc: subprocess.Popen) -> None:
    terminate_chrome(proc)
```

- [ ] **Step 4: Run tests**

Run: `python3 test/test_chrome.py`
Expected: "✓ All Chrome manager tests passed!"

- [ ] **Step 5: Verify existing tests still pass**

Run: `python3 test/test_capture_pipeline.py`
Expected: "✓ All capture pipeline tests passed!"

- [ ] **Step 6: Commit**

```bash
git add traffictracer/capture/chrome.py test/test_chrome.py
git commit -m "feat: add CDP support to chrome launcher and graceful exit"
```

---

### Task 6: Integrate CDP into capture pipeline

**Files:**
- Modify: `traffictracer/capture/pipeline.py`

**Interfaces:**
- Consumes: `SyncCDPClient`, `repair_truncated_netlog` (Task 3), `launch_chrome` with new params, `wait_chrome_exit`, `terminate_chrome` (Task 5), `ChromeConfig.enable_cdp`, `ChromeConfig.remote_debugging_port`, `ChromeConfig.graceful_close_timeout`, `SiteConfig.wait_load_timeout` (Task 2)

- [ ] **Step 1: Read current pipeline.py**

Already read.

- [ ] **Step 2: Update imports in pipeline.py**

In `traffictracer/capture/pipeline.py`, replace the import block:

```python
from ..config import Config, GlobalConfig, SiteConfig
from ..utils import logger, ensure_dir, setup_logging
from .mihomo import MihomoManager
from .tshark import start_tshark, stop_tshark
from .chrome import launch_chrome, wait_chrome_exit, terminate_chrome
from .cdp import SyncCDPClient
from .netlog_fix import repair_truncated_netlog
```

- [ ] **Step 3: Replace _capture_domain with CDP-aware version**

Replace the entire body of `_capture_domain()` with:

```python
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
    cdp_client = None

    try:
        mihomo.enable_tracing(mihomo_trace_path)

        proxy_info = mihomo.get_proxy_info()
        proxy_info_path = os.path.join(logs_dir, f"proxy_info_{domain}_{run_tag}.json")
        with open(proxy_info_path, "w") as f:
            json.dump(proxy_info, f, indent=2, ensure_ascii=False)
        logger.info("Proxy info saved to %s", proxy_info_path)

        tun_path = os.path.join(run_dir, "tun.pcap")
        phys_path = os.path.join(run_dir, "phys.pcap")

        tun_proc = start_tshark(g.network.tun_interface, tun_path)
        phys_proc = start_tshark(g.network.phys_interface, phys_path)

        use_cdp = g.chrome.enable_cdp and g.chrome.headless

        if use_cdp:
            cdp_port = g.chrome.remote_debugging_port
            chrome_proc = launch_chrome(
                binary=g.chrome.binary,
                url=site.url,
                netlog_path=netlog_path,
                user_data_dir=os.path.join(g.chrome.user_data_dir, domain),
                headless=g.chrome.headless,
                remote_debugging_port=cdp_port,
                netlog_capture_mode=g.chrome.netlog_capture_mode,
                open_url=False,
            )
            _active_procs.append(chrome_proc)

            time.sleep(3)

            cdp_client = SyncCDPClient(debugging_port=cdp_port)
            cdp_client.enable_domains()
            cdp_client.navigate(site.url, load_timeout=site.wait_load_timeout)

            logger.info("Collecting CDP events for %ds...", site.wait)
            cdp_events = cdp_client.collect(site.wait)

            cdp_log_dir = os.path.dirname(cdp_log_path)
            ensure_dir(cdp_log_dir)
            with open(cdp_log_path, "w") as f:
                json.dump(cdp_events, f, indent=2, ensure_ascii=False)
            logger.info("CDP events saved to %s (%d events)",
                        cdp_log_path, len(cdp_events))

            cdp_client.close_browser()
            cdp_client.close()

            if not wait_chrome_exit(chrome_proc, timeout=g.chrome.graceful_close_timeout):
                terminate_chrome(chrome_proc)
        else:
            chrome_proc = launch_chrome(
                binary=g.chrome.binary,
                url=site.url,
                netlog_path=netlog_path,
                user_data_dir=os.path.join(g.chrome.user_data_dir, domain),
                headless=g.chrome.headless,
            )
            _active_procs.append(chrome_proc)

            logger.info("Waiting %ds for %s...", site.wait, site.url)
            time.sleep(site.wait)

            terminate_chrome(chrome_proc)

        repair_truncated_netlog(netlog_path)

    finally:
        if chrome_proc:
            if chrome_proc in _active_procs:
                _active_procs.remove(chrome_proc)
            if chrome_proc.poll() is None:
                terminate_chrome(chrome_proc)
        if tun_proc:
            stop_tshark(tun_proc)
            if tun_proc in _active_procs:
                _active_procs.remove(tun_proc)
        if phys_proc:
            stop_tshark(phys_proc)
            if phys_proc in _active_procs:
                _active_procs.remove(phys_proc)
        try:
            mihomo.disable_tracing()
        except Exception:
            pass

    logger.info("=== Done capturing %s ===", domain)
```

- [ ] **Step 4: Update kill_chrome calls to terminate_chrome in _cleanup**

In `_capture_domain` finally block (already shown above), and `_cleanup`:

```python
def _cleanup(mihomo_proc, active_procs=None):
    if active_procs:
        for proc in active_procs[:]:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        active_procs.clear()
    if mihomo_proc and mihomo_proc.poll() is None:
        mihomo_proc.terminate()
        mihomo_proc.wait(timeout=10)
```

(No change to _cleanup, just verify it's consistent)

- [ ] **Step 5: Run capture pipeline tests**

Run: `python3 test/test_capture_pipeline.py`
Expected: "✓ All capture pipeline tests passed!"

- [ ] **Step 6: Run config tests**

Run: `python3 test/test_config.py`
Expected: "✓ All config tests passed!"

- [ ] **Step 7: Commit**

```bash
git add traffictracer/capture/pipeline.py
git commit -m "feat: integrate CDP collection and NetLog repair into pipeline"
```

---

### Task 7: Update sites.example.yaml and README

**Files:**
- Modify: `sites.example.yaml`
- Modify: `README.md`

- [ ] **Step 1: Update sites.example.yaml**

Replace `sites.example.yaml`:

```yaml
global:
  mihomo:
    binary: /path/to/mihomo
    config: /path/to/mihomo.yaml
    api: "http://127.0.0.1:9090"
  chrome:
    binary: google-chrome               # or tools/chrome-wrapper.sh if no sudo
    user_data_dir: /tmp/chrome-profile
    headless: false

    enable_cdp: true
    remote_debugging_port: 9222
    netlog_capture_mode: Default
    graceful_close_timeout: 20
  network:
    tun_interface: utun
    phys_interface: eth0                # run 'ip route show default' to find yours
  output:
    base_dir: ./output

sites:
  - domain: bilibili.com
    url: "https://www.bilibili.com"
    wait: 10
    traffic_type: all
    wait_load_timeout: 30
  - domain: youtube.com
    url: "https://www.youtube.com"
    wait: 15
    traffic_type: tcp
```

- [ ] **Step 2: Update README.md**

Read `README.md` first (already read).

In `README.md`, after line 5 (description), add:

```markdown
TrafficTracer now supports CDP-based request-level logging.

CDP is used to collect browser-side request semantics:
tab/page request, URL, resource type, frameId, requestId, response status and timestamps.

NetLog is still used for Chrome network-stack information:
URL_REQUEST, DNS, socket, TLS, QUIC, cache and proxy events.

pcap is still used for real packet-level traffic.
```

Replace the output structure section (around line 120-131) to include cdp file:

```markdown
```
output/2026-07-07_10-35-05/
  captures/bilibili.com/
    tun.pcap              # raw TUN interface capture (pre-proxy)
    phys.pcap             # raw physical interface capture (post-proxy)
  logs/
    netlog_bilibili.com.json          # Chrome NetLog
    cdp_bilibili.com.json             # CDP request events
    mihomo_trace_bilibili.com.jsonl   # Mihomo connection trace (JSONL)
    proxy_info_bilibili.com.json      # proxy node info at capture time
```
```

Replace the NetLog truncated section around line 139-147 with:

```markdown
> **NetLog truncated?** Chrome is now closed through CDP `Browser.close` when CDP is enabled.
> If NetLog is still truncated, TrafficTracer backs up the original file as `*.truncated.bak`
> and attempts conservative repair automatically. No manual fix needed.
```

Update config reference table for Chrome (around line 751-758), add rows:

```markdown
| `chrome.enable_cdp` | Enable CDP request-level collection (default: `true`) |
| `chrome.remote_debugging_port` | Chrome DevTools debugging port (default: `9222`) |
| `chrome.netlog_capture_mode` | NetLog capture mode for `--net-log-capture-mode` (default: `Default`) |
| `chrome.graceful_close_timeout` | Seconds to wait for Chrome graceful exit (default: `20`) |
```

Update sites table (around line 763-770), add row:

```markdown
| `wait_load_timeout` | Max seconds to wait for Page.loadEventFired in CDP mode (default: `30`) |
```

Add data pipeline section before "Configuration Reference":

```markdown
## Data Pipeline

After a CDP-enabled capture, one visit sample contains:

```
CDP:
  Page request semantics, URL, resourceType, requestId, frameId, timestamp

NetLog:
  Chrome network stack events, DNS, socket, TLS, QUIC, cache, proxy

Mihomo trace:
  pre-proxy / post-proxy connection mapping

pcap:
  TUN and physical NIC real packet sequences
```

Correlation target:

```
CDP request
  → NetLog URL_REQUEST / socket / QUIC session
  → Mihomo pre/post proxy mapping
  → pcap flow
```
```

- [ ] **Step 3: Commit**

```bash
git add sites.example.yaml README.md
git commit -m "docs: add CDP collection docs, config fields, and data pipeline"
```

---

### Task 8: Run all tests

**Files:**
- None (verification only)

- [ ] **Step 1: Run all tests in sequence**

```bash
python3 test/test_config.py && \
python3 test/test_netlog_fix.py && \
python3 test/test_cdp.py && \
python3 test/test_chrome.py && \
python3 test/test_capture_pipeline.py
```

Expected: All tests pass with ✓ print statements

- [ ] **Step 2: Verify Python syntax of all new files**

Run:
```bash
python3 -m py_compile traffictracer/config.py && \
python3 -m py_compile traffictracer/capture/netlog_fix.py && \
python3 -m py_compile traffictracer/capture/cdp.py && \
python3 -m py_compile traffictracer/capture/chrome.py && \
python3 -m py_compile traffictracer/capture/pipeline.py
```
Expected: No output (success)

- [ ] **Step 3: Commit if any fixes were needed**

```bash
# Only if fixes were made
git add -A
git commit -m "fix: test and syntax fixes"
```
