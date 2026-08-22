"""Tests for structured CDP collector."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import asyncio
import pytest
from unittest.mock import patch, MagicMock

from traffictracer.capture.cdp import CDPCollector
from traffictracer.playback import PlaybackPolicy


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
    collector._cache_mode = "warm"
    collector._ws = ws
    collector._cmd_id = 0
    collector._pending = {}
    collector._reader_task = None
    collector._lock = asyncio.Lock()
    collector._targets: dict[str, dict] = {}
    collector._session_to_target: dict[str, str] = {}
    collector._requests: list[dict] = []
    collector._responses: dict[str, dict] = {}
    collector._completions: dict[str, dict] = {}
    collector._request_occurrences: dict[object, int] = {}
    collector._websockets: list[dict] = []
    collector._visit_url = ""
    collector._collecting = True
    collector._setup_complete = False
    collector._load_events: dict[str, asyncio.Event] = {}
    collector._enabled_sessions: set[str] = set()
    collector._enable_tasks: set[asyncio.Task] = set()
    collector._warnings: list[dict] = []
    collector._navigation: dict = {}
    return collector


def test_collector_parses_request_will_be_sent():
    async def run():
        ws = FakeWS()
        collector = _make_collector_with_ws(ws)
        collector._targets["T1"] = {"type": "page", "url": "https://www.bilibili.com"}
        collector._session_to_target["S1"] = "T1"

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
                "fromDiskCache": True,
                "fromServiceWorker": False,
                "fromPrefetchCache": False,
            },
        }, session_id="S1")

        collector._reader_task = asyncio.create_task(collector._reader_loop())
        await asyncio.sleep(0.1)
        collector._reader_task.cancel()
        try:
            await collector._reader_task
        except asyncio.CancelledError:
            pass

        assert ("S1", "921.18") in collector._responses
        resp = collector._responses[("S1", "921.18")]
        assert resp["connection_id"] == 17
        assert resp["remote_ip"] == "1.2.3.4"
        assert resp["remote_port"] == 443
        assert resp["connection_reused"] is True
        assert resp["from_disk_cache"] is True

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
            "from_disk_cache": True,
            "from_service_worker": False,
            "from_prefetch_cache": False,
        }

        data = collector.get_structured_data()
        assert data["visit_url"] == "https://www.bilibili.com"
        assert len(data["targets"]) == 1
        assert len(data["requests"]) == 1
        req = data["requests"][0]
        assert req["connection_id"] == 5
        assert req["remote_ip"] == "10.0.0.1"
        assert req["connection_reused"] is False
        assert req["from_disk_cache"] is True

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


def test_late_attached_target_enables_network_and_page():
    async def run():
        ws = FakeWS()
        collector = _make_collector_with_ws(ws)
        collector._setup_complete = True
        sent = []

        async def send(method, params=None, timeout=10.0, session_id=""):
            sent.append((method, session_id))
            return {}

        collector.send = send
        collector._on_target_attached({
            "sessionId": "S2",
            "targetInfo": {
                "targetId": "T2",
                "type": "iframe",
                "url": "https://example.com/frame",
            },
        })
        await asyncio.gather(*collector._enable_tasks)

        assert ("Network.enable", "S2") in sent
        assert ("Page.enable", "S2") in sent
        assert "S2" in collector._enabled_sessions

    asyncio.run(run())


def test_cold_cache_mode_disables_cache_and_bypasses_service_worker():
    async def run():
        collector = _make_collector_with_ws(FakeWS())
        collector._cache_mode = "cold"
        sent = []

        async def send(method, params=None, timeout=10.0, session_id=""):
            sent.append((method, params, session_id))
            return {}

        collector.send = send
        await collector._enable_session("S-cold", "page")
        assert ("Network.setCacheDisabled", {"cacheDisabled": True}, "S-cold") in sent
        assert ("Network.setBypassServiceWorker", {"bypass": True}, "S-cold") in sent

    asyncio.run(run())


def test_navigate_uses_created_target_and_waits_for_load():
    async def run():
        ws = FakeWS()
        collector = _make_collector_with_ws(ws)
        sent = []

        async def send(method, params=None, timeout=10.0, session_id=""):
            sent.append((method, params, session_id))
            if method == "Target.createTarget":
                collector._session_to_target["S3"] = "T3"
                collector._targets["T3"] = {
                    "type": "page",
                    "url": "about:blank",
                }
                return {"targetId": "T3"}
            if method == "Page.navigate":
                collector._dispatch_event({
                    "method": "Page.loadEventFired",
                    "params": {},
                    "sessionId": session_id,
                })
            return {}

        collector.send = send
        await collector.navigate("https://example.com", load_timeout=0.2)

        assert ("Page.navigate", {"url": "https://example.com"}, "S3") in sent
        assert collector._visit_url == "https://example.com"
        assert "S3" not in collector._load_events

    asyncio.run(run())


def test_navigate_command_timeout_keeps_collecting_and_records_warning():
    async def run():
        collector = _make_collector_with_ws(FakeWS())

        async def send(method, params=None, timeout=10.0, session_id=""):
            if method == "Target.createTarget":
                collector._session_to_target["S-timeout"] = "T-timeout"
                collector._targets["T-timeout"] = {
                    "type": "page",
                    "url": "about:blank",
                }
                return {"targetId": "T-timeout"}
            if method == "Page.navigate":
                collector._requests.append({
                    "request_id": "partial.1", "target_id": "T-timeout",
                    "frame_id": "frame", "loader_id": "loader",
                    "url": "https://www.youtube.com/", "resource_type": "Document",
                    "timestamp": 100.0, "initiator_type": "other",
                })
                raise asyncio.TimeoutError()
            return {}

        collector.send = send
        await collector.navigate("https://www.youtube.com/", load_timeout=0.01)

        data = collector.get_structured_data()
        assert len(data["requests"]) == 1
        assert data["metadata"]["navigation"]["status"] == (
            "command_and_load_timeout"
        )
        assert data["metadata"]["warnings"] == [{
            "code": "CDP_NAVIGATE_COMMAND_TIMEOUT",
            "message": "Page.navigate response timed out; collection continued",
        }]

    asyncio.run(run())


if __name__ == "__main__":
    test_collector_parses_request_will_be_sent()
    test_collector_parses_response_received()
    test_collector_structured_data_output()
    test_collector_target_attached()
    test_collector_websocket_created()
    test_late_attached_target_enables_network_and_page()
    test_navigate_uses_created_target_and_waits_for_load()
    print("\n✓ All CDP collector tests passed!")


def test_collect_cancellation_enters_cleanup_window_quickly():
    import time
    from traffictracer.jobs.cancellation import CancellationToken, CancelledError

    async def scenario():
        token = CancellationToken()
        collector = CDPCollector(cancellation=token)
        task = asyncio.create_task(collector.collect(30))
        await asyncio.sleep(0.05)
        started = time.monotonic()
        token.cancel("cancel during collection")
        with pytest.raises(CancelledError, match="cancel during collection"):
            await task
        return time.monotonic() - started

    assert asyncio.run(scenario()) < 2.0


def test_navigation_checks_pre_cancelled_token_before_cdp_commands():
    from traffictracer.jobs.cancellation import CancellationToken, CancelledError

    async def scenario():
        token = CancellationToken()
        token.cancel("cancel before navigation")
        collector = CDPCollector(cancellation=token)
        with pytest.raises(CancelledError, match="cancel before navigation"):
            await collector.navigate("https://example.com")

    asyncio.run(scenario())


def test_collector_records_response_and_failed_lifecycle_timestamps():
    collector = _make_collector_with_ws(FakeWS())
    collector._requests.append({
        "request_id": "failed.1",
        "target_id": "",
        "frame_id": "",
        "loader_id": "",
        "url": "https://assets.example/app.js",
        "resource_type": "Script",
        "timestamp": 10.0,
        "initiator_type": "parser",
    })
    collector._on_response_received({
        "requestId": "failed.1",
        "timestamp": 10.5,
        "response": {"status": 200, "connectionId": 9},
    }, "")
    collector._on_loading_failed({
        "requestId": "failed.1",
        "timestamp": 11.0,
        "canceled": True,
        "errorText": "net::ERR_ABORTED",
    })

    request = collector.get_structured_data()["requests"][0]

    assert request["response_timestamp"] == 10.5
    assert request["completion_timestamp"] == 11.0
    assert request["failed"] is True
    assert request["canceled"] is True
    assert request["failure_reason"] == "net::ERR_ABORTED"


def test_redirect_occurrences_keep_distinct_response_evidence():
    collector = _make_collector_with_ws(FakeWS())
    collector._on_request_will_be_sent({
        "requestId": "redirect.1",
        "timestamp": 10.0,
        "request": {"url": "https://example.com/"},
        "type": "Document",
    }, "")
    collector._on_request_will_be_sent({
        "requestId": "redirect.1",
        "timestamp": 10.5,
        "request": {"url": "https://example.com/"},
        "redirectResponse": {
            "status": 301,
            "connectionId": 7,
            "remoteIPAddress": "198.51.100.7",
            "remotePort": 443,
        },
        "type": "Document",
    }, "")
    collector._on_response_received({
        "requestId": "redirect.1",
        "timestamp": 11.0,
        "response": {
            "status": 200,
            "connectionId": 8,
            "remoteIPAddress": "198.51.100.8",
            "remotePort": 443,
        },
    }, "")

    requests = collector.get_structured_data()["requests"]

    assert [item["url"] for item in requests] == [
        "https://example.com/",
        "https://example.com/",
    ]
    assert [item["redirect_index"] for item in requests] == [0, 1]
    assert requests[1]["redirect_from_url"] == "https://example.com/"
    assert requests[1]["redirect_status"] == 301
    assert [item["response_status"] for item in requests] == [301, 200]
    assert [item["connection_id"] for item in requests] == [7, 8]
    assert [item["remote_ip"] for item in requests] == [
        "198.51.100.7",
        "198.51.100.8",
    ]


def test_same_request_id_is_isolated_between_cdp_sessions():
    collector = _make_collector_with_ws(FakeWS())
    collector._on_request_will_be_sent({
        "requestId": "shared.1",
        "timestamp": 10.0,
        "request": {"url": "https://one.example/"},
        "type": "Document",
    }, "S1")
    collector._on_request_will_be_sent({
        "requestId": "shared.1",
        "timestamp": 10.1,
        "request": {"url": "https://two.example/"},
        "type": "Document",
    }, "S2")

    requests = collector.get_structured_data()["requests"]

    assert [item["redirect_index"] for item in requests] == [0, 0]
    assert collector._warnings == []


def test_playback_interaction_dispatches_cdp_mouse_sequence_to_page_session():
    async def scenario():
        collector = _make_collector_with_ws(FakeWS())
        collector._page_session = "PAGE-SESSION"
        collector._navigation_started_at = asyncio.get_running_loop().time()
        sent = []

        async def send(method, params=None, timeout=10, session_id=""):
            sent.append((method, params, session_id))
            return {}

        async def observe(policy, seconds, **kwargs):
            assert policy.provider == "youtube"
            assert seconds == 35
            assert await kwargs["recover"]() is True
            assert await kwargs["interact"](
                "skip", {"center_x": 442.0, "center_y": 315.0},
            ) is True
            return {"primary_content_observed": True}

        collector.send = send
        with patch(
            "traffictracer.capture.cdp.observe_youtube_playback", observe,
        ):
            result = await collector.collect_playback(
                35, PlaybackPolicy("youtube"),
            )
        assert result["primary_content_observed"] is True
        assert [item[0] for item in sent] == [
            "Page.reload",
            "Input.dispatchMouseEvent",
            "Input.dispatchMouseEvent",
            "Input.dispatchMouseEvent",
        ]
        assert sent[0][1] == {"ignoreCache": False}
        assert [item[1]["type"] for item in sent[1:]] == [
            "mouseMoved", "mousePressed", "mouseReleased",
        ]
        assert all(item[2] == "PAGE-SESSION" for item in sent)
        assert sent[2][1]["button"] == "left"
        assert sent[3][1]["clickCount"] == 1

    asyncio.run(scenario())


def test_playback_interaction_rejects_non_finite_coordinates():
    async def scenario():
        collector = _make_collector_with_ws(FakeWS())
        collector._page_session = "PAGE-SESSION"
        collector._navigation_started_at = asyncio.get_running_loop().time()

        async def observe(_policy, _seconds, **kwargs):
            await kwargs["interact"](
                "play", {"center_x": float("nan"), "center_y": 2},
            )
            return {}

        with patch(
            "traffictracer.capture.cdp.observe_youtube_playback", observe,
        ):
            with pytest.raises(ValueError, match="must be finite"):
                await collector.collect_playback(
                    35,
                    PlaybackPolicy("youtube"),
                )

    asyncio.run(scenario())
