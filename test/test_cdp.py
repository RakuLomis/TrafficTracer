"""Tests for CDP client (mocked WebSocket)."""

import json
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import patch
import asyncio

from traffictracer.capture.cdp import CDPClient, SyncCDPClient


class FakeWS:
    def __init__(self, send_queue=None):
        self.sent = []
        self._recv = asyncio.Queue()
        self.closed = False
        if send_queue:
            for item in send_queue:
                self._recv.put_nowait(json.dumps(item))

    async def send(self, msg):
        parsed = json.loads(msg)
        self.sent.append(parsed)
        cmd_id = parsed.get("id")
        if cmd_id is not None:
            await self._recv.put(json.dumps({"id": cmd_id, "result": {}}))

    async def close(self):
        self.closed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await self._recv.get()
        except Exception:
            raise StopAsyncIteration


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
        pass

    async def enable_side(client_self):
        events.append(("send", "Network.enable"))
        events.append(("send", "Page.enable"))

    async def navigate_side(client_self, url, load_timeout=30.0):
        events.append(("navigate", url))

    async def collect_side(client_self, seconds):
        events.append(("collect", seconds))
        return [
            {"method": "Network.requestWillBeSent", "params": {"request": {"url": "https://example.com"}}},
            {"method": "Network.responseReceived", "params": {"response": {"url": "https://example.com", "status": 200}}},
            {"method": "Page.loadEventFired", "params": {}},
        ]

    with patch.object(CDPClient, 'connect_to_page', connect_side):
        with patch.object(CDPClient, 'enable_domains', enable_side):
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
    async def run():
        ws = FakeWS()
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
        assert result == {}
        assert len(ws.sent) == 1
        assert ws.sent[0]["method"] == "Network.enable"
        assert ws.sent[0]["id"] == 1

    asyncio.run(run())


if __name__ == "__main__":
    test_sync_cdp_client_events_collected()
    test_cdp_client_send_receives_response()
    print("\n✓ All CDP client tests passed!")
