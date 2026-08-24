"""Mihomo process management and API control for tracing."""

from __future__ import annotations

from contextlib import contextmanager
import http.client
import json
from pathlib import Path
import socket
import subprocess
import time
from urllib.parse import urlparse

from ..utils import logger


_PROXY_GROUP_TYPES = frozenset({
    "selector", "urltest", "fallback", "loadbalance", "relay",
})
_NON_PROXY_LEAF_TYPES = frozenset({
    "direct", "reject", "rejectdrop", "dns", "pass", "compatible",
})


def _normalized_proxy_type(value: object) -> str:
    return str(value or "").lower().replace("-", "").replace("_", "")


class MihomoApiError(RuntimeError):
    """An HTTP error returned by the Mihomo controller."""

    def __init__(self, method: str, path: str, status: int, body: str):
        super().__init__(f"Mihomo API {method} {path} returned {status}: {body}")
        self.status = status
        self.body = body


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


class MihomoManager:
    def __init__(self, binary: str, config_path: str, api_url: str, secret: str = ""):
        self.binary = binary
        self.config_path = config_path
        self.api_url = api_url.rstrip("/")
        self.secret = secret

    def start(self, ready_timeout: float = 30.0) -> subprocess.Popen | None:
        if self._api_reachable():
            if self._tracing_reachable():
                logger.info("TrafficTracer Mihomo already running at %s, reusing", self.api_url)
                return None
            logger.error(
                "A non-TrafficTracer Mihomo is already on %s — "
                "stop it first or change the api endpoint in config.", self.api_url,
            )
            raise RuntimeError(f"Non-TrafficTracer Mihomo occupying {self.api_url}")

        config_dir = str(Path(self.config_path).parent)
        logger.info("Starting Mihomo: %s -d %s", self.binary, config_dir)
        proc = subprocess.Popen(
            [self.binary, "-d", config_dir],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._wait_ready(proc, ready_timeout)
        return proc

    def _api_reachable(self) -> bool:
        try:
            self._api_request("GET", "/version", timeout=3)
            return True
        except Exception:
            return False

    def _tracing_reachable(self) -> bool:
        try:
            self._api_request("GET", "/experimental/tracing", timeout=3)
            return True
        except Exception:
            return False

    def _wait_ready(self, proc: subprocess.Popen, timeout: float) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(
                    f"Mihomo exited prematurely with code {proc.returncode}"
                )
            try:
                data = self._api_request("GET", "/version", timeout=3)
                logger.info("Mihomo ready: %s", data.get("version", "unknown"))
                return
            except Exception:
                time.sleep(1)
        raise RuntimeError(
            f"Mihomo API not reachable at {self.api_url} after {timeout}s"
        )

    def stop(self, proc: subprocess.Popen | None) -> None:
        if proc is None or proc.poll() is not None:
            return
        logger.info("Stopping Mihomo (PID %d)", proc.pid)
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    def _connection(self, timeout: float) -> tuple[http.client.HTTPConnection, str]:
        parsed = urlparse(self.api_url)
        if parsed.scheme == "unix":
            socket_path = parsed.path or f"/{parsed.netloc}"
            if not socket_path:
                raise ValueError("Unix Mihomo API must include a socket path")
            return _UnixHTTPConnection(socket_path, timeout), ""
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Mihomo API must use http://, https://, or unix://")
        cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        return cls(parsed.hostname, parsed.port, timeout=timeout), parsed.path.rstrip("/")

    def _api_request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        timeout: float = 10,
    ) -> dict:
        connection, base_path = self._connection(timeout)
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": "application/json", "Host": "localhost"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if self.secret:
            headers["Authorization"] = f"Bearer {self.secret}"
        try:
            connection.request(method, f"{base_path}{path}", body=payload, headers=headers)
            response = connection.getresponse()
            text = response.read().decode("utf-8", errors="replace")
            if not 200 <= response.status < 300:
                raise MihomoApiError(method, path, response.status, text)
            if not text:
                return {}
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"raw": text}
        except (OSError, http.client.HTTPException) as exc:
            logger.error("Mihomo API error: %s %s: %s", method, path, exc)
            raise
        finally:
            connection.close()

    def get_tracing_status(self) -> dict:
        return self._api_request("GET", "/experimental/tracing")

    def patch_tracing(self, state: dict) -> dict:
        return self._api_request("PATCH", "/experimental/tracing", state)

    def trace_barrier(self) -> dict:
        """Flush and return the durable cutoff for the active trace sink."""
        boundary = self._api_request("POST", "/experimental/tracing/barrier")
        required = {"session_id", "event_seq", "ts", "output"}
        if not isinstance(boundary, dict) or not required.issubset(boundary):
            raise RuntimeError("Mihomo returned an invalid trace barrier")
        if not isinstance(boundary["event_seq"], int) or boundary["event_seq"] <= 0:
            raise RuntimeError("Mihomo returned an invalid trace barrier event_seq")
        return boundary

    def restore_tracing(self, state: dict) -> dict:
        patch = {
            "enabled": state.get("enabled", False),
            "output": state.get("output", ""),
            "session_id": state.get("session_id", ""),
        }
        return self.patch_tracing(patch)

    def enable_tracing(self, output_path: str, session_id: str = "") -> dict:
        output_path = str(Path(output_path).expanduser().resolve())
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        logger.info("Enabling Mihomo tracing -> %s", output_path)
        patch = {"enabled": True, "output": output_path}
        if session_id:
            patch["session_id"] = session_id
        return self.patch_tracing(patch)

    def disable_tracing(self) -> dict:
        logger.info("Disabling Mihomo tracing")
        return self.patch_tracing({"enabled": False})

    @contextmanager
    def tracing_session(self, output_path: str, session_id: str = ""):
        """Enable tracing temporarily and restore the controller's prior state."""
        previous = self.get_tracing_status()
        self.enable_tracing(output_path, session_id=session_id)
        try:
            yield
        finally:
            logger.info("Restoring previous Mihomo tracing state")
            self.restore_tracing(previous)

    def get_proxy_info(self) -> list[dict]:
        """Return selected proxy groups with recursively resolved leaf nodes."""
        groups = self._api_request("GET", "/proxies").get("proxies", {})
        result = []
        for group_name, group in groups.items():
            node_name = group.get("now", "")
            if not node_name:
                continue
            leaf_name, chain = _selected_leaf(groups, group_name)
            detail = groups.get(leaf_name, {})
            if not isinstance(detail, dict):
                detail = {}
            result.append({
                "group": group_name,
                "node": node_name,
                "type": groups.get(node_name, {}).get("type", "")
                if isinstance(groups.get(node_name), dict) else "",
                "leaf_node": leaf_name,
                "leaf_type": detail.get("type", ""),
                "selection_chain": chain,
                "server": detail.get("server", ""),
                "port": detail.get("port", ""),
                "network": detail.get("network", ""),
            })
        return result

    def get_proxy_protocol_snapshot(self, selection_group: str = "") -> dict:
        selections = self.get_proxy_info()
        inventory_protocols = sorted({
            _normalized_proxy_type(row.get("leaf_type", ""))
            for row in selections
            if _normalized_proxy_type(row.get("leaf_type", ""))
            not in _PROXY_GROUP_TYPES | _NON_PROXY_LEAF_TYPES | {""}
        })
        selected = next(
            (row for row in selections if row.get("group") == selection_group),
            None,
        ) if selection_group else None
        selected_protocol = _normalized_proxy_type(
            selected.get("leaf_type", "") if selected else ""
        )
        protocols = (
            [selected_protocol]
            if selected_protocol
            and selected_protocol not in _PROXY_GROUP_TYPES | _NON_PROXY_LEAF_TYPES
            else []
        )
        return {
            "mode": "strict_single",
            "status": (
                "single" if protocols
                else "selection_not_found" if selection_group and selected is None
                else "no_proxy" if selection_group
                else "unscoped"
            ),
            "protocols": protocols,
            "expected_protocol": protocols[0] if len(protocols) == 1 else "",
            "selection_group": selection_group,
            "selected_scope": selected or {},
            "inventory_protocols": inventory_protocols,
            "selections": selections,
        }


def _selected_leaf(groups: object, start: str) -> tuple[str, list[str]]:
    if not isinstance(groups, dict):
        return start, [start]
    chain: list[str] = []
    current = start
    seen: set[str] = set()
    while current and current not in seen:
        seen.add(current)
        chain.append(current)
        detail = groups.get(current)
        if not isinstance(detail, dict):
            break
        selected = str(detail.get("now", "") or "")
        if not selected:
            break
        current = selected
    return (chain[-1] if chain else start), chain
