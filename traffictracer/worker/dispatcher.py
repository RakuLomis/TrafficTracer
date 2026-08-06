"""Validated request routing and stable error mapping for the Complete Worker."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from threading import Lock
from typing import Any

from traffictracer.contracts import ValidationError, validate_worker_message
from traffictracer.jobs.cancellation import CancelledError
from traffictracer.version import (
    COMPLETE_VERSION,
    FLOW_SCHEMA_VERSION,
    JOB_SCHEMA_VERSION,
    SESSION_SCHEMA_VERSION,
    WORKER_API_VERSION,
)

from .protocol import ProtocolFailure


RequestHandler = Callable[[dict[str, Any]], Any]

METHODS = (
    "hello",
    "environment.diagnose",
    "config.targets.load",
    "job.start",
    "job.cancel",
    "job.status",
    "analysis.start",
    "session.list",
    "session.scope.resolve",
    "session.scope.list",
    "session.get",
    "session.delete",
    "session.cleanup.preview",
    "flow.query",
    "batch.start",
    "batch.status",
    "batch.cancel",
    "batch.list",
    "batch.resume",
    "worker.shutdown",
)

ERROR_CODES = frozenset({
    "INVALID_REQUEST",
    "PROTOCOL_VERSION_MISMATCH",
    "METHOD_NOT_FOUND",
    "INVALID_PARAMS",
    "JOB_BUSY",
    "JOB_NOT_FOUND",
    "SESSION_NOT_FOUND",
    "CAPTURE_PERMISSION_DENIED",
    "CORE_UNAVAILABLE",
    "CANCELLED",
    "INTERNAL_ERROR",
})


class WorkerMethodError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        data: Mapping[str, Any] | None = None,
    ) -> None:
        if code not in ERROR_CODES:
            raise ValueError(f"unsupported Worker error code: {code}")
        if not message:
            raise ValueError("Worker error message must not be empty")
        self.code = code
        self.message = message
        self.data = dict(data or {})
        super().__init__(message)


class Dispatcher:
    def __init__(self, handlers: Mapping[str, RequestHandler] | None = None) -> None:
        supplied = dict(handlers or {})
        unknown = set(supplied) - set(METHODS)
        if unknown:
            raise ValueError(f"unknown Worker handlers: {', '.join(sorted(unknown))}")
        self._handlers = supplied
        self._handlers.setdefault("hello", self._hello)
        self._seen_ids: set[str | int] = set()
        self._lock = Lock()

    def dispatch(self, frame: dict[str, Any] | ProtocolFailure) -> dict[str, Any]:
        if isinstance(frame, ProtocolFailure):
            return frame.to_response()
        request_id = frame.get("id") if isinstance(frame, dict) else None
        if not isinstance(frame, dict):
            return _error_response(None, "INVALID_REQUEST", "Request must be an object.")
        if frame.get("api_version") != WORKER_API_VERSION:
            return _error_response(
                request_id if _valid_id(request_id) else None,
                "PROTOCOL_VERSION_MISMATCH",
                f"Worker API version {WORKER_API_VERSION} is required.",
                {"supported": WORKER_API_VERSION},
            )
        if frame.get("type") != "request":
            return _error_response(
                request_id if _valid_id(request_id) else None,
                "INVALID_REQUEST",
                "Dispatcher accepts request messages only.",
            )
        method = frame.get("method")
        if isinstance(method, str) and method not in METHODS:
            return _error_response(
                request_id if _valid_id(request_id) else None,
                "METHOD_NOT_FOUND",
                "Worker method is not supported.",
            )
        try:
            validate_worker_message(frame)
        except ValidationError as exc:
            code = "INVALID_PARAMS" if exc.path[:1] == ("params",) else "INVALID_REQUEST"
            return _error_response(
                request_id if _valid_id(request_id) else None,
                code,
                exc.message,
                {"path": list(exc.path), "rule": exc.rule},
            )

        with self._lock:
            if request_id in self._seen_ids:
                return _error_response(
                    request_id,
                    "INVALID_REQUEST",
                    "Request ID has already been used.",
                    {"reason": "DUPLICATE_REQUEST_ID"},
                )
            self._seen_ids.add(request_id)

        handler = self._handlers.get(method)
        if handler is None:
            return _error_response(
                request_id,
                "METHOD_NOT_FOUND",
                f"Worker method is not available: {method}",
            )
        try:
            result = handler(frame["params"])
        except WorkerMethodError as exc:
            return _error_response(
                request_id, exc.code, exc.message, exc.data or None
            )
        except CancelledError as exc:
            return _error_response(request_id, "CANCELLED", str(exc) or "Job cancelled.")
        except (TypeError, ValueError) as exc:
            return _error_response(
                request_id, "INVALID_PARAMS", str(exc) or "Invalid method parameters."
            )
        except Exception:
            return _error_response(
                request_id,
                "INTERNAL_ERROR",
                "The Worker could not complete the request.",
            )
        return _success_response(request_id, result)

    def _hello(self, params: dict[str, Any]) -> dict[str, Any]:
        if params:
            raise WorkerMethodError(
                "INVALID_PARAMS", "hello does not accept parameters."
            )
        return {
            "product": "TrafficTracer Complete Worker",
            "version": COMPLETE_VERSION,
            "api_version": WORKER_API_VERSION,
            "job_schema_version": JOB_SCHEMA_VERSION,
            "session_schema_version": SESSION_SCHEMA_VERSION,
            "flow_schema_version": FLOW_SCHEMA_VERSION,
            "methods": list(METHODS),
        }


def _success_response(request_id: str | int, result: Any) -> dict[str, Any]:
    response = {
        "api_version": WORKER_API_VERSION,
        "type": "response",
        "id": request_id,
        "result": result,
    }
    validate_worker_message(response)
    return response


def _error_response(
    request_id: str | int | None,
    code: str,
    message: str,
    data: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data:
        error["data"] = dict(data)
    response = {
        "api_version": WORKER_API_VERSION,
        "type": "response",
        "id": request_id,
        "error": error,
    }
    validate_worker_message(response)
    return response


def _valid_id(value: object) -> bool:
    return (
        isinstance(value, str) and 1 <= len(value) <= 128
    ) or (isinstance(value, int) and not isinstance(value, bool) and value >= 0)
