"""Cooperative, thread-safe cancellation for a single Complete job."""

from __future__ import annotations

from threading import Event, Lock


class CancelledError(Exception):
    """Raised at a cancellation checkpoint after cancellation was requested."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class InterruptedError(CancelledError):
    """Raised when a resumable batch interruption reaches a checkpoint."""


class CancellationToken:
    """An idempotent cancellation signal that preserves the first reason."""

    def __init__(self) -> None:
        self._event = Event()
        self._lock = Lock()
        self._reason = ""
        self._intent = ""

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str:
        with self._lock:
            return self._reason

    @property
    def intent(self) -> str:
        """Return the requested stop intent, or an empty string."""
        with self._lock:
            return self._intent

    @property
    def interrupted(self) -> bool:
        return self.intent == "interrupt"

    def cancel(self, reason: str = "cancelled") -> bool:
        """Request cancellation, returning True only for the first caller."""
        return self._request("cancel", reason, "cancelled")

    def interrupt(self, reason: str = "interrupted") -> bool:
        """Request resumable interruption, returning True for the first caller."""
        return self._request("interrupt", reason, "interrupted")

    def _request(self, intent: str, reason: str, fallback: str) -> bool:
        normalized = reason.strip() or fallback
        with self._lock:
            if self._event.is_set():
                return False
            self._intent = intent
            self._reason = normalized
            self._event.set()
            return True

    def wait(self, timeout: float | None = None) -> bool:
        """Wait until cancelled or timeout, mirroring threading.Event.wait."""
        return self._event.wait(timeout)

    def checkpoint(self) -> None:
        """Raise CancelledError if cancellation has been requested."""
        if not self._event.is_set():
            return
        with self._lock:
            reason = self._reason
            intent = self._intent
        error_type = InterruptedError if intent == "interrupt" else CancelledError
        raise error_type(reason)
