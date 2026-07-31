"""Cooperative, thread-safe cancellation for a single Complete job."""

from __future__ import annotations

from threading import Event, Lock


class CancelledError(Exception):
    """Raised at a cancellation checkpoint after cancellation was requested."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class CancellationToken:
    """An idempotent cancellation signal that preserves the first reason."""

    def __init__(self) -> None:
        self._event = Event()
        self._lock = Lock()
        self._reason = ""

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str:
        with self._lock:
            return self._reason

    def cancel(self, reason: str = "cancelled") -> bool:
        """Request cancellation, returning True only for the first caller."""
        normalized = reason.strip() or "cancelled"
        with self._lock:
            if self._event.is_set():
                return False
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
        raise CancelledError(reason)
