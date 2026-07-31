"""Non-fatal startup coordination for interrupted Complete Session recovery."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from traffictracer.contracts import validate_worker_message
from traffictracer.session.recovery import (
    ProcessFingerprint,
    RecoveryManager,
    RecoveryReport,
    TracingSnapshot,
)
from traffictracer.session.store import SessionStore
from traffictracer.utils import logger
from traffictracer.version import WORKER_API_VERSION


@dataclass(frozen=True)
class WorkerRecoveryReport:
    recovered_sessions: tuple[str, ...] = ()
    terminated_pids: tuple[int, ...] = ()
    skipped_pids: tuple[int, ...] = ()
    errors: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        return "degraded" if self.errors else "ok"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "recovered_sessions": list(self.recovered_sessions),
            "terminated_pids": list(self.terminated_pids),
            "skipped_pids": list(self.skipped_pids),
            "errors": list(self.errors),
        }


class WorkerRecovery:
    def __init__(
        self,
        store: SessionStore,
        *,
        restore_tracing: Callable[[dict[str, object]], Any],
        notify: Callable[[dict[str, Any]], None] | None = None,
        fingerprint: Callable[[int], ProcessFingerprint | None] | None = None,
        terminate: Callable[[int], None] | None = None,
    ) -> None:
        self._store = store
        self._restore = restore_tracing
        self._notify = notify
        self._fingerprint = fingerprint
        self._terminate = terminate

    def run(self) -> WorkerRecoveryReport:
        try:
            manager = RecoveryManager(
                self._store,
                restore_tracing=self._restore_snapshot,
                fingerprint=self._fingerprint,
                terminate=self._terminate,
            )
            report = manager.recover()
            result = _worker_report(report)
        except Exception as exc:
            logger.error("Worker startup recovery failed: %s", exc)
            result = WorkerRecoveryReport(
                errors=(f"startup recovery scan failed: {_safe_error(exc)}",)
            )
        self._publish(result)
        return result

    def _restore_snapshot(self, snapshot: TracingSnapshot) -> None:
        self._restore(snapshot.to_dict())

    def _publish(self, report: WorkerRecoveryReport) -> None:
        if self._notify is None:
            return
        notification = {
            "api_version": WORKER_API_VERSION,
            "type": "notification",
            "method": "worker.log",
            "params": {
                "level": "warning" if report.errors else "info",
                "code": "RECOVERY_DEGRADED" if report.errors else "RECOVERY_COMPLETE",
                "message": (
                    "Worker recovery completed with errors."
                    if report.errors
                    else "Worker recovery completed."
                ),
                "recovery": report.to_dict(),
            },
        }
        validate_worker_message(notification)
        try:
            self._notify(notification)
        except Exception as exc:
            logger.error("Worker recovery notification failed: %s", exc)


def _worker_report(report: RecoveryReport) -> WorkerRecoveryReport:
    return WorkerRecoveryReport(
        recovered_sessions=report.recovered_sessions,
        terminated_pids=report.terminated_pids,
        skipped_pids=report.skipped_pids,
        errors=report.errors,
    )


def _safe_error(error: Exception) -> str:
    message = str(error).strip()
    return message or error.__class__.__name__
