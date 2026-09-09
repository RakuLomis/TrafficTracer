"""Best-effort durable health snapshots, separate from result publication."""

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import os
from pathlib import Path
from threading import Event, Thread, Lock
import time

from traffictracer.session.atomic import write_json_atomic
from traffictracer.utils import logger

_activity = ContextVar("analysis_activity", default=None)


def record_analysis_progress(operation, processed=0, total=None):
    tracker = _activity.get()
    if tracker is None:
        return
    lock, values = tracker
    with lock:
        if values.get("operation") != operation or values.get("processed") != processed:
            values["last_progress_monotonic"] = time.monotonic()
        values.update(operation=operation, processed=processed, total=total)


@contextmanager
def analysis_health(session_dir, job_id, progress, *, interval=5.0, stall_warning_seconds=300):
    path = Path(session_dir) / ".analysis-health.json"
    stopped = Event()
    started = time.monotonic()
    outcome = "running"
    activity_lock = Lock()
    activity = {}
    warned = False
    context_token = _activity.set((activity_lock, activity))

    def write_snapshot():
        nonlocal warned
        try:
            stage = progress.stage
            with activity_lock:
                activity_snapshot = dict(activity)
            last_progress = activity_snapshot.pop("last_progress_monotonic", started)
            activity_snapshot["seconds_since_progress"] = round(time.monotonic() - last_progress, 3)
            stalled = outcome == "running" and time.monotonic() - last_progress >= stall_warning_seconds
            activity_snapshot["stall_warning"] = stalled
            if stalled and not warned:
                logger.warning("ANALYSIS_PROGRESS_STALLED: no measured progress for %s seconds; job remains cancellable", stall_warning_seconds)
            warned = stalled
            memory = {}
            status = Path("/proc/self/status")
            if status.is_file():
                for line in status.read_text().splitlines():
                    key, _, value = line.partition(":")
                    if key in {"VmRSS", "VmHWM", "VmSwap", "Threads"}:
                        memory[key] = value.strip()
            write_json_atomic(path, {
                "schema_version": 1, "job_id": job_id, "pid": os.getpid(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "stage": stage.value if stage is not None else None,
                "state": outcome, "process_memory": memory,
                "activity": activity_snapshot,
                "note": "heartbeat proves liveness, not parsing progress",
            })
        except Exception as error:
            # Diagnostics must never invalidate a successfully published result.
            logger.warning("Analysis health snapshot unavailable: %s", type(error).__name__)

    def monitor():
        while not stopped.wait(interval):
            write_snapshot()
        write_snapshot()

    write_snapshot()
    thread = Thread(target=monitor, name="analysis-health", daemon=True)
    thread.start()
    try:
        result = {}
        yield result
        outcome = result.get("state", "completed")
    except BaseException as error:
        outcome = type(error).__name__
        raise
    finally:
        _activity.reset(context_token)
        stopped.set()
        thread.join(timeout=2.0)
