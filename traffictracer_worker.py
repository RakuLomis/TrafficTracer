#!/usr/bin/env python3
"""TrafficTracer Complete JSONL Worker executable."""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path
import signal
import sys
from threading import Event

from traffictracer.contracts import validate_worker_message
from traffictracer.version import COMPLETE_VERSION, WORKER_API_VERSION
from traffictracer.worker.dispatcher import Dispatcher
from traffictracer.worker.protocol import (
    JsonlWriter,
    MessageTooLargeError,
    read_jsonl,
)
from traffictracer.worker.recovery import WorkerRecovery
from traffictracer.worker.services import WorkerServices


class _TerminateWorker(BaseException):
    pass


def _write_response(writer: JsonlWriter, response: dict) -> None:
    try:
        writer.write(response)
    except MessageTooLargeError as exc:
        request_id = response.get("id")
        logging.error(
            "Worker response exceeded protocol limit: id=%r bytes=%d max=%d",
            request_id,
            exc.actual_bytes,
            exc.max_bytes,
        )
        writer.write({
            "api_version": WORKER_API_VERSION,
            "type": "response",
            "id": request_id,
            "error": {
                "code": "RESPONSE_TOO_LARGE",
                "message": "Worker response exceeds the protocol size limit.",
                "data": {
                    "actual_bytes": exc.actual_bytes,
                    "max_bytes": exc.max_bytes,
                },
            },
        })


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root",
        default=os.environ.get(
            "TRAFFICTRACER_OUTPUT_ROOT", "/tmp/traffictracer-complete-sessions"
        ),
        help="Absolute root for managed Complete Sessions",
    )
    parser.add_argument(
        "--controller-endpoint",
        default=os.environ.get("TRAFFICTRACER_CONTROLLER_ENDPOINT", ""),
        help="Mihomo controller used for startup tracing recovery",
    )
    args = parser.parse_args(argv)
    output_root = Path(args.output_root).expanduser().resolve()
    controller_secret = os.environ.get("TRAFFICTRACER_CONTROLLER_SECRET", "")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
        force=True,
    )
    writer = JsonlWriter(sys.stdout.buffer)
    shutdown_event = Event()
    services = WorkerServices(
        output_root,
        notify=writer.write,
        shutdown_event=shutdown_event,
        controller_endpoint=args.controller_endpoint,
        controller_secret=controller_secret,
    )
    dispatcher = Dispatcher(services.handlers())
    recovery = WorkerRecovery(
        services.store,
        restore_tracing=services.restore_tracing,
        notify=writer.write,
    ).run()
    try:
        services.recover_batches()
    except Exception as exc:
        logging.error("Batch startup recovery failed: %s", exc)
    ready = {
        "api_version": WORKER_API_VERSION,
        "type": "notification",
        "method": "worker.ready",
        "params": {
            "version": COMPLETE_VERSION,
            "api_version": WORKER_API_VERSION,
            "output_root": str(output_root),
            "recovery": recovery.to_dict(),
        },
    }
    validate_worker_message(ready)

    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def terminate(signum, frame):
        shutdown_event.set()
        raise _TerminateWorker()

    signal.signal(signal.SIGTERM, terminate)
    try:
        # ready promises the supervisor can immediately request graceful stop.
        # Install the handler before exposing that promise to another process.
        writer.write(ready)
        for frame in read_jsonl(sys.stdin.buffer):
            response = dispatcher.dispatch(frame)
            _write_response(writer, response)
            if shutdown_event.is_set():
                break
    except (_TerminateWorker, KeyboardInterrupt):
        shutdown_event.set()
    except BrokenPipeError:
        shutdown_event.set()
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
        services.jobs.shutdown(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
