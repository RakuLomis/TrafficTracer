#!/usr/bin/env python3
"""Manage persisted TrafficTracer serial batches without UI state."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from threading import Event

from traffictracer.worker.services import WorkerServices


def _services(args) -> WorkerServices:
    return WorkerServices(
        Path(args.output_root).expanduser().resolve(),
        notify=lambda message: None,
        shutdown_event=Event(),
        controller_endpoint=args.controller_endpoint,
        controller_secret=os.environ.get("TRAFFICTRACER_CONTROLLER_SECRET", ""),
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--controller-endpoint", default="")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    status = commands.add_parser("status")
    status.add_argument("batch_id")
    start = commands.add_parser("start")
    start.add_argument("job_json")
    resume = commands.add_parser("resume")
    resume.add_argument("batch_id")
    cancel = commands.add_parser("cancel")
    cancel.add_argument("batch_id")
    args = parser.parse_args(argv)
    services = _services(args)
    try:
        if args.command == "list":
            result = services.batch_list({})
        elif args.command == "status":
            result = services.batch_status({"batch_id": args.batch_id})
        elif args.command == "cancel":
            result = services.batch_cancel({"batch_id": args.batch_id})
        else:
            if args.command == "start":
                with Path(args.job_json).open(encoding="utf-8") as stream:
                    started = services.batch_start({"job": json.load(stream)})
            else:
                services.recover_batches()
                started = services.batch_resume({"batch_id": args.batch_id})
            try:
                services.jobs.wait(started["job_id"])
            except KeyboardInterrupt:
                services.batch_cancel({
                    "batch_id": started["job_id"],
                    "reason": "CLI interrupted by user.",
                })
                services.jobs.wait(started["job_id"], timeout=10)
                return 130
            result = services.batch_status({"batch_id": started["job_id"]})
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
