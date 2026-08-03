"""Job-scoped single-domain capture lifecycle."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any

from traffictracer.jobs.cancellation import CancellationToken, CancelledError
from traffictracer.jobs.models import CaptureJobResult, CaptureJobSpec, JobState
from traffictracer.jobs.process_registry import ProcessRegistry
from traffictracer.jobs.progress import JobStage, ProgressReporter
from traffictracer.session.atomic import write_json_atomic
from traffictracer.session.recovery import (
    RECOVERY_JOURNAL_NAME,
    RecoveryJournal,
    TracingSnapshot,
)
from traffictracer.session.store import SessionStore
from traffictracer.utils import logger

from .cdp import SyncCDPCollector
from .chrome import launch_chrome, terminate_chrome, wait_chrome_exit
from .mihomo import MihomoManager
from .netlog_fix import repair_truncated_netlog
from .tshark import start_packet_capture, stop_packet_capture


@dataclass(frozen=True)
class CaptureSessionContext:
    session_id: str
    directory: Path
    store: SessionStore | None = None


@dataclass(frozen=True)
class CaptureRuntime:
    user_data_dir: str
    enable_cdp: bool = True
    remote_debugging_port: int = 9222
    netlog_capture_mode: str = "Default"
    graceful_close_timeout: int = 20
    disable_background_networking: bool = False
    wait_load_timeout: int = 30
    run_label: str = ""


class CaptureJob:
    def __init__(
        self,
        spec: CaptureJobSpec,
        *,
        runtime: CaptureRuntime,
        mihomo: MihomoManager,
        session: CaptureSessionContext,
        registry: ProcessRegistry,
        progress: ProgressReporter,
        cancellation: CancellationToken,
        finalize_progress: bool = True,
    ) -> None:
        spec.to_dict()
        self.spec = spec
        self.runtime = runtime
        self.mihomo = mihomo
        self.session = session
        self.registry = registry
        self.progress = progress
        self.cancellation = cancellation
        self.finalize_progress = finalize_progress
        self._artifacts: list[str] = []

    def run(self) -> CaptureJobResult:
        try:
            self._run()
        except CancelledError:
            self.registry.cleanup()
            self.progress.finish(JobState.CANCELLED, self.cancellation.reason)
            raise
        except Exception:
            self.progress.finish(JobState.FAILED, "capture failed")
            raise
        if self.finalize_progress:
            self.progress.finish(JobState.COMPLETED, "capture complete")
        return CaptureJobResult(
            job_id=self.spec.job_id,
            state=JobState.COMPLETED,
            session_id=self.session.session_id,
            artifacts=tuple(self._artifacts),
        )

    def _run(self) -> None:
        self.cancellation.checkpoint()
        self.progress.emit(JobState.PREPARING, JobStage.PREPARING, 0.05)
        paths = self._prepare_paths()
        previous_tracing: dict[str, Any] | None = None
        tun_capture = None
        phys_capture = None
        chrome_proc = None
        collector = None

        capture_context = {
            "schema_version": 1,
            "job_id": self.spec.job_id,
            "session_id": self.session.session_id,
            "target": {"url": self.spec.url, "domain": self.spec.domain},
            "interfaces": self.spec.interfaces.to_dict(),
            "output_root": self.spec.output_root,
        }
        write_json_atomic(paths["capture_context"], capture_context)
        self._record(paths["capture_context"])

        try:
            self.cancellation.checkpoint()
            self.progress.emit(JobState.PREPARING, JobStage.CORE_CONFIGURE, 0.1)
            previous_tracing = self.mihomo.get_tracing_status()
            self._persist_recovery(previous_tracing)
            self.mihomo.enable_tracing(
                str(paths["mihomo_trace"]), session_id=self.session.session_id
            )
            self._record(paths["mihomo_trace"])

            proxy_info = self.mihomo.get_proxy_info()
            write_json_atomic(paths["proxy_info"], proxy_info)
            self._record(paths["proxy_info"])

            if self.spec.options.capture_packets:
                self.cancellation.checkpoint()
                self.progress.emit(
                    JobState.CAPTURING, JobStage.CAPTURE_PACKETS, 0.2
                )
                tun_capture = start_packet_capture(
                    self.spec.interfaces.tun, paths["tun_pcap"]
                )
                self.registry.register(tun_capture.process, "tshark-tun")
                self._persist_recovery(previous_tracing)
                phys_capture = start_packet_capture(
                    self.spec.interfaces.physical, paths["phys_pcap"]
                )
                self.registry.register(phys_capture.process, "tshark-physical")
                self._persist_recovery(previous_tracing)
                self._record(paths["tun_pcap"])
                self._record(paths["phys_pcap"])

            self.cancellation.checkpoint()
            self.progress.emit(JobState.CAPTURING, JobStage.CAPTURE_BROWSER, 0.4)
            use_cdp = self.runtime.enable_cdp and self.spec.options.collect_cdp
            chrome_proc = launch_chrome(
                binary=self.spec.chrome_binary,
                url=self.spec.url,
                netlog_path=str(paths["netlog"]),
                user_data_dir=str(paths["profile"]),
                headless=self.spec.options.headless,
                remote_debugging_port=(
                    self.runtime.remote_debugging_port if use_cdp else None
                ),
                netlog_capture_mode=self.runtime.netlog_capture_mode,
                open_url=not use_cdp,
                disable_background_networking=self.runtime.disable_background_networking,
            )
            self.registry.register(chrome_proc, "chrome")
            self._persist_recovery(previous_tracing)
            self._record(paths["netlog"])

            if use_cdp:
                collector = SyncCDPCollector(
                    debugging_port=self.runtime.remote_debugging_port,
                    cancellation=self.cancellation,
                )
                collector.connect()
                collector.setup()
                self.cancellation.checkpoint()
                collector.navigate(
                    self.spec.url, load_timeout=self.runtime.wait_load_timeout
                )
                collector.collect(self.spec.duration_seconds)
                self.cancellation.checkpoint()
                collector.stop_collecting()
                write_json_atomic(paths["cdp"], collector.get_structured_data())
                self._record(paths["cdp"])
                collector.close_browser()
                collector.close()
                collector = None
                if not wait_chrome_exit(
                    chrome_proc,
                    timeout=self.runtime.graceful_close_timeout,
                    cancellation=self.cancellation,
                ):
                    terminate_chrome(chrome_proc, cancellation=self.cancellation)
            else:
                self.cancellation.wait(self.spec.duration_seconds)
                self.cancellation.checkpoint()
                terminate_chrome(chrome_proc, cancellation=self.cancellation)

            if self.spec.options.collect_netlog:
                repair_truncated_netlog(str(paths["netlog"]))
        finally:
            self._cleanup_resources(
                collector=collector,
                chrome_proc=chrome_proc,
                tun_capture=tun_capture,
                phys_capture=phys_capture,
                previous_tracing=previous_tracing,
                suppress_errors=sys.exc_info()[0] is not None,
            )

    def _cleanup_resources(
        self,
        *,
        collector: Any,
        chrome_proc: Any,
        tun_capture: Any,
        phys_capture: Any,
        previous_tracing: dict[str, Any] | None,
        suppress_errors: bool,
    ) -> None:
        errors: list[Exception] = []

        def attempt(label: str, action: Any) -> None:
            try:
                action()
            except Exception as exc:
                logger.warning("%s failed: %s", label, exc)
                errors.append(exc)

        attempt(
            "progress cleanup notification",
            lambda: self.progress.emit(
                JobState.CAPTURING, JobStage.CLEANUP, 0.9, force=True
            ),
        )
        if collector is not None:
            attempt("CDP browser close", collector.close_browser)
            attempt("CDP collector close", collector.close)
        if chrome_proc is not None and chrome_proc.poll() is None:
            attempt("Chrome stop", lambda: terminate_chrome(chrome_proc, cancellation=self.cancellation))
        if phys_capture is not None:
            attempt("physical packet capture stop", lambda: stop_packet_capture(phys_capture))
        if tun_capture is not None:
            attempt("TUN packet capture stop", lambda: stop_packet_capture(tun_capture))
        cleanup = self.registry.cleanup()
        if cleanup.errors:
            logger.warning("Process cleanup errors: %s", "; ".join(cleanup.errors))
        if previous_tracing is not None:
            try:
                self.mihomo.restore_tracing(previous_tracing)
                self._clear_recovery()
            except Exception as exc:
                logger.warning("Failed to restore Mihomo tracing state: %s", exc)
                errors.append(exc)
        if errors and not suppress_errors:
            raise errors[0]

    def _prepare_paths(self) -> dict[str, Path]:
        domain_dir = self.session.directory / "captures" / self.spec.domain
        logs_dir = self.session.directory / "logs"
        domain_dir.mkdir(parents=True, exist_ok=True)
        logs_dir.mkdir(parents=True, exist_ok=True)
        index = 1
        run_label = self.runtime.run_label or self.spec.network
        while (domain_dir / f"{run_label}_{index}").exists():
            index += 1
        run_tag = f"{run_label}_{index}"
        run_dir = domain_dir / run_tag
        run_dir.mkdir(mode=0o700)
        return {
            "mihomo_trace": logs_dir
            / f"mihomo_trace_{self.spec.domain}_{run_tag}.jsonl",
            "proxy_info": logs_dir
            / f"proxy_info_{self.spec.domain}_{run_tag}.json",
            "capture_context": logs_dir
            / f"capture_context_{self.spec.domain}_{run_tag}.json",
            "netlog": logs_dir / f"netlog_{self.spec.domain}_{run_tag}.json",
            "cdp": logs_dir / f"cdp_{self.spec.domain}_{run_tag}.json",
            "tun_pcap": run_dir / "tun.pcap",
            "phys_pcap": run_dir / "phys.pcap",
            "profile": Path(self.runtime.user_data_dir)
            / self.spec.domain
            / run_tag,
        }

    def _record(self, path: Path) -> None:
        try:
            relative = path.relative_to(self.session.directory)
        except ValueError:
            return
        value = str(relative)
        if value not in self._artifacts:
            self._artifacts.append(value)

    def _persist_recovery(self, previous_tracing: dict[str, Any]) -> None:
        if self.session.store is None:
            return
        journal = RecoveryJournal.capture(
            session_id=self.session.session_id,
            tracing=TracingSnapshot(
                enabled=previous_tracing.get("enabled") is True,
                output=(
                    previous_tracing.get("output", "")
                    if isinstance(previous_tracing.get("output", ""), str)
                    else ""
                ),
                session_id=(
                    previous_tracing.get("session_id", "")
                    if isinstance(previous_tracing.get("session_id", ""), str)
                    else ""
                ),
            ),
            processes=self.registry.snapshot(),
        )
        journal.persist(self.session.store)

    def _clear_recovery(self) -> None:
        if self.session.store is None:
            return
        path = self.session.store.artifact_path(
            self.session.session_id, RECOVERY_JOURNAL_NAME
        )
        try:
            path.unlink()
        except FileNotFoundError:
            pass
