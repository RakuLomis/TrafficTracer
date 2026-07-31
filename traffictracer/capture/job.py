"""Job-scoped single-domain capture lifecycle."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import time
from typing import Any

from traffictracer.jobs.cancellation import CancellationToken, CancelledError
from traffictracer.jobs.models import CaptureJobResult, CaptureJobSpec, JobState
from traffictracer.jobs.process_registry import ProcessRegistry
from traffictracer.jobs.progress import JobStage, ProgressReporter
from traffictracer.session.atomic import write_json_atomic
from traffictracer.utils import logger

from .cdp import SyncCDPCollector
from .chrome import launch_chrome, terminate_chrome, wait_chrome_exit
from .mihomo import MihomoManager
from .netlog_fix import repair_truncated_netlog
from .tshark import start_tshark, stop_tshark


@dataclass(frozen=True)
class CaptureSessionContext:
    session_id: str
    directory: Path


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
    ) -> None:
        spec.to_dict()
        self.spec = spec
        self.runtime = runtime
        self.mihomo = mihomo
        self.session = session
        self.registry = registry
        self.progress = progress
        self.cancellation = cancellation
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
        tun_proc = None
        phys_proc = None
        chrome_proc = None
        collector = None

        try:
            self.cancellation.checkpoint()
            self.progress.emit(JobState.PREPARING, JobStage.CORE_CONFIGURE, 0.1)
            previous_tracing = self.mihomo.get_tracing_status()
            self.mihomo.enable_tracing(str(paths["mihomo_trace"]))
            self._record(paths["mihomo_trace"])

            proxy_info = self.mihomo.get_proxy_info()
            write_json_atomic(paths["proxy_info"], proxy_info)
            self._record(paths["proxy_info"])

            if self.spec.options.capture_packets:
                self.cancellation.checkpoint()
                self.progress.emit(
                    JobState.CAPTURING, JobStage.CAPTURE_PACKETS, 0.2
                )
                tun_proc = start_tshark(
                    self.spec.interfaces.tun, str(paths["tun_pcap"])
                )
                self.registry.register(tun_proc, "tshark-tun")
                phys_proc = start_tshark(
                    self.spec.interfaces.physical, str(paths["phys_pcap"])
                )
                self.registry.register(phys_proc, "tshark-physical")
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
            self._record(paths["netlog"])

            if use_cdp:
                collector = SyncCDPCollector(
                    debugging_port=self.runtime.remote_debugging_port
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
                    chrome_proc, timeout=self.runtime.graceful_close_timeout
                ):
                    terminate_chrome(chrome_proc)
            else:
                time.sleep(self.spec.duration_seconds)
                self.cancellation.checkpoint()
                terminate_chrome(chrome_proc)

            if self.spec.options.collect_netlog:
                repair_truncated_netlog(str(paths["netlog"]))
        finally:
            self.progress.emit(
                JobState.CAPTURING, JobStage.CLEANUP, 0.9, force=True
            )
            if collector is not None:
                try:
                    collector.close_browser()
                finally:
                    collector.close()
            if chrome_proc is not None and chrome_proc.poll() is None:
                terminate_chrome(chrome_proc)
            if tun_proc is not None:
                stop_tshark(tun_proc)
            if phys_proc is not None:
                stop_tshark(phys_proc)
            cleanup = self.registry.cleanup()
            if cleanup.errors:
                logger.warning("Process cleanup errors: %s", "; ".join(cleanup.errors))
            if previous_tracing is not None:
                try:
                    self.mihomo.restore_tracing(previous_tracing)
                except Exception as exc:
                    logger.warning("Failed to restore Mihomo tracing state: %s", exc)

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
