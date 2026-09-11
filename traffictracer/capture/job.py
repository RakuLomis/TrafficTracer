"""Job-scoped single-domain capture lifecycle."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
import shutil
import time
from typing import Any
from traffictracer.analyze.mihomo_log import (
    observed_proxy_protocols,
)


from traffictracer.jobs.cancellation import (
    CancellationToken,
    CancelledError,
    InterruptedError,
)
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
from .chrome import (
    BrowserHealthToken,
    BrowserProcessError,
    compact_chrome_stderr,
    launch_chrome,
    terminate_chrome,
    wait_chrome_exit,
)
from .mihomo import MihomoManager
from .netlog_fix import repair_truncated_netlog
from .profile import remove_owned_cold_profile
from .quiescence import verify_chrome_quiescence
from .tshark import CaptureMonitor, PacketCaptureError, capture_output_complete, start_packet_capture, stop_packet_capture


class ProxyProtocolInvariantError(RuntimeError):
    code = "PROXY_PROTOCOL_INVARIANT_FAILED"


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
    chrome_quiescence_timeout: float = 2.0
    trace_tail_grace_seconds: float = 0.5
    packet_tail_grace_seconds: float = 0.2


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
        self._capture_monitor = None

    @property
    def artifacts(self) -> tuple[str, ...]:
        return tuple(self._artifacts)

    def run(self) -> CaptureJobResult:
        try:
            self._run()
        except InterruptedError:
            self.registry.cleanup()
            self.progress.finish(JobState.INTERRUPTED, self.cancellation.reason)
            raise
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
        self.progress.emit(
            JobState.PREPARING,
            JobStage.PREPARING,
            0.05,
            operation="capture.prepare_paths",
        )
        paths = self._prepare_paths()
        previous_tracing: dict[str, Any] | None = None
        tracing_configured = False
        tun_capture = None
        phys_capture = None
        chrome_proc = None
        browser_health = None
        collector = None

        capture_context = {
            "trace_policy": {
                "schema_version": 1,
                "immutable_analysis_input": True,
                "retain_journal": self.spec.options.retain_trace_journal,
            },
            "schema_version": 1,
            "job_id": self.spec.job_id,
            "session_id": self.session.session_id,
            "target": {"url": self.spec.url, "domain": self.spec.domain},
            "interfaces": self.spec.interfaces.to_dict(),
            "output_root": self.spec.output_root,
            "cache_mode": self.spec.options.cache_mode,
            "inbound": {
                "mode": "tun",
                "interface": self.spec.interfaces.tun,
                "expected_core_name": "DEFAULT-TUN",
            },
        }
        if self.spec.orchestration is not None:
            capture_context["orchestration"] = self.spec.orchestration.to_dict()
        if self.spec.playback is not None:
            capture_context["playback_policy"] = (
                self.spec.playback.to_dict()
            )
        write_json_atomic(paths["capture_context"], capture_context)
        self._record(paths["capture_context"])

        try:
            self.cancellation.checkpoint()
            self.progress.emit(
                JobState.PREPARING,
                JobStage.CORE_CONFIGURE,
                0.1,
                operation="core.trace_status",
            )
            previous_tracing = self.mihomo.get_tracing_status()
            self._persist_recovery(previous_tracing)
            self.progress.emit(
                JobState.PREPARING,
                JobStage.CORE_CONFIGURE,
                0.11,
                operation="core.trace_enable",
            )
            self.mihomo.enable_tracing(
                str(paths["mihomo_trace"]), session_id=self.session.session_id
            )
            tracing_configured = True
            self._record(paths["mihomo_trace"])

            self.progress.emit(
                JobState.PREPARING,
                JobStage.CORE_CONFIGURE,
                0.12,
                operation="core.protocol_snapshot",
            )
            protocol_snapshot = (
                self.mihomo.get_proxy_protocol_snapshot(
                    self.spec.options.proxy_selection_group,
                )
                if self.spec.options.proxy_selection_group
                else self.mihomo.get_proxy_protocol_snapshot()
            )
            protocol_snapshot["mode"] = self.spec.options.proxy_protocol_mode
            expected = self.spec.options.expected_proxy_protocol.lower().replace(
                "-", ""
            ).replace("_", "")
            if expected:
                protocol_snapshot["expected_protocol"] = expected
            selected = set(protocol_snapshot["protocols"])
            if (
                self.spec.options.proxy_protocol_mode == "strict_single"
                and expected
                and selected
                and selected != {expected}
            ):
                raise ProxyProtocolInvariantError(
                    f"Proxy protocol selection mismatch: expected {expected}, "
                    f"selected {', '.join(sorted(selected))}"
                )
            proxy_info = protocol_snapshot["selections"]
            capture_context["proxy_protocol"] = protocol_snapshot
            write_json_atomic(paths["capture_context"], capture_context)
            write_json_atomic(paths["proxy_info"], proxy_info)
            self._record(paths["proxy_info"])

            if self.spec.options.capture_packets:
                self.cancellation.checkpoint()
                self.progress.emit(
                    JobState.CAPTURING, JobStage.CAPTURE_PACKETS, 0.2,
                    operation="capture.tshark_tun_start",
                )
                tun_capture = start_packet_capture(
                    self.spec.interfaces.tun, paths["tun_pcap"], checkpoint=self.cancellation.checkpoint
                )
                self.registry.register(tun_capture.process, "tshark-tun")
                self._persist_recovery(previous_tracing)
                self.progress.emit(
                    JobState.CAPTURING,
                    JobStage.CAPTURE_PACKETS,
                    0.25,
                    operation="capture.tshark_physical_start",
                )
                phys_capture = start_packet_capture(
                    self.spec.interfaces.physical, paths["phys_pcap"], checkpoint=self.cancellation.checkpoint
                )
                self.registry.register(phys_capture.process, "tshark-physical")
                self._persist_recovery(previous_tracing)
                self._record(paths["tun_pcap"])
                self._record(paths["phys_pcap"])
                self._capture_monitor = CaptureMonitor((tun_capture, phys_capture), self.cancellation)
                self._capture_monitor.start()
                self.cancellation = self._capture_monitor
                capture_context["packet_coverage"] = {
                    "session_id": self.session.session_id,
                    "schema_version": 1, "clock": "monotonic_seconds",
                    "status": "in_progress", "drops": "unknown",
                    "ready": {"tun": getattr(tun_capture, "ready_monotonic", None),
                              "physical": getattr(phys_capture, "ready_monotonic", None)},
                }

            self.cancellation.checkpoint()
            for capture in (tun_capture, phys_capture):
                if capture is not None and capture.process.poll() is not None:
                    raise PacketCaptureError("CAPTURE_EXITED_BEFORE_BROWSER", "packet capture exited before Chrome launch")
            self.progress.emit(
                JobState.CAPTURING,
                JobStage.CAPTURE_BROWSER,
                0.4,
                operation="capture.chrome_launch",
            )
            use_cdp = self.runtime.enable_cdp and self.spec.options.collect_cdp
            if "packet_coverage" in capture_context:
                capture_context["packet_coverage"]["browser_start_requested"] = time.monotonic()
                write_json_atomic(paths["capture_context"], capture_context)
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
                stderr_path=str(paths["chrome_stderr"]),
            )
            self.registry.register(chrome_proc, "chrome")
            browser_health = BrowserHealthToken(chrome_proc, self.cancellation)
            capture_context["browser_lifecycle"] = {
                "schema_version": 1,
                "pid": getattr(chrome_proc, "pid", None),
                "status": "running",
                "started_monotonic": time.monotonic(),
            }
            write_json_atomic(paths["capture_context"], capture_context)
            self._persist_recovery(previous_tracing)
            self._record(paths["netlog"])

            if use_cdp:
                if "packet_coverage" in capture_context:
                    capture_context["packet_coverage"]["cdp_setup_started"] = time.monotonic()
                self.progress.emit(
                    JobState.CAPTURING,
                    JobStage.CAPTURE_BROWSER,
                    0.45,
                    operation="capture.cdp_connect",
                )
                collector = SyncCDPCollector(
                    debugging_port=self.runtime.remote_debugging_port,
                    cancellation=browser_health,
                    cache_mode=self.spec.options.cache_mode,
                )
                collector.connect()
                collector.setup()
                self.cancellation.checkpoint()
                self.progress.emit(
                    JobState.CAPTURING,
                    JobStage.CAPTURE_BROWSER,
                    0.5,
                    operation="capture.navigation",
                )
                if self.spec.playback is None:
                    if "packet_coverage" in capture_context:
                        capture_context["packet_coverage"]["navigation_requested"] = time.monotonic()
                        write_json_atomic(paths["capture_context"], capture_context)
                    collector.navigate(
                        self.spec.url,
                        load_timeout=self.runtime.wait_load_timeout,
                    )
                    self.progress.emit(
                        JobState.CAPTURING,
                        JobStage.CAPTURE_BROWSER,
                        0.55,
                        operation="capture.observation",
                    )
                    collector.collect(self.spec.duration_seconds)
                else:
                    if "packet_coverage" in capture_context:
                        capture_context["packet_coverage"]["navigation_requested"] = time.monotonic()
                        write_json_atomic(paths["capture_context"], capture_context)
                    collector.navigate(
                        self.spec.url,
                        load_timeout=self.runtime.wait_load_timeout,
                        wait_for_load=False,
                    )

                    self.progress.emit(
                        JobState.CAPTURING,
                        JobStage.CAPTURE_BROWSER,
                        0.5,
                        operation="capture.observation",
                    )

                    def playback_progress(status: dict[str, Any]) -> None:
                        duration = max(1.0, self.spec.duration_seconds)
                        elapsed = float(status.get("elapsed_seconds", 0.0))
                        self.progress.emit(
                            JobState.CAPTURING,
                            JobStage.CAPTURE_BROWSER,
                            min(0.85, 0.5 + 0.35 * elapsed / duration),
                            (
                                f"{status.get('phase', 'preparation')} "
                                f"{elapsed:.1f}/{duration:.0f}s; primary "
                                f"{status.get('primary_content_seconds', 0):.1f}/"
                                f"{status.get('desired_primary_seconds', 0)}s"
                            ),
                            operation="capture.observation",
                        )

                    playback_result = collector.collect_playback(
                        self.spec.duration_seconds,
                        self.spec.playback,
                        playback_progress,
                    )
                    capture_context["playback"] = playback_result
                    write_json_atomic(paths["capture_context"], capture_context)
                browser_health.checkpoint()
                collector.stop_collecting()
                write_json_atomic(paths["cdp"], collector.get_structured_data())
                self._record(paths["cdp"])
                browser_health.checkpoint()
                browser_health.expect_shutdown("cdp_browser_close")
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
                self.progress.emit(
                    JobState.CAPTURING,
                    JobStage.CAPTURE_BROWSER,
                    0.5,
                    operation="capture.observation",
                )
                browser_health.wait(self.spec.duration_seconds)
                browser_health.checkpoint()
                browser_health.expect_shutdown("capture_complete")
                terminate_chrome(chrome_proc, cancellation=self.cancellation)

            if self.spec.options.collect_netlog:
                repair_truncated_netlog(str(paths["netlog"]))
        finally:
            self._cleanup_resources(
                collector=collector,
                chrome_proc=chrome_proc,
                browser_health=browser_health,
                chrome_stderr=paths["chrome_stderr"],
                chrome_profile=paths["profile"],
                tun_capture=tun_capture,
                phys_capture=phys_capture,
                previous_tracing=previous_tracing,
                tracing_configured=tracing_configured,
                capture_context=capture_context,
                capture_context_path=paths["capture_context"],
                suppress_errors=sys.exc_info()[0] is not None,
            )

    def _cleanup_resources(
        self,
        *,
        collector: Any,
        chrome_proc: Any,
        browser_health: BrowserHealthToken | None,
        chrome_stderr: Path,
        chrome_profile: Path,
        tun_capture: Any,
        phys_capture: Any,
        previous_tracing: dict[str, Any] | None,
        tracing_configured: bool,
        capture_context: dict[str, Any],
        capture_context_path: Path,
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
                JobState.CAPTURING,
                JobStage.CLEANUP,
                0.9,
                force=True,
                operation="capture.cleanup",
            ),
        )
        if browser_health is not None:
            code = browser_health.observe()
            if code is None:
                browser_health.expect_shutdown("cleanup")
            elif not browser_health.expected_shutdown and not suppress_errors:
                errors.append(BrowserProcessError(
                    "BROWSER_PROCESS_EXITED",
                    f"Chrome exited unexpectedly with code {code}",
                    exit_code=code,
                ))
        if collector is not None:
            attempt("CDP browser close", collector.close_browser)
            attempt("CDP collector close", collector.close)
        if chrome_proc is not None and chrome_proc.poll() is None:
            # Cleanup must not be aborted by the failed sensor/cancel token.
            attempt("Chrome stop", lambda: terminate_chrome(chrome_proc))
        if chrome_proc is not None:
            def quiesce_chrome() -> None:
                verify_chrome_quiescence(
                    chrome_proc,
                    chrome_profile,
                    timeout=self.runtime.chrome_quiescence_timeout,
                )
                if "packet_coverage" in capture_context:
                    capture_context["packet_coverage"]["browser_quiescent"] = time.monotonic()
                if self.spec.options.cache_mode == "cold":
                    raw_dir = self.session.directory / "raw"
                    if raw_dir.is_dir():
                        remove_owned_cold_profile(
                            chrome_profile,
                            self.runtime.user_data_dir,
                            self.session.session_id,
                        )
                    else:
                        # Compatibility Sessions predate owned scratch roots.
                        shutil.rmtree(chrome_profile, ignore_errors=True)

            attempt("Chrome quiescence barrier", quiesce_chrome)
        if browser_health is not None:
            capture_context["browser_lifecycle"] = browser_health.snapshot()
            stderr = compact_chrome_stderr(chrome_stderr)
            try:
                stderr_path = str(chrome_stderr.relative_to(self.session.directory))
            except ValueError:
                stderr_path = chrome_stderr.name
            capture_context["browser_lifecycle"]["stderr"] = {
                "path": stderr_path, "bytes": stderr["bytes"],
                "truncated": stderr["truncated"],
            }
            if stderr["bytes"]:
                self._record(chrome_stderr)
            attempt("browser lifecycle publication", lambda: write_json_atomic(
                capture_context_path, capture_context))
        if self._capture_monitor is not None:
            # Bounded tail, no network stimulation and no change to trace
            # causal eligibility. Sensors remain monitored through this wait.
            if chrome_proc is not None and not self.cancellation.parent.cancelled and self.runtime.packet_tail_grace_seconds > 0:
                attempt("packet tail grace", lambda: self._capture_monitor.wait(
                    max(0.0, min(self.runtime.packet_tail_grace_seconds, 2.0))))
            attempt("packet capture health", self._capture_monitor.check_health)
            self._capture_monitor.stop()
            self.cancellation = self._capture_monitor.parent
        def finish_capture(role, capture):
            result = stop_packet_capture(capture)
            coverage = capture_context.get("packet_coverage")
            if coverage is not None:
                coverage.setdefault("stopped", {})[role] = time.monotonic()
                coverage.setdefault("exit", {})[role] = {
                    "code": getattr(result, "exit_code", None),
                    "killed": getattr(result, "killed", None),
                }
            if result is not None and (result.killed or result.exit_code not in (0, -15)):
                raise PacketCaptureError("CAPTURE_STOP_FAILED", f"capture stopped abnormally: {result.exit_code}", interface=getattr(capture, "interface", ""))
            if result is not None and not capture_output_complete(capture.output_path):
                raise PacketCaptureError("CAPTURE_OUTPUT_INVALID", "capture output has an invalid header or truncated final block", interface=capture.interface)
        if phys_capture is not None:
            attempt("physical packet capture stop", lambda: finish_capture("physical", phys_capture))
        if tun_capture is not None:
            attempt("TUN packet capture stop", lambda: finish_capture("tun", tun_capture))
        cleanup = self.registry.cleanup()
        if cleanup.errors:
            logger.warning("Process cleanup errors: %s", "; ".join(cleanup.errors))
            errors.append(RuntimeError("; ".join(cleanup.errors)))
        if "packet_coverage" in capture_context:
            coverage = capture_context["packet_coverage"]
            coverage["status"] = "failed" if errors or "browser_quiescent" not in coverage else "passed"
            coverage["errors"] = [str(error)[:1000] for error in errors]
            attempt("packet coverage publication", lambda: write_json_atomic(capture_context_path, capture_context))
        if tracing_configured:
            def persist_protocol_observation(boundary: dict[str, Any]) -> None:
                observation = observed_proxy_protocols(
                    str(boundary.get("output", "")),
                    max_event_seq=boundary.get("event_seq"),
                )
                protocol_context = capture_context.setdefault("proxy_protocol", {})
                expected = str(
                    protocol_context.get("expected_protocol", "")
                ).lower().replace("-", "").replace("_", "")
                protocols = set(observation["protocols"])
                event_count = int(observation["proxy_dial_events"])
                if event_count == 0:
                    consistency = "not_observed"
                elif expected and protocols == {expected}:
                    consistency = "match"
                elif expected:
                    consistency = "mismatch"
                elif len(protocols) <= 1:
                    consistency = "consistent"
                else:
                    consistency = "mixed"
                observation["validation_source"] = "bounded_mihomo_trace"
                observation["consistency"] = consistency
                protocol_context["runtime_observation"] = observation
                write_json_atomic(capture_context_path, capture_context)
                strict_mismatch = (
                    self.spec.options.proxy_protocol_mode == "strict_single"
                    and event_count > 0
                    and (
                        (expected and protocols != {expected})
                        or (not expected and len(protocols) > 1)
                    )
                )
                if strict_mismatch:
                    wanted = expected or "one runtime proxy protocol"
                    actual = ", ".join(sorted(protocols)) or "none"
                    raise ProxyProtocolInvariantError(
                        "Proxy protocol invariant failed from Mihomo trace: "
                        f"expected {wanted}; observed {actual}"
                    )


            def persist_trace_boundary() -> None:
                initial = self.mihomo.trace_barrier()
                boundary = initial
                if boundary.get("session_id") != self.session.session_id:
                    raise RuntimeError(
                        "Mihomo trace barrier session_id does not match capture session"
                    )
                capture_context["trace_boundary"] = {
                    "source": "mihomo_barrier",
                    "session_id": boundary["session_id"],
                    "event_seq": boundary["event_seq"],
                    "ts": boundary["ts"],
                    "output": boundary["output"],
                    "settle_seconds": self.runtime.trace_tail_grace_seconds,
                    "byte_size": boundary.get("byte_size", 0),
                    "journal_locking": boundary.get("journal_locking") is True,
                }
                write_json_atomic(capture_context_path, capture_context)
                persist_protocol_observation(capture_context["trace_boundary"])

                if self.runtime.trace_tail_grace_seconds <= 0:
                    return
                self.cancellation.wait(self.runtime.trace_tail_grace_seconds)
                try:
                    settled = self.mihomo.trace_barrier()
                    if settled.get("session_id") != self.session.session_id:
                        raise RuntimeError(
                            "settled Mihomo trace barrier session_id does not match capture session"
                        )
                except Exception as exc:
                    logger.warning(
                        "Settled Mihomo trace barrier failed; retaining initial boundary: %s",
                        exc,
                    )
                    return
                capture_context["trace_boundary_initial"] = {
                    "event_seq": initial["event_seq"],
                    "ts": initial["ts"],
                }
                capture_context["trace_boundary"].update({
                    "event_seq": settled["event_seq"],
                    "ts": settled["ts"],
                    "output": settled["output"],
                    "byte_size": settled.get("byte_size", 0),
                    "journal_locking": settled.get("journal_locking") is True,
                })
                write_json_atomic(capture_context_path, capture_context)

                persist_protocol_observation(capture_context["trace_boundary"])
            attempt("Mihomo trace barrier", persist_trace_boundary)
        if previous_tracing is not None:
            try:
                self.mihomo.restore_tracing(previous_tracing)
                if not errors:
                    self._clear_recovery()
            except Exception as exc:
                logger.warning("Failed to restore Mihomo tracing state: %s", exc)
                errors.append(exc)
        if errors and not suppress_errors:
            raise errors[0]

    def _prepare_paths(self) -> dict[str, Path]:
        raw_dir = self.session.directory / "raw"
        if raw_dir.is_dir():
            return {
                "mihomo_trace": raw_dir / "mihomo-trace.jsonl",
                "proxy_info": raw_dir / "proxy-info.json",
                "capture_context": raw_dir / "capture-context.json",
                "chrome_stderr": raw_dir / "chrome-stderr.log",
                "netlog": raw_dir / "netlog.json",
                "cdp": raw_dir / "cdp.json",
                "tun_pcap": raw_dir / "tun.pcap",
                "phys_pcap": raw_dir / "phys.pcap",
                "profile": Path(self.runtime.user_data_dir)
                / ("cold" if self.spec.options.cache_mode == "cold" else "warm")
                / self.spec.domain
                / (
                    self.session.session_id
                    if self.spec.options.cache_mode == "cold"
                    else self.spec.page_type
                ),
            }

        # Compatibility for Sessions written before the Capture Group layout.
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
            "chrome_stderr": logs_dir / f"chrome_stderr_{self.spec.domain}_{run_tag}.log",
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
        journal.persist(
            self.session.store,
            session_dir=self.session.directory,
        )

    def _clear_recovery(self) -> None:
        if self.session.store is None:
            return
        path = self.session.store.artifact_path_for_session(
            self.session.session_id,
            self.session.directory,
            RECOVERY_JOURNAL_NAME,
        )
        try:
            path.unlink()
        except FileNotFoundError:
            pass
