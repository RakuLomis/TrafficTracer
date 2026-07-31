"""Legacy config adapter for job-scoped TrafficTracer capture."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import shutil
from uuid import uuid4

from ..config import Config, GlobalConfig, SiteConfig
from ..jobs.cancellation import CancellationToken
from ..jobs.models import (
    CaptureInterfaces,
    CaptureJobOptions,
    CaptureJobSpec,
    ControllerSpec,
)
from ..jobs.process_registry import ProcessRegistry
from ..jobs.progress import ProgressReporter
from ..utils import ensure_dir, logger, setup_logging
from .controller_config import ResolvedControllerConfig, resolve_controller_config
from .job import CaptureJob, CaptureRuntime, CaptureSessionContext
from .mihomo import MihomoManager


def run_capture(config: Config, only_domain: str | None = None) -> str:
    """Run legacy YAML capture without installing process signal handlers."""
    setup_logging()
    global_config = config.global_config
    session_dir = ensure_dir(
        Path(global_config.output.base_dir)
        / datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    ).resolve()

    sites = config.sites
    if only_domain:
        sites = [site for site in sites if site.domain == only_domain]
        if not sites:
            logger.error("Domain '%s' not found in config", only_domain)
            return str(session_dir)

    controller = resolve_controller_config(global_config.mihomo)
    mihomo = MihomoManager(
        global_config.mihomo.binary,
        controller.generated_config,
        controller.endpoint,
        controller.secret,
    )
    mihomo_proc = None
    if global_config.mihomo.managed:
        mihomo_proc = mihomo.start()
    else:
        logger.info("Using externally-managed Mihomo at %s", controller.endpoint)
        if not mihomo._api_reachable():
            logger.warning(
                "Mihomo API not reachable at %s — tracing will fail",
                controller.endpoint,
            )

    try:
        for site in sites:
            _run_site(site, global_config, controller, mihomo, session_dir)
    finally:
        if global_config.mihomo.managed:
            mihomo.stop(mihomo_proc)
        logger.info("Capture session complete: %s", session_dir)
    return str(session_dir)


def _run_site(
    site: SiteConfig,
    config: GlobalConfig,
    controller: ResolvedControllerConfig,
    mihomo: MihomoManager,
    session_dir: Path,
) -> None:
    job_id = str(uuid4())
    session_id = str(uuid4())
    spec = CaptureJobSpec(
        job_id=job_id,
        url=site.url,
        domain=site.domain,
        duration_seconds=site.wait,
        network=(site.traffic_type if site.traffic_type in {"tcp", "udp", "all"} else "all"),
        interfaces=CaptureInterfaces(
            tun=config.network.tun_interface,
            physical=config.network.phys_interface,
        ),
        output_root=str(session_dir.parent),
        chrome_binary=_resolve_executable(config.chrome.binary),
        controller=ControllerSpec(
            endpoint=controller.endpoint,
            secret=controller.secret or None,
            generated_config=controller.generated_config or None,
        ),
        options=CaptureJobOptions(
            capture_packets=True,
            collect_cdp=config.chrome.enable_cdp,
            collect_netlog=True,
            analyze_after_capture=False,
            headless=config.chrome.headless,
        ),
    )
    spec.to_dict()
    progress = ProgressReporter(
        job_id,
        lambda event: logger.info(
            "Capture progress %s %.0f%%", event.stage, event.progress * 100
        ),
    )
    job = CaptureJob(
        spec,
        runtime=CaptureRuntime(
            user_data_dir=config.chrome.user_data_dir,
            enable_cdp=config.chrome.enable_cdp,
            remote_debugging_port=config.chrome.remote_debugging_port,
            netlog_capture_mode=config.chrome.netlog_capture_mode,
            graceful_close_timeout=config.chrome.graceful_close_timeout,
            disable_background_networking=config.chrome.disable_background_networking,
            wait_load_timeout=site.wait_load_timeout,
            run_label=site.traffic_type or "all",
        ),
        mihomo=mihomo,
        session=CaptureSessionContext(session_id, session_dir),
        registry=ProcessRegistry(),
        progress=progress,
        cancellation=CancellationToken(),
    )
    job.run()


def _resolve_executable(value: str) -> str:
    expanded = Path(value).expanduser()
    if expanded.is_absolute() or "/" in value:
        return str(expanded.resolve())
    discovered = shutil.which(value)
    if discovered:
        return str(Path(discovered).resolve())
    return str((Path("/usr/bin") / value).resolve())
