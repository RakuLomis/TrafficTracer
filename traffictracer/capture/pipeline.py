"""Capture pipeline — orchestrates Mihomo, tshark, Chrome per domain."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from datetime import datetime
from pathlib import Path

from ..config import Config, GlobalConfig, SiteConfig
from ..utils import logger, ensure_dir, setup_logging
from .controller_config import resolve_controller_config
from .mihomo import MihomoManager
from .tshark import start_tshark, stop_tshark
from .chrome import launch_chrome, wait_chrome_exit, terminate_chrome
from .cdp import SyncCDPCollector
from .netlog_fix import repair_truncated_netlog

_active_procs: list[subprocess.Popen] = []


def run_capture(config: Config, only_domain: str | None = None) -> str:
    setup_logging()

    g = config.global_config
    session_dir = ensure_dir(os.path.join(
        g.output.base_dir, datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
    ))

    sites = config.sites
    if only_domain:
        sites = [s for s in sites if s.domain == only_domain]
        if not sites:
            logger.error("Domain '%s' not found in config", only_domain)
            return str(session_dir)

    controller = resolve_controller_config(g.mihomo)
    mihomo = MihomoManager(
        g.mihomo.binary,
        controller.generated_config,
        controller.endpoint,
        controller.secret,
    )

    if g.mihomo.managed:
        mihomo_proc = mihomo.start()
    else:
        mihomo_proc = None
        logger.info("Using externally-managed Mihomo at %s", controller.endpoint)
        if not mihomo._api_reachable():
            logger.warning("Mihomo API not reachable at %s — tracing will fail", controller.endpoint)

    original_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, lambda s, f: (_cleanup(mihomo_proc, _active_procs), exit(1)))

    try:
        for site in sites:
            _capture_domain(site, g, mihomo, session_dir)
    finally:
        signal.signal(signal.SIGINT, original_handler)
        if g.mihomo.managed:
            mihomo.stop(mihomo_proc)
        logger.info("Capture session complete: %s", session_dir)

    return str(session_dir)


def _capture_domain(site: SiteConfig, g: GlobalConfig, mihomo: MihomoManager, session_dir: str) -> None:
    domain = site.domain
    traffic_type = site.traffic_type or "all"
    logger.info("=== Capturing %s (%s) ===", domain, traffic_type)

    domain_dir = ensure_dir(os.path.join(session_dir, "captures", domain))
    logs_dir = ensure_dir(os.path.join(session_dir, "logs"))

    i = 1
    while True:
        sub = f"{traffic_type}_{i}"
        run_dir = os.path.join(domain_dir, sub)
        if not os.path.exists(run_dir):
            break
        i += 1
    run_dir = ensure_dir(run_dir)
    run_tag = f"{traffic_type}_{i}"

    mihomo_trace_path = os.path.join(logs_dir, f"mihomo_trace_{domain}_{run_tag}.jsonl")
    netlog_path = os.path.join(logs_dir, f"netlog_{domain}_{run_tag}.json")
    cdp_log_path = os.path.join(logs_dir, f"cdp_{domain}_{run_tag}.json")

    tun_proc = None
    phys_proc = None
    chrome_proc = None
    cdp_collector = None
    previous_tracing = None

    try:
        previous_tracing = mihomo.get_tracing_status()
        mihomo.enable_tracing(mihomo_trace_path)

        proxy_info = mihomo.get_proxy_info()
        proxy_info_path = os.path.join(logs_dir, f"proxy_info_{domain}_{run_tag}.json")
        with open(proxy_info_path, "w") as f:
            json.dump(proxy_info, f, indent=2, ensure_ascii=False)
        logger.info("Proxy info saved to %s", proxy_info_path)

        tun_path = os.path.join(run_dir, "tun.pcap")
        phys_path = os.path.join(run_dir, "phys.pcap")

        tun_proc = start_tshark(g.network.tun_interface, tun_path)
        phys_proc = start_tshark(g.network.phys_interface, phys_path)

        use_cdp = g.chrome.enable_cdp
        visit_profile = os.path.join(g.chrome.user_data_dir, domain, run_tag)

        if use_cdp:
            cdp_port = g.chrome.remote_debugging_port
            chrome_proc = launch_chrome(
                binary=g.chrome.binary,
                url=site.url,
                netlog_path=netlog_path,
                user_data_dir=visit_profile,
                headless=g.chrome.headless,
                remote_debugging_port=cdp_port,
                netlog_capture_mode=g.chrome.netlog_capture_mode,
                open_url=False,
                disable_background_networking=g.chrome.disable_background_networking,
            )
            _active_procs.extend([tun_proc, phys_proc, chrome_proc])

            cdp_collector = SyncCDPCollector(debugging_port=cdp_port)
            try:
                cdp_collector.connect()
                cdp_collector.setup()
                cdp_collector.navigate(site.url, load_timeout=site.wait_load_timeout)

                logger.info("Collecting CDP events for %ds...", site.wait)
                cdp_collector.collect(site.wait)
                cdp_collector.stop_collecting()

                cdp_data = cdp_collector.get_structured_data()
                with open(cdp_log_path, "w") as f:
                    json.dump(cdp_data, f, indent=2, ensure_ascii=False)
                logger.info("CDP structured data saved to %s (%d requests)",
                            cdp_log_path,
                            cdp_data.get("metadata", {}).get("request_count", 0))
            finally:
                cdp_collector.close_browser()
                cdp_collector.close()

            if not wait_chrome_exit(chrome_proc, timeout=g.chrome.graceful_close_timeout):
                terminate_chrome(chrome_proc)
        else:
            chrome_proc = launch_chrome(
                binary=g.chrome.binary,
                url=site.url,
                netlog_path=netlog_path,
                user_data_dir=visit_profile,
                headless=g.chrome.headless,
                disable_background_networking=g.chrome.disable_background_networking,
            )
            _active_procs.extend([tun_proc, phys_proc, chrome_proc])

            logger.info("Waiting %ds for %s...", site.wait, site.url)
            time.sleep(site.wait)

            terminate_chrome(chrome_proc)

        repair_truncated_netlog(netlog_path)

    finally:
        if chrome_proc:
            if chrome_proc in _active_procs:
                _active_procs.remove(chrome_proc)
            if chrome_proc.poll() is None:
                terminate_chrome(chrome_proc)
        if tun_proc:
            stop_tshark(tun_proc)
            if tun_proc in _active_procs:
                _active_procs.remove(tun_proc)
        if phys_proc:
            stop_tshark(phys_proc)
            if phys_proc in _active_procs:
                _active_procs.remove(phys_proc)
        if previous_tracing is not None:
            try:
                mihomo.restore_tracing(previous_tracing)
            except Exception as exc:
                logger.warning("Failed to restore Mihomo tracing state: %s", exc)

    logger.info("=== Done capturing %s ===", domain)


def _cleanup(mihomo_proc, active_procs=None):
    if active_procs:
        for proc in active_procs[:]:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        active_procs.clear()
    if mihomo_proc and mihomo_proc.poll() is None:
        mihomo_proc.terminate()
        mihomo_proc.wait(timeout=10)


