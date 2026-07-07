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
from .mihomo import MihomoManager
from .tshark import start_tshark, stop_tshark
from .chrome import launch_chrome, wait_chrome_exit, terminate_chrome
from .cdp import SyncCDPClient
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

    mihomo_api = g.mihomo.api
    if g.mihomo.config:
        mihomo_api = _extract_api_from_config(g.mihomo.config) or mihomo_api

    mihomo = MihomoManager(g.mihomo.binary, g.mihomo.config, mihomo_api)
    mihomo_proc = mihomo.start()

    original_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, lambda s, f: (_cleanup(mihomo_proc, _active_procs), exit(1)))

    try:
        for site in sites:
            _capture_domain(site, g, mihomo, session_dir)
    finally:
        signal.signal(signal.SIGINT, original_handler)
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
    cdp_client = None

    try:
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

        use_cdp = g.chrome.enable_cdp and g.chrome.headless

        if use_cdp:
            cdp_port = g.chrome.remote_debugging_port
            chrome_proc = launch_chrome(
                binary=g.chrome.binary,
                url=site.url,
                netlog_path=netlog_path,
                user_data_dir=os.path.join(g.chrome.user_data_dir, domain),
                headless=g.chrome.headless,
                remote_debugging_port=cdp_port,
                netlog_capture_mode=g.chrome.netlog_capture_mode,
                open_url=False,
            )
            _active_procs.extend([tun_proc, phys_proc, chrome_proc])

            time.sleep(3)

            cdp_client = SyncCDPClient(debugging_port=cdp_port)
            try:
                cdp_client.enable_domains()
                cdp_client.navigate(site.url, load_timeout=site.wait_load_timeout)

                logger.info("Collecting CDP events for %ds...", site.wait)
                cdp_events = cdp_client.collect(site.wait)

                with open(cdp_log_path, "w") as f:
                    json.dump(cdp_events, f, indent=2, ensure_ascii=False)
                logger.info("CDP events saved to %s (%d events)",
                            cdp_log_path, len(cdp_events))
            finally:
                cdp_client.close_browser()
                cdp_client.close()

            if not wait_chrome_exit(chrome_proc, timeout=g.chrome.graceful_close_timeout):
                terminate_chrome(chrome_proc)
        else:
            chrome_proc = launch_chrome(
                binary=g.chrome.binary,
                url=site.url,
                netlog_path=netlog_path,
                user_data_dir=os.path.join(g.chrome.user_data_dir, domain),
                headless=g.chrome.headless,
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
        try:
            mihomo.disable_tracing()
        except Exception:
            pass

    logger.info("=== Done capturing %s ===", domain)


def _extract_api_from_config(config_path: str) -> str | None:
    try:
        with open(config_path, "r") as f:
            import yaml
            cfg = yaml.safe_load(f)
        if isinstance(cfg, dict):
            ec = cfg.get("external-controller", "")
            if ec:
                return f"http://{ec}" if "://" not in ec else ec
    except Exception:
        pass
    return None


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


