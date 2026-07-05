"""Capture pipeline — orchestrates Mihomo, tshark, Chrome per domain."""

from __future__ import annotations

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
from .chrome import launch_chrome, kill_chrome

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
    logger.info("=== Capturing %s ===", domain)

    domain_dir = ensure_dir(os.path.join(session_dir, "captures", domain))
    logs_dir = ensure_dir(os.path.join(session_dir, "logs"))
    mihomo_trace_path = os.path.join(logs_dir, f"mihomo_trace_{domain}.jsonl")
    netlog_path = os.path.join(logs_dir, f"netlog_{domain}.json")

    tun_proc = None
    phys_proc = None
    chrome_proc = None

    try:
        mihomo.enable_tracing(mihomo_trace_path)

        tun_path = os.path.join(domain_dir, "tun.pcap")
        phys_path = os.path.join(domain_dir, "phys.pcap")

        tun_proc = start_tshark(g.network.tun_interface, tun_path)
        phys_proc = start_tshark(g.network.phys_interface, phys_path)

        chrome_proc = launch_chrome(
            binary=g.chrome.binary,
            url=site.url,
            netlog_path=netlog_path,
            user_data_dir=g.chrome.user_data_dir,
            headless=g.chrome.headless,
        )

        _active_procs.extend([tun_proc, phys_proc, chrome_proc])

        logger.info("Waiting %ds for %s...", site.wait, site.url)
        time.sleep(site.wait)
    finally:
        if chrome_proc:
            kill_chrome(chrome_proc)
            if chrome_proc in _active_procs:
                _active_procs.remove(chrome_proc)
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


