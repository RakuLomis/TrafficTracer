# TrafficTracer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a two-phase traffic capture and analysis pipeline that correlates Chrome browsing traffic pre/post Mihomo proxy at the domain level.

**Architecture:** Two independent pipelines — Capture (online: launches Mihomo/TUN, tshark ×2, Chrome per domain, collects pcaps + NetLog + Mihomo trace) and Analysis (offline: parses NetLog → 5-tuples, matches Mihomo trace, produces correlation JSON, splits pcaps per-flow). Python 3.10+ stdlib only.

**Tech Stack:** Python 3.10+ (stdlib), YAML config, tshark, Mihomo binary, Chrome/Chromium.

## Global Constraints

- Conda environment: `traffictracer`
- Python 3.10+
- Dependencies: `pyyaml` (install via `conda install pyyaml` or `pip install pyyaml`)
- Existing `parser/` package must remain unchanged
- New code goes in `traffictracer/` package
- YAML config format as specified in design spec
- Output directory: `output/<session>/captures/<domain>/flows/<root>/<relative>/`
- tshark graceful shutdown: SIGTERM → wait(5s) → SIGKILL fallback
- Mihomo API: configurable base URL

---

### Pre-Task Setup

- [ ] **Step 0a: Create alpha branch**

```bash
git checkout -b alpha
```

- [ ] **Step 0b: Install PyYAML**

```bash
conda activate traffictracer && pip install pyyaml
```

---

### Task 1: Project scaffolding and config module

**Files:**
- Create: `traffictracer/__init__.py`
- Create: `traffictracer/utils.py`
- Create: `traffictracer/config.py`
- Create: `sites.example.yaml`
- Create: `test/test_config.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `Config` dataclass with `global_config: GlobalConfig` and `sites: list[SiteConfig]`
  - `GlobalConfig` dataclass with `mihomo: MihomoConfig`, `chrome: ChromeConfig`, `network: NetworkConfig`, `output: OutputConfig`
  - `MihomoConfig` dataclass with `binary: str`, `config: str`, `api: str`, `tracing_log: str`
  - `ChromeConfig` dataclass with `binary: str`, `user_data_dir: str`, `headless: bool`
  - `NetworkConfig` dataclass with `tun_interface: str`, `phys_interface: str`
  - `OutputConfig` dataclass with `base_dir: str`
  - `SiteConfig` dataclass with `domain: str`, `url: str`, `wait: int`, `traffic_type: str`
  - `load_config(path: str) -> Config`
  - `ensure_dir(path: str) -> None` in utils.py

- [ ] **Step 1: Create package structure**

```bash
mkdir -p traffictracer/capture traffictracer/analyze
touch traffictracer/__init__.py traffictracer/capture/__init__.py traffictracer/analyze/__init__.py
```

- [ ] **Step 2: Write utils.py**

```python
"""Shared utilities for TrafficTracer."""

import os
import logging
import signal
import subprocess
from pathlib import Path

logger = logging.getLogger("traffictracer")


def setup_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def ensure_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def cleanup_processes(processes: list[subprocess.Popen]) -> None:
    for proc in processes:
        if proc is None or proc.poll() is not None:
            continue
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def signal_handler(signum, frame):
    logger.info("Received signal %s, cleaning up...", signum)
    raise KeyboardInterrupt
```

- [ ] **Step 3: Write config.py**

```python
"""YAML configuration loading and validation for TrafficTracer."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import yaml


@dataclass
class MihomoConfig:
    binary: str = "mihomo"
    config: str = ""
    api: str = "http://127.0.0.1:9090"
    tracing_log: str = ""


@dataclass
class ChromeConfig:
    binary: str = "google-chrome"
    user_data_dir: str = "/tmp/chrome-profile"
    headless: bool = False


@dataclass
class NetworkConfig:
    tun_interface: str = ""
    phys_interface: str = ""


@dataclass
class OutputConfig:
    base_dir: str = "./output"


@dataclass
class GlobalConfig:
    mihomo: MihomoConfig = field(default_factory=MihomoConfig)
    chrome: ChromeConfig = field(default_factory=ChromeConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    output: OutputConfig = field(default_factory=OutputConfig)


@dataclass
class SiteConfig:
    domain: str
    url: str
    wait: int = 10
    traffic_type: str = "all"


@dataclass
class Config:
    global_config: GlobalConfig
    sites: list[SiteConfig]


def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError("Config file must be a YAML mapping")

    g = raw.get("global", {})
    if not isinstance(g, dict):
        raise ValueError("Missing or invalid 'global' section")

    m = g.get("mihomo", {})
    mihomo = MihomoConfig(
        binary=m.get("binary", "mihomo"),
        config=m.get("config", ""),
        api=m.get("api", "http://127.0.0.1:9090"),
        tracing_log=m.get("tracing_log", ""),
    )

    c = g.get("chrome", {})
    chrome = ChromeConfig(
        binary=c.get("binary", "google-chrome"),
        user_data_dir=c.get("user_data_dir", "/tmp/chrome-profile"),
        headless=c.get("headless", False),
    )

    n = g.get("network", {})
    network = NetworkConfig(
        tun_interface=n.get("tun_interface", ""),
        phys_interface=n.get("phys_interface", ""),
    )

    o = g.get("output", {})
    output = OutputConfig(base_dir=o.get("base_dir", "./output"))

    global_config = GlobalConfig(mihomo=mihomo, chrome=chrome,
                                  network=network, output=output)

    sites_raw = raw.get("sites", [])
    if not isinstance(sites_raw, list):
        raise ValueError("Missing or invalid 'sites' section")

    sites = []
    for s in sites_raw:
        if not isinstance(s, dict):
            continue
        sites.append(SiteConfig(
            domain=s["domain"],
            url=s["url"],
            wait=s.get("wait", 10),
            traffic_type=s.get("traffic_type", "all"),
        ))

    if not sites:
        raise ValueError("No sites defined in config")

    return Config(global_config=global_config, sites=sites)
```

- [ ] **Step 4: Write sites.example.yaml**

```yaml
global:
  mihomo:
    binary: /path/to/mihomo
    config: /path/to/mihomo.yaml
    api: "http://127.0.0.1:9090"
  chrome:
    binary: google-chrome
    user_data_dir: /tmp/chrome-profile
    headless: false
  network:
    tun_interface: utun
    phys_interface: eth0
  output:
    base_dir: ./output

sites:
  - domain: bilibili.com
    url: "https://www.bilibili.com"
    wait: 10
    traffic_type: all
  - domain: youtube.com
    url: "https://www.youtube.com"
    wait: 15
    traffic_type: tcp
```

- [ ] **Step 5: Write test_config.py**

```python
"""Tests for config loading."""

import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.config import load_config, Config, GlobalConfig, SiteConfig


def test_load_config():
    yaml_content = """\
global:
  mihomo:
    binary: /usr/bin/mihomo
    config: /etc/mihomo/config.yaml
    api: "http://127.0.0.1:9090"
  chrome:
    binary: google-chrome
    user_data_dir: /tmp/chrome-profile
    headless: true
  network:
    tun_interface: utun
    phys_interface: eth0
  output:
    base_dir: ./output
sites:
  - domain: example.com
    url: "https://www.example.com"
    wait: 10
    traffic_type: all
  - domain: test.org
    url: "https://test.org"
    wait: 5
    traffic_type: tcp
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(yaml_content)
        tmp = f.name

    try:
        cfg = load_config(tmp)
        assert isinstance(cfg, Config)
        assert cfg.global_config.mihomo.binary == "/usr/bin/mihomo"
        assert cfg.global_config.mihomo.api == "http://127.0.0.1:9090"
        assert cfg.global_config.chrome.headless is True
        assert cfg.global_config.network.tun_interface == "utun"
        assert cfg.global_config.output.base_dir == "./output"
        assert len(cfg.sites) == 2
        assert cfg.sites[0].domain == "example.com"
        assert cfg.sites[0].wait == 10
        assert cfg.sites[1].traffic_type == "tcp"
    finally:
        os.unlink(tmp)

    print("  ✓ config loading pass")


if __name__ == "__main__":
    test_load_config()
    print("\n✓ All config tests passed!")
```

- [ ] **Step 6: Run test to verify**

Run: `python test/test_config.py`
Expected: `✓ config loading pass`

- [ ] **Step 7: Commit**

```bash
git add traffictracer/__init__.py traffictracer/utils.py traffictracer/config.py traffictracer/capture/__init__.py traffictracer/analyze/__init__.py sites.example.yaml test/test_config.py
git commit -m "feat: add project scaffolding, config module, and example config"
```

---

### Task 2: Mihomo process and API manager

**Files:**
- Create: `traffictracer/capture/mihomo.py`
- Create: `test/test_mihomo.py`

**Interfaces:**
- Consumes: `traffictracer.utils.logger`
- Produces:
  - `MihomoManager(binary: str, config_path: str, api_url: str)`
  - `MihomoManager.start() -> subprocess.Popen`
  - `MihomoManager.stop(process: subprocess.Popen) -> None`
  - `MihomoManager.enable_tracing(output_path: str) -> dict` — PATCH /experimental/tracing
  - `MihomoManager.disable_tracing() -> dict` — PATCH /experimental/tracing
  - `MihomoManager.get_tracing_status() -> dict` — GET /experimental/tracing

- [ ] **Step 1: Write mihomo.py**

```python
"""Mihomo process management and API control for tracing."""

from __future__ import annotations

import json
import subprocess
import time
import urllib.request
import urllib.error
from pathlib import Path

from ..utils import logger


class MihomoManager:
    def __init__(self, binary: str, config_path: str, api_url: str):
        self.binary = binary
        self.config_path = config_path
        self.api_url = api_url.rstrip("/")

    def start(self) -> subprocess.Popen:
        logger.info("Starting Mihomo: %s -f %s", self.binary, self.config_path)
        proc = subprocess.Popen(
            [self.binary, "-f", self.config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)
        return proc

    def stop(self, proc: subprocess.Popen) -> None:
        if proc is None or proc.poll() is not None:
            return
        logger.info("Stopping Mihomo (PID %d)", proc.pid)
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    def _api_request(self, method: str, path: str, body: dict | None = None) -> dict:
        url = f"{self.api_url}{path}"
        data = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            logger.error("Mihomo API error: %s %s: %s", method, path, e)
            raise

    def get_tracing_status(self) -> dict:
        return self._api_request("GET", "/experimental/tracing")

    def enable_tracing(self, output_path: str) -> dict:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        logger.info("Enabling Mihomo tracing -> %s", output_path)
        return self._api_request("PATCH", "/experimental/tracing", {
            "enabled": True,
            "output": output_path,
        })

    def disable_tracing(self) -> dict:
        logger.info("Disabling Mihomo tracing")
        return self._api_request("PATCH", "/experimental/tracing", {
            "enabled": False,
        })
```

- [ ] **Step 2: Write test_mihomo.py**

```python
"""Tests for Mihomo manager (no live Mihomo required)."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.capture.mihomo import MihomoManager


def test_mihomo_manager_init():
    mgr = MihomoManager(
        binary="/usr/bin/mihomo",
        config_path="/etc/mihomo/config.yaml",
        api_url="http://127.0.0.1:9090",
    )
    assert mgr.binary == "/usr/bin/mihomo"
    assert mgr.config_path == "/etc/mihomo/config.yaml"
    assert mgr.api_url == "http://127.0.0.1:9090"

    mgr2 = MihomoManager("mihomo", "cfg.yaml", "http://localhost:9090/")
    assert mgr2.api_url == "http://localhost:9090"


def test_enable_tracing_payload_format():
    mgr = MihomoManager("mihomo", "cfg.yaml", "http://127.0.0.1:9090")
    import json
    payload = {"enabled": True, "output": "/tmp/trace.jsonl"}
    data = json.dumps(payload)
    assert json.loads(data) == payload


if __name__ == "__main__":
    test_mihomo_manager_init()
    test_enable_tracing_payload_format()
    print("\n✓ All Mihomo manager tests passed!")
```

- [ ] **Step 3: Run test to verify**

Run: `python test/test_mihomo.py`
Expected: `✓ All Mihomo manager tests passed!`

- [ ] **Step 4: Commit**

```bash
git add traffictracer/capture/mihomo.py test/test_mihomo.py
git commit -m "feat: add Mihomo process and tracing API manager"
```

---

### Task 3: tshark subprocess manager

**Files:**
- Create: `traffictracer/capture/tshark.py`
- Create: `test/test_tshark.py`

**Interfaces:**
- Consumes: `traffictracer.utils.logger`
- Produces:
  - `start_tshark(interface: str, output_path: str, capture_filter: str = "") -> subprocess.Popen`
  - `stop_tshark(proc: subprocess.Popen, timeout: int = 5) -> None`

- [ ] **Step 1: Write tshark.py**

```python
"""tshark subprocess management with graceful shutdown."""

from __future__ import annotations

import subprocess
import signal
from pathlib import Path

from ..utils import logger


def start_tshark(interface: str, output_path: str,
                 capture_filter: str = "") -> subprocess.Popen:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    cmd = ["tshark", "-i", interface, "-w", output_path]
    if capture_filter:
        cmd.extend(["-f", capture_filter])
    logger.info("Starting tshark on %s -> %s", interface, output_path)
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def stop_tshark(proc: subprocess.Popen, timeout: int = 5) -> None:
    if proc is None or proc.poll() is not None:
        return
    logger.info("Stopping tshark (PID %d) gracefully...", proc.pid)
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=timeout)
        logger.info("tshark exited cleanly")
    except subprocess.TimeoutExpired:
        logger.warning("tshark did not exit, sending SIGKILL")
        proc.kill()
        proc.wait()
```

- [ ] **Step 2: Write test_tshark.py**

```python
"""Tests for tshark manager (smoke-only, no live tshark required)."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import subprocess
from traffictracer.capture.tshark import stop_tshark


def test_stop_tshark_graceful():
    proc = subprocess.Popen(
        ["sleep", "2"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    stop_tshark(proc, timeout=3)
    assert proc.poll() is not None


def test_stop_tshark_already_dead():
    proc = subprocess.Popen(
        ["true"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    proc.wait()
    stop_tshark(proc, timeout=1)
    assert proc.poll() == 0


if __name__ == "__main__":
    test_stop_tshark_graceful()
    test_stop_tshark_already_dead()
    print("\n✓ All tshark manager tests passed!")
```

- [ ] **Step 3: Run test to verify**

Run: `python test/test_tshark.py`
Expected: `✓ All tshark manager tests passed!`

- [ ] **Step 4: Commit**

```bash
git add traffictracer/capture/tshark.py test/test_tshark.py
git commit -m "feat: add tshark subprocess manager with graceful shutdown"
```

---

### Task 4: Chrome subprocess manager

**Files:**
- Create: `traffictracer/capture/chrome.py`
- Create: `test/test_chrome.py`

**Interfaces:**
- Consumes: `traffictracer.utils.logger`
- Produces:
  - `launch_chrome(binary: str, url: str, netlog_path: str, user_data_dir: str, headless: bool = False, proxy_server: str = "") -> subprocess.Popen`
  - `kill_chrome(proc: subprocess.Popen) -> None`

- [ ] **Step 1: Write chrome.py**

```python
"""Chrome browser subprocess management for NetLog capture."""

from __future__ import annotations

import subprocess
from pathlib import Path

from ..utils import logger


def launch_chrome(
    binary: str,
    url: str,
    netlog_path: str,
    user_data_dir: str,
    headless: bool = False,
    proxy_server: str = "",
) -> subprocess.Popen:
    Path(netlog_path).parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        binary,
        f"--user-data-dir={user_data_dir}",
        f"--log-net-log={netlog_path}",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    if headless:
        cmd.append("--headless=new")
    if proxy_server:
        cmd.append(f"--proxy-server={proxy_server}")
    cmd.append(url)
    logger.info("Launching Chrome: %s -> %s", binary, url)
    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def kill_chrome(proc: subprocess.Popen) -> None:
    if proc is None or proc.poll() is not None:
        return
    logger.info("Killing Chrome (PID %d)", proc.pid)
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
```

- [ ] **Step 2: Write test_chrome.py**

```python
"""Tests for Chrome manager (no live Chrome required)."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import subprocess
import tempfile
from traffictracer.capture.chrome import launch_chrome, kill_chrome


def test_kill_chrome():
    proc = subprocess.Popen(
        ["sleep", "5"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    kill_chrome(proc)
    assert proc.poll() is not None


def test_kill_chrome_already_exited():
    proc = subprocess.Popen(
        ["true"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    proc.wait()
    kill_chrome(proc)
    assert proc.poll() == 0


if __name__ == "__main__":
    test_kill_chrome()
    test_kill_chrome_already_exited()
    print("\n✓ All Chrome manager tests passed!")
```

- [ ] **Step 3: Run test to verify**

Run: `python test/test_chrome.py`
Expected: `✓ All Chrome manager tests passed!`

- [ ] **Step 4: Commit**

```bash
git add traffictracer/capture/chrome.py test/test_chrome.py
git commit -m "feat: add Chrome browser subprocess manager"
```

---

### Task 5: Capture pipeline orchestrator

**Files:**
- Create: `traffictracer/capture/pipeline.py`
- Create: `test/test_capture_pipeline.py`

**Interfaces:**
- Consumes: `traffictracer.config.Config`, `traffictracer.capture.mihomo.MihomoManager`, `traffictracer.capture.tshark.start_tshark/stop_tshark`, `traffictracer.capture.chrome.launch_chrome/kill_chrome`, `traffictracer.utils.ensure_dir`
- Produces:
  - `run_capture(config: Config, only_domain: str | None = None) -> str` — returns session dir path

- [ ] **Step 1: Write pipeline.py**

```python
"""Capture pipeline — orchestrates Mihomo, tshark, Chrome per domain."""

from __future__ import annotations

import os
import signal
import time
from datetime import datetime
from pathlib import Path

from ..config import Config
from ..utils import logger, ensure_dir, setup_logging
from .mihomo import MihomoManager
from .tshark import start_tshark, stop_tshark
from .chrome import launch_chrome, kill_chrome


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
    signal.signal(signal.SIGINT, lambda s, f: (_cleanup(mihomo_proc), exit(1)))

    try:
        for site in sites:
            _capture_domain(site, g, mihomo, session_dir)
    finally:
        signal.signal(signal.SIGINT, original_handler)
        mihomo.stop(mihomo_proc)
        logger.info("Capture session complete: %s", session_dir)

    return str(session_dir)


def _capture_domain(site, g, mihomo: MihomoManager, session_dir: str) -> None:
    domain = site.domain
    logger.info("=== Capturing %s ===", domain)

    domain_dir = ensure_dir(os.path.join(session_dir, "captures", domain))
    logs_dir = ensure_dir(os.path.join(session_dir, "logs"))
    mihomo_trace_path = os.path.join(logs_dir, f"mihomo_trace_{domain}.jsonl")
    netlog_path = os.path.join(logs_dir, f"netlog_{domain}.json")

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

    logger.info("Waiting %ds for %s...", site.wait, site.url)
    time.sleep(site.wait)

    kill_chrome(chrome_proc)
    stop_tshark(tun_proc)
    stop_tshark(phys_proc)

    mihomo.disable_tracing()
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


def _cleanup(mihomo_proc):
    if mihomo_proc and mihomo_proc.poll() is None:
        mihomo_proc.terminate()
        mihomo_proc.wait(timeout=10)
```

- [ ] **Step 2: Write test_capture_pipeline.py**

```python
"""Tests for capture pipeline (config parsing and session dir)."""

import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.config import (
    load_config, Config, GlobalConfig, MihomoConfig, ChromeConfig,
    NetworkConfig, OutputConfig, SiteConfig,
)


def test_session_dir_structure():
    cfg = GlobalConfig(output=OutputConfig(base_dir="/tmp/tt-test"))
    session_dir = os.path.join(cfg.output.base_dir, "2025-07-05_14-30-00")
    domain = "example.com"
    captures = os.path.join(session_dir, "captures", domain)
    logs = os.path.join(session_dir, "logs")
    assert "captures/example.com" in captures
    assert "logs" in logs


def test_site_filtering():
    sites = [
        SiteConfig(domain="a.com", url="https://a.com", wait=10),
        SiteConfig(domain="b.com", url="https://b.com", wait=15),
    ]
    filtered = [s for s in sites if s.domain == "a.com"]
    assert len(filtered) == 1
    assert filtered[0].domain == "a.com"


if __name__ == "__main__":
    test_session_dir_structure()
    test_site_filtering()
    print("\n✓ All capture pipeline tests passed!")
```

- [ ] **Step 3: Run test to verify**

Run: `python test/test_capture_pipeline.py`
Expected: `✓ All capture pipeline tests passed!`

- [ ] **Step 4: Commit**

```bash
git add traffictracer/capture/pipeline.py test/test_capture_pipeline.py
git commit -m "feat: add capture pipeline orchestrator"
```

---

### Task 6: NetLog 5-tuple extractor

**Files:**
- Create: `traffictracer/analyze/netlog.py`
- Create: `test/test_netlog.py`

**Interfaces:**
- Consumes: `parser.domain_analyzer.get_domain_connections`, `parser.dependency_graph.FiveTuple`
- Produces:
  - `FiveTupleData(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str)` named tuple
  - `DomainConnections(name: str, site: str, relation: str, five_tuples: list[FiveTupleData])` named tuple
  - `extract_five_tuples(netlog_path: str, domain: str) -> list[DomainConnections]`

- [ ] **Step 1: Write netlog.py**

```python
"""NetLog 5-tuple extraction — wraps parser/ for TrafficTracer analysis."""

from __future__ import annotations

from typing import NamedTuple

from parser.domain_analyzer import get_domain_connections


class FiveTupleData(NamedTuple):
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str


class DomainConnections(NamedTuple):
    name: str
    site: str
    relation: str
    five_tuples: list[FiveTupleData]


def extract_five_tuples(netlog_path: str, domain: str) -> list[DomainConnections]:
    results = get_domain_connections(netlog_path, domain)
    output: list[DomainConnections] = []

    for item in results:
        tuples: list[FiveTupleData] = []
        for detail in item.get("connection_detail", []):
            local = detail.get("local_address", "")
            remote = detail.get("remote_address", "")
            src_ip, src_port = _parse_addr(local)
            dst_ip, dst_port = _parse_addr(remote)
            tuples.append(FiveTupleData(
                src_ip=src_ip, src_port=src_port,
                dst_ip=dst_ip, dst_port=dst_port,
                protocol="",
            ))
        output.append(DomainConnections(
            name=item["name"],
            site=item["site"],
            relation=item["relation"],
            five_tuples=tuples,
        ))

    return output


def _parse_addr(addr: str) -> tuple[str, int]:
    if not addr:
        return ("", 0)
    if addr.startswith("["):
        idx = addr.rfind("]:")
        if idx == -1:
            return ("", 0)
        host = addr[1:idx]
        port_str = addr[idx + 2:]
    else:
        idx = addr.rfind(":")
        if idx == -1:
            return (addr, 0)
        host = addr[:idx]
        port_str = addr[idx + 1:]
    try:
        port = int(port_str)
    except ValueError:
        return (host, 0)
    return (host, port)
```

- [ ] **Step 2: Write test_netlog.py**

```python
"""Tests for NetLog 5-tuple extraction."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.analyze.netlog import _parse_addr, FiveTupleData, DomainConnections


def test_parse_addr_ipv4():
    assert _parse_addr("127.0.0.1:51891") == ("127.0.0.1", 51891)
    assert _parse_addr("192.168.1.1:0") == ("192.168.1.1", 0)


def test_parse_addr_ipv6():
    assert _parse_addr("[::1]:443") == ("::1", 443)
    assert _parse_addr("[2001:db8::1]:8443") == ("2001:db8::1", 8443)


def test_parse_addr_empty():
    assert _parse_addr("") == ("", 0)
    assert _parse_addr("no-port") == ("no-port", 0)


def test_domain_connections_creation():
    ft = FiveTupleData(src_ip="127.0.0.1", src_port=51891,
                        dst_ip="127.0.0.1", dst_port=7890, protocol="")
    dc = DomainConnections(
        name="https://www.example.com",
        site="https://example.com",
        relation="same_site",
        five_tuples=[ft],
    )
    assert dc.name == "https://www.example.com"
    assert dc.relation == "same_site"
    assert dc.five_tuples[0].src_port == 51891


if __name__ == "__main__":
    test_parse_addr_ipv4()
    test_parse_addr_ipv6()
    test_parse_addr_empty()
    test_domain_connections_creation()
    print("\n✓ All NetLog extractor tests passed!")
```

- [ ] **Step 3: Run test to verify**

Run: `python test/test_netlog.py`
Expected: `✓ All NetLog extractor tests passed!`

- [ ] **Step 4: Commit**

```bash
git add traffictracer/analyze/netlog.py test/test_netlog.py
git commit -m "feat: add NetLog 5-tuple extractor wrapping parser/"
```

---

### Task 7: Mihomo tracing log parser

**Files:**
- Create: `traffictracer/analyze/mihomo_log.py`
- Create: `test/test_mihomo_log.py`

**Interfaces:**
- Consumes: nothing external
- Produces:
  - `TcpConnect(ts, conn_id, src, dst, host)`
  - `TcpProxyDial(ts, conn_id, proxy, proxy_type, proxy_addr, out_src)`
  - `TcpClose(ts, conn_id, bytes_up, bytes_down, duration_ms)`
  - `MihomoConnection(conn_id, connect, proxy_dial, close)` - groups events by conn_id
  - `parse_tracing_log(path: str) -> dict[str, MihomoConnection]`

- [ ] **Step 1: Write mihomo_log.py**

```python
"""Mihomo tracing JSONL log parser for TrafficTracer analysis."""

from __future__ import annotations

import json
from typing import NamedTuple


class TcpConnect(NamedTuple):
    ts: str
    conn_id: str
    src: str
    dst: str
    host: str


class TcpProxyDial(NamedTuple):
    ts: str
    conn_id: str
    proxy: str
    proxy_type: str
    proxy_addr: str
    out_src: str


class TcpClose(NamedTuple):
    ts: str
    conn_id: str
    bytes_up: int
    bytes_down: int
    duration_ms: int


class MihomoConnection(NamedTuple):
    conn_id: str
    connect: TcpConnect | None
    proxy_dial: TcpProxyDial | None
    close: TcpClose | None


def parse_tracing_log(path: str) -> dict[str, MihomoConnection]:
    connections: dict[str, dict[str, TcpConnect | TcpProxyDial | TcpClose | None]] = {}

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            etype = event.get("type", "")
            conn_id = event.get("conn_id", "")
            if not conn_id:
                continue

            if conn_id not in connections:
                connections[conn_id] = {
                    "connect": None, "proxy_dial": None, "close": None,
                }

            if etype == "tcp_connect":
                connections[conn_id]["connect"] = TcpConnect(
                    ts=event.get("ts", ""),
                    conn_id=conn_id,
                    src=event.get("src", ""),
                    dst=event.get("dst", ""),
                    host=event.get("host", ""),
                )
            elif etype == "tcp_proxy_dial":
                connections[conn_id]["proxy_dial"] = TcpProxyDial(
                    ts=event.get("ts", ""),
                    conn_id=conn_id,
                    proxy=event.get("proxy", ""),
                    proxy_type=event.get("proxy_type", ""),
                    proxy_addr=event.get("proxy_addr", ""),
                    out_src=event.get("out_src", ""),
                )
            elif etype == "tcp_close":
                connections[conn_id]["close"] = TcpClose(
                    ts=event.get("ts", ""),
                    conn_id=conn_id,
                    bytes_up=event.get("bytes_up", 0),
                    bytes_down=event.get("bytes_down", 0),
                    duration_ms=event.get("duration_ms", 0),
                )

    return {
        cid: MihomoConnection(
            conn_id=cid,
            connect=conn["connect"],
            proxy_dial=conn["proxy_dial"],
            close=conn["close"],
        )
        for cid, conn in connections.items()
    }
```

- [ ] **Step 2: Write test_mihomo_log.py**

```python
"""Tests for Mihomo tracing log parser."""

import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.analyze.mihomo_log import (
    parse_tracing_log, MihomoConnection, TcpConnect, TcpProxyDial, TcpClose,
)


def test_parse_tracing_log():
    content = """\
{"ts":"2025-07-05T10:00:00Z","type":"tcp_connect","conn_id":"conn-1","src":"127.0.0.1:55555","dst":"127.0.0.1:7890","host":"www.example.com"}
{"ts":"2025-07-05T10:00:01Z","type":"tcp_proxy_dial","conn_id":"conn-1","proxy":"Proxy","proxy_type":"ss","proxy_addr":"1.2.3.4:443","out_src":"192.168.1.100:41234"}
{"ts":"2025-07-05T10:00:10Z","type":"tcp_close","conn_id":"conn-1","bytes_up":1024,"bytes_down":4096,"duration_ms":9000}
{"ts":"2025-07-05T10:00:00Z","type":"tcp_connect","conn_id":"conn-2","src":"127.0.0.1:55556","dst":"127.0.0.1:7890","host":"cdn.example.com"}
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(content)
        tmp = f.name

    try:
        conns = parse_tracing_log(tmp)
        assert len(conns) == 2
        assert "conn-1" in conns
        c1 = conns["conn-1"]
        assert c1.connect is not None
        assert c1.connect.src == "127.0.0.1:55555"
        assert c1.connect.host == "www.example.com"
        assert c1.proxy_dial is not None
        assert c1.proxy_dial.out_src == "192.168.1.100:41234"
        assert c1.close is not None
        assert c1.close.bytes_up == 1024
        assert c1.close.bytes_down == 4096

        c2 = conns["conn-2"]
        assert c2.connect is not None
        assert c2.proxy_dial is None
        assert c2.close is None
    finally:
        os.unlink(tmp)

    print("  ✓ Mihomo log parsing pass")


def test_parse_empty_log():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write("\n")
        tmp = f.name
    try:
        conns = parse_tracing_log(tmp)
        assert len(conns) == 0
    finally:
        os.unlink(tmp)


if __name__ == "__main__":
    test_parse_tracing_log()
    test_parse_empty_log()
    print("\n✓ All Mihomo log parser tests passed!")
```

- [ ] **Step 3: Run test to verify**

Run: `python test/test_mihomo_log.py`
Expected: `✓ All Mihomo log parser tests passed!`

- [ ] **Step 4: Commit**

```bash
git add traffictracer/analyze/mihomo_log.py test/test_mihomo_log.py
git commit -m "feat: add Mihomo tracing JSONL log parser"
```

---

### Task 8: Correlation engine

**Files:**
- Create: `traffictracer/analyze/correlator.py`
- Create: `test/test_correlator.py`

**Interfaces:**
- Consumes: `traffictracer.analyze.netlog.DomainConnections` / `FiveTupleData`, `traffictracer.analyze.mihomo_log.MihomoConnection`
- Produces:
  - `CorrelatedFlow(name, relation, pre_proxy: FiveTupleData, post_proxy: FiveTupleData)` NamedTuple
  - `CorrelationResult(domain, flows: list[CorrelatedFlow])` NamedTuple
  - `correlate(netlog_conns: list[DomainConnections], mihomo_conns: dict[str, MihomoConnection], domain: str) -> CorrelationResult`

- [ ] **Step 1: Write correlator.py**

```python
"""Correlation engine — matches NetLog 5-tuples to Mihomo connection events."""

from __future__ import annotations

from typing import NamedTuple

from .netlog import FiveTupleData, DomainConnections
from .mihomo_log import MihomoConnection


class CorrelatedFlow(NamedTuple):
    name: str
    relation: str
    pre_proxy: FiveTupleData
    post_proxy: FiveTupleData


class CorrelationResult(NamedTuple):
    domain: str
    flows: list[CorrelatedFlow]


def correlate(
    netlog_conns: list[DomainConnections],
    mihomo_conns: dict[str, MihomoConnection],
    domain: str,
) -> CorrelationResult:
    flows: list[CorrelatedFlow] = []

    for dc in netlog_conns:
        for ft in dc.five_tuples:
            mconn = _find_matching_mihomo(ft, mihomo_conns)
            if mconn is None:
                continue

            pre_proxy = ft

            post_proxy = FiveTupleData(
                src_ip="", src_port=0,
                dst_ip="", dst_port=0,
                protocol="",
            )
            if mconn.proxy_dial:
                out_ip, out_port = _parse_addr(mconn.proxy_dial.out_src)
                proxy_ip, proxy_port = _parse_addr(mconn.proxy_dial.proxy_addr)
                post_proxy = FiveTupleData(
                    src_ip=out_ip, src_port=out_port,
                    dst_ip=proxy_ip, dst_port=proxy_port,
                    protocol="tcp",
                )
            elif mconn.connect:
                dst_ip, dst_port = _parse_addr(mconn.connect.dst)
                post_proxy = FiveTupleData(
                    src_ip="", src_port=0,
                    dst_ip=dst_ip, dst_port=dst_port,
                    protocol="tcp",
                )

            flows.append(CorrelatedFlow(
                name=dc.name,
                relation=dc.relation,
                pre_proxy=pre_proxy,
                post_proxy=post_proxy,
            ))

    return CorrelationResult(domain=domain, flows=flows)


def _find_matching_mihomo(
    ft: FiveTupleData,
    mihomo_conns: dict[str, MihomoConnection],
) -> MihomoConnection | None:
    netlog_src = f"{ft.src_ip}:{ft.src_port}"
    netlog_dst = f"{ft.dst_ip}:{ft.dst_port}"

    for conn_id, mconn in mihomo_conns.items():
        if mconn.connect is None:
            continue
        m_src = mconn.connect.src
        m_dst = mconn.connect.dst
        if netlog_src == m_src or netlog_src == m_dst:
            return mconn
        if netlog_dst == m_src or netlog_dst == m_dst:
            return mconn

    return None


def _parse_addr(addr: str) -> tuple[str, int]:
    if not addr:
        return ("", 0)
    if addr.startswith("["):
        idx = addr.rfind("]:")
        if idx == -1:
            return ("", 0)
        host = addr[1:idx]
        port_str = addr[idx + 2:]
    else:
        idx = addr.rfind(":")
        if idx == -1:
            return (addr, 0)
        host = addr[:idx]
        port_str = addr[idx + 1:]
    try:
        port = int(port_str)
    except ValueError:
        return (host, 0)
    return (host, port)
```

- [ ] **Step 2: Write test_correlator.py**

```python
"""Tests for correlation engine."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.analyze.netlog import FiveTupleData, DomainConnections
from traffictracer.analyze.mihomo_log import (
    MihomoConnection, TcpConnect, TcpProxyDial, TcpClose,
)
from traffictracer.analyze.correlator import correlate, CorrelationResult, CorrelatedFlow


def test_correlate_matching():
    netlog_conns = [
        DomainConnections(
            name="https://www.example.com",
            site="https://example.com",
            relation="same_site",
            five_tuples=[
                FiveTupleData("127.0.0.1", 55555, "127.0.0.1", 7890, "tcp"),
            ],
        ),
    ]

    mihomo_conns = {
        "conn-1": MihomoConnection(
            conn_id="conn-1",
            connect=TcpConnect(
                ts="", conn_id="conn-1",
                src="127.0.0.1:55555", dst="127.0.0.1:7890",
                host="www.example.com",
            ),
            proxy_dial=TcpProxyDial(
                ts="", conn_id="conn-1",
                proxy="Proxy", proxy_type="ss",
                proxy_addr="1.2.3.4:443",
                out_src="192.168.1.100:41234",
            ),
            close=None,
        ),
    }

    result = correlate(netlog_conns, mihomo_conns, "example.com")
    assert result.domain == "example.com"
    assert len(result.flows) == 1
    assert result.flows[0].pre_proxy.src_port == 55555
    assert result.flows[0].post_proxy.src_ip == "192.168.1.100"
    assert result.flows[0].post_proxy.src_port == 41234
    assert result.flows[0].post_proxy.dst_ip == "1.2.3.4"
    assert result.flows[0].post_proxy.dst_port == 443


def test_correlate_no_match():
    netlog_conns = [
        DomainConnections(
            name="https://no-match.com",
            site="https://no-match.com",
            relation="same_site",
            five_tuples=[
                FiveTupleData("127.0.0.1", 99999, "127.0.0.1", 7890, "tcp"),
            ],
        ),
    ]
    mihomo_conns = {
        "conn-1": MihomoConnection(
            conn_id="conn-1",
            connect=TcpConnect(
                ts="", conn_id="conn-1",
                src="127.0.0.1:55555", dst="127.0.0.1:7890",
                host="other.example.com",
            ),
            proxy_dial=None,
            close=None,
        ),
    }
    result = correlate(netlog_conns, mihomo_conns, "no-match.com")
    assert len(result.flows) == 0


if __name__ == "__main__":
    test_correlate_matching()
    test_correlate_no_match()
    print("\n✓ All correlator tests passed!")
```

- [ ] **Step 3: Run test to verify**

Run: `python test/test_correlator.py`
Expected: `✓ All correlator tests passed!`

- [ ] **Step 4: Commit**

```bash
git add traffictracer/analyze/correlator.py test/test_correlator.py
git commit -m "feat: add correlation engine for NetLog-Mihomo matching"
```

---

### Task 9: pcap splitter (per-flow filtering)

**Files:**
- Create: `traffictracer/analyze/pcap_splitter.py`
- Create: `test/test_pcap_splitter.py`

**Interfaces:**
- Consumes: `traffictracer.analyze.correlator.CorrelationResult`
- Produces:
  - `build_tshark_filter(ft: FiveTupleData, direction: str) -> str` — direction: "src" | "dst"
  - `split_flows(result: CorrelationResult, tun_pcap: str, phys_pcap: str, output_base: str) -> None`

- [ ] **Step 1: Write pcap_splitter.py**

```python
"""pcap splitting — filter per-flow pcaps using tshark display filters."""

from __future__ import annotations

import subprocess
from pathlib import Path

from ..utils import logger, ensure_dir
from .correlator import CorrelationResult, CorrelatedFlow
from .netlog import FiveTupleData


def build_tshark_filter(ft: FiveTupleData, direction: str) -> str:
    parts = []
    if ft.src_ip and ft.src_port:
        if direction == "src":
            parts.append(f"ip.src=={ft.src_ip} and tcp.srcport=={ft.src_port}")
        else:
            parts.append(f"ip.src=={ft.src_ip} and tcp.port=={ft.src_port}")
    elif ft.src_ip:
        parts.append(f"ip.addr=={ft.src_ip}")
    return " and ".join(parts) if parts else ""


def split_flows(
    result: CorrelationResult,
    tun_pcap: str,
    phys_pcap: str,
    output_base: str,
) -> None:
    for flow in result.flows:
        rel_name = _sanitize_name(flow.name)
        root_name = result.domain
        flow_dir = ensure_dir(str(Path(output_base) / root_name / rel_name))

        pre_filter = build_tshark_filter(flow.pre_proxy, "src")
        if pre_filter:
            pre_path = str(Path(flow_dir) / "pre_proxy.pcap")
            _run_tshark_extract(tun_pcap, pre_filter, pre_path)

        post_filter = build_tshark_filter(flow.post_proxy, "src")
        if post_filter:
            post_path = str(Path(flow_dir) / "post_proxy.pcap")
            _run_tshark_extract(phys_pcap, post_filter, post_path)


def _run_tshark_extract(input_pcap: str, display_filter: str,
                         output_path: str) -> None:
    cmd = ["tshark", "-r", input_pcap, "-Y", display_filter, "-w", output_path]
    logger.info("tshark: %s", " ".join(cmd))
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=False)


def _sanitize_name(name: str) -> str:
    return name.replace("https://", "").replace("http://", "").rstrip("/")
```

- [ ] **Step 2: Write test_pcap_splitter.py**

```python
"""Tests for pcap splitter filter generation."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from traffictracer.analyze.netlog import FiveTupleData
from traffictracer.analyze.pcap_splitter import build_tshark_filter, _sanitize_name


def test_build_filter_src():
    ft = FiveTupleData("192.168.1.100", 41234, "1.2.3.4", 443, "tcp")
    f = build_tshark_filter(ft, "src")
    assert "ip.src==192.168.1.100" in f
    assert "tcp.srcport==41234" in f


def test_build_filter_dst():
    ft = FiveTupleData("192.168.1.100", 41234, "1.2.3.4", 443, "tcp")
    f = build_tshark_filter(ft, "dst")
    assert "ip.src==192.168.1.100" in f
    assert "tcp.port==41234" in f


def test_build_filter_empty():
    ft = FiveTupleData("", 0, "", 0, "")
    f = build_tshark_filter(ft, "src")
    assert f == ""


def test_sanitize_name():
    assert _sanitize_name("https://www.example.com/") == "www.example.com"
    assert _sanitize_name("https://api.example.com") == "api.example.com"
    assert _sanitize_name("http://localhost:8080/path") == "localhost:8080/path"


if __name__ == "__main__":
    test_build_filter_src()
    test_build_filter_dst()
    test_build_filter_empty()
    test_sanitize_name()
    print("\n✓ All pcap splitter tests passed!")
```

- [ ] **Step 3: Run test to verify**

Run: `python test/test_pcap_splitter.py`
Expected: `✓ All pcap splitter tests passed!`

- [ ] **Step 4: Commit**

```bash
git add traffictracer/analyze/pcap_splitter.py test/test_pcap_splitter.py
git commit -m "feat: add pcap splitter for per-flow traffic filtering"
```

---

### Task 10: Analysis pipeline orchestrator

**Files:**
- Create: `traffictracer/analyze/pipeline.py`
- Create: `test/test_analyze_pipeline.py`

**Interfaces:**
- Consumes: all analyze/ modules, traffictracer.utils
- Produces:
  - `run_analysis(session_dir: str) -> str` — returns path to correlation.json

- [ ] **Step 1: Write pipeline.py**

```python
"""Analysis pipeline — orchestrates NetLog parsing, Mihomo matching, and pcap splitting."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..utils import logger, ensure_dir, setup_logging
from .netlog import extract_five_tuples, DomainConnections
from .mihomo_log import parse_tracing_log
from .correlator import correlate, CorrelationResult
from .pcap_splitter import split_flows


def run_analysis(session_dir: str) -> str:
    setup_logging()

    session = Path(session_dir)
    if not session.exists():
        raise FileNotFoundError(f"Session directory not found: {session_dir}")

    logs_dir = session / "logs"
    captures_dir = session / "captures"
    results_dir = ensure_dir(str(session / "results"))

    all_correlations: dict[str, list[dict]] = {}

    trace_files = sorted(logs_dir.glob("mihomo_trace_*.jsonl"))
    if trace_files:
        mihomo_conns = parse_tracing_log(str(trace_files[0]))
    else:
        logger.warning("No Mihomo trace files found in %s", logs_dir)
        mihomo_conns = {}

    for domain_dir in sorted(captures_dir.iterdir()):
        if not domain_dir.is_dir():
            continue

        domain = domain_dir.name
        netlog_path = logs_dir / f"netlog_{domain}.json"

        if not netlog_path.exists():
            logger.warning("No NetLog for %s, skipping", domain)
            continue

        logger.info("Analyzing %s...", domain)

        try:
            netlog_conns = extract_five_tuples(str(netlog_path), domain)
        except Exception as e:
            logger.error("Failed to parse NetLog for %s: %s", domain, e)
            continue

        result = correlate(netlog_conns, mihomo_conns, domain)
        all_correlations[domain] = _result_to_dict(result)

        tun_pcap = str(domain_dir / "tun.pcap")
        phys_pcap = str(domain_dir / "phys.pcap")
        flows_base = str(domain_dir / "flows")

        if os.path.exists(tun_pcap) and os.path.exists(phys_pcap):
            try:
                split_flows(result, tun_pcap, phys_pcap, flows_base)
            except Exception as e:
                logger.error("pcap splitting failed for %s: %s", domain, e)

    corr_path = str(results_dir / "correlation.json")
    with open(corr_path, "w", encoding="utf-8") as f:
        json.dump(all_correlations, f, indent=2, ensure_ascii=False)

    logger.info("Correlation results written to %s", corr_path)
    return corr_path


def _result_to_dict(result: CorrelationResult) -> list[dict]:
    return [
        {
            "name": f.name,
            "relation": f.relation,
            "pre_proxy": {
                "src": f"{f.pre_proxy.src_ip}:{f.pre_proxy.src_port}" if f.pre_proxy.src_ip else "",
                "dst": f"{f.pre_proxy.dst_ip}:{f.pre_proxy.dst_port}" if f.pre_proxy.dst_ip else "",
                "proto": f.pre_proxy.protocol,
            },
            "post_proxy": {
                "src": f"{f.post_proxy.src_ip}:{f.post_proxy.src_port}" if f.post_proxy.src_ip else "",
                "dst": f"{f.post_proxy.dst_ip}:{f.post_proxy.dst_port}" if f.post_proxy.dst_ip else "",
                "proto": f.post_proxy.protocol,
            },
        }
        for f in result.flows
    ]
```

- [ ] **Step 2: Write test_analyze_pipeline.py**

```python
"""Tests for analysis pipeline result serialization."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
from traffictracer.analyze.netlog import FiveTupleData
from traffictracer.analyze.correlator import CorrelationResult, CorrelatedFlow
from traffictracer.analyze.pipeline import _result_to_dict


def test_result_to_dict():
    result = CorrelationResult(
        domain="example.com",
        flows=[
            CorrelatedFlow(
                name="https://www.example.com",
                relation="same_site",
                pre_proxy=FiveTupleData("127.0.0.1", 55555, "127.0.0.1", 7890, "tcp"),
                post_proxy=FiveTupleData("192.168.1.100", 41234, "1.2.3.4", 443, "tcp"),
            ),
        ],
    )
    d = _result_to_dict(result)
    assert len(d) == 1
    assert d[0]["name"] == "https://www.example.com"
    assert d[0]["pre_proxy"]["src"] == "127.0.0.1:55555"
    assert d[0]["post_proxy"]["dst"] == "1.2.3.4:443"
    assert d[0]["relation"] == "same_site"


def test_json_roundtrip():
    result = CorrelationResult(
        domain="test.com",
        flows=[
            CorrelatedFlow(
                name="https://cdn.test.com",
                relation="cross_site",
                pre_proxy=FiveTupleData("10.0.0.1", 443, "10.0.0.2", 8080, "tcp"),
                post_proxy=FiveTupleData("", 0, "", 0, ""),
            ),
        ],
    )
    d = _result_to_dict(result)
    j = json.dumps(d)
    parsed = json.loads(j)
    assert parsed[0]["name"] == "https://cdn.test.com"
    assert parsed[0]["post_proxy"]["src"] == ""


if __name__ == "__main__":
    test_result_to_dict()
    test_json_roundtrip()
    print("\n✓ All analysis pipeline tests passed!")
```

- [ ] **Step 3: Run test to verify**

Run: `python test/test_analyze_pipeline.py`
Expected: `✓ All analysis pipeline tests passed!`

- [ ] **Step 4: Commit**

```bash
git add traffictracer/analyze/pipeline.py test/test_analyze_pipeline.py
git commit -m "feat: add analysis pipeline orchestrator"
```

---

### Task 11: CLI entry points

**Files:**
- Create: `capture.py`
- Create: `analyze.py`
- Modify: `traffictracer/capture/pipeline.py` — add `main()` function

**Interfaces:**
- Consumes: `traffictracer.capture.pipeline.run_capture`, `traffictracer.analyze.pipeline.run_analysis`
- Produces: CLI commands `capture.py` and `analyze.py`

- [ ] **Step 1: Write capture.py**

```python
#!/usr/bin/env python3
"""TrafficTracer Capture — collect traffic data for configured domains.

Usage:
  python capture.py --config sites.yaml
  python capture.py --config sites.yaml --only bilibili.com
"""

import argparse
import sys

from traffictracer.capture.pipeline import run_capture
from traffictracer.config import load_config


def main():
    parser = argparse.ArgumentParser(
        description="TrafficTracer Capture Pipeline",
    )
    parser.add_argument("--config", "-c", required=True,
                        help="Path to YAML config file")
    parser.add_argument("--only", "-o",
                        help="Only capture this domain")
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Error loading config: {e}", file=sys.stderr)
        sys.exit(1)

    session_dir = run_capture(config, only_domain=args.only)
    print(f"Capture session saved to: {session_dir}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Write analyze.py**

```python
#!/usr/bin/env python3
"""TrafficTracer Analysis — correlate and split captured traffic data.

Usage:
  python analyze.py --session output/2025-07-05_14-30-00/
"""

import argparse
import sys

from traffictracer.analyze.pipeline import run_analysis


def main():
    parser = argparse.ArgumentParser(
        description="TrafficTracer Analysis Pipeline",
    )
    parser.add_argument("--session", "-s", required=True,
                        help="Path to capture session directory")
    args = parser.parse_args()

    try:
        corr_path = run_analysis(args.session)
        print(f"Correlation results: {corr_path}")
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Verify CLI help output**

Run: `python capture.py --help`
Expected: shows usage info and `--config`/`--only` flags

Run: `python analyze.py --help`
Expected: shows usage info and `--session` flag

- [ ] **Step 4: Commit**

```bash
git add capture.py analyze.py
git commit -m "feat: add capture.py and analyze.py CLI entry points"
```

---

### Task 12: Integration test and final verification

**Files:**
- Create: `test/test_integration.py`

**Interfaces:**
- Consumes: all modules
- Produces: integration test verifying end-to-end analysis pipeline with synthetic data

- [ ] **Step 1: Write test_integration.py**

```python
"""Integration test — end-to-end analysis pipeline with synthetic data."""

import sys
import os
import json
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pathlib import Path
from traffictracer.analyze.netlog import extract_five_tuples
from traffictracer.analyze.mihomo_log import parse_tracing_log
from traffictracer.analyze.correlator import correlate
from traffictracer.analyze.pcap_splitter import build_tshark_filter


def test_analysis_integration():
    tmpdir = tempfile.mkdtemp()

    # Create synthetic NetLog JSON
    netlog = {
        "constants": {
            "logFormatVersion": 1,
            "timeTickOffset": "1329000000000",
            "logEventTypes": {
                "REQUEST_ALIVE": 0, "URL_REQUEST_START_JOB": 11,
                "TCP_CONNECT": 4, "SOCKET_ALIVE": 3, "SSL_CONNECT": 50,
            },
            "logSourceType": {
                "URL_REQUEST": 1, "TRANSPORT_CONNECT_JOB": 2,
                "SOCKET": 3, "HTTP_STREAM_JOB": 5,
                "HTTP_PROXY_CONNECT_JOB": 10, "TCP_STREAM_ATTEMPT": 20,
            },
            "logEventPhase": {"PHASE_BEGIN": 0, "PHASE_END": 1, "PHASE_NONE": 2},
            "clientInfo": {"name": "integration-test"},
        },
        "events": [
            {"time": "1000", "type": 0, "phase": 0, "source": {"id": 100, "type": 1},
             "params": {"url": "https://www.example.com/",
                        "source_dependency": {"id": 200, "type": 5}}},
            {"time": "1100", "type": 21, "phase": 2, "source": {"id": 200, "type": 5},
             "params": {"group_id": "https://www.example.com <https://example.com same_site>"}},
            {"time": "1200", "type": 50, "phase": 2, "source": {"id": 300, "type": 10},
             "params": {"local_address": "127.0.0.1:55555",
                        "remote_address": "127.0.0.1:7890",
                        "source_dependency": {"id": 200, "type": 5}}},
        ],
    }
    netlog_path = os.path.join(tmpdir, "netlog_example.com.json")
    with open(netlog_path, "w") as f:
        json.dump(netlog, f)

    # Create synthetic Mihomo trace
    trace_path = os.path.join(tmpdir, "mihomo_trace.jsonl")
    with open(trace_path, "w") as f:
        f.write('{"ts":"","type":"tcp_connect","conn_id":"c1",'
                '"src":"127.0.0.1:55555","dst":"127.0.0.1:7890",'
                '"host":"www.example.com"}\n')
        f.write('{"ts":"","type":"tcp_proxy_dial","conn_id":"c1",'
                '"proxy":"Proxy","proxy_type":"ss","proxy_addr":"1.2.3.4:443",'
                '"out_src":"192.168.1.100:41234"}\n')

    # Parse
    netlog_conns = extract_five_tuples(netlog_path, "example.com")
    mihomo_conns = parse_tracing_log(trace_path)

    assert len(mihomo_conns) == 1
    assert "c1" in mihomo_conns

    # Correlate
    result = correlate(netlog_conns, mihomo_conns, "example.com")
    assert result.domain == "example.com"

    # Verify filter generation
    for flow in result.flows:
        if flow.pre_proxy.src_port == 55555:
            assert flow.pre_proxy.src_ip == "127.0.0.1"
            f = build_tshark_filter(flow.pre_proxy, "src")
            assert "tcp.srcport==55555" in f

    # Cleanup
    import shutil
    shutil.rmtree(tmpdir)
    print("  ✓ integration test pass")


if __name__ == "__main__":
    test_analysis_integration()
    print("\n✓ All integration tests passed!")
```

- [ ] **Step 2: Run integration test**

Run: `python test/test_integration.py`
Expected: `✓ All integration tests passed!`

- [ ] **Step 3: Run all tests**

```bash
python test/test_config.py && python test/test_mihomo.py && python test/test_tshark.py && python test/test_chrome.py && python test/test_capture_pipeline.py && python test/test_netlog.py && python test/test_mihomo_log.py && python test/test_correlator.py && python test/test_pcap_splitter.py && python test/test_analyze_pipeline.py && python test/test_integration.py && python test/test_parser.py
```

- [ ] **Step 4: Commit**

```bash
git add test/test_integration.py
git commit -m "test: add integration test for analysis pipeline"
```
