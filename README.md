# TrafficTracer

Capture and correlate network traffic before and after Mihomo proxy at domain-level granularity. Orchestrates Chrome NetLog capture, dual-interface packet sniffing, and Mihomo connection tracing to produce per-flow correlation tables and filtered pcap files.

## Architecture

TrafficTracer consists of two independent pipelines:

```
┌──────────────┐     ┌──────────────┐
│  Capture     │──▶  │  Analysis    │
│  Pipeline    │     │  Pipeline    │
└──────────────┘     └──────────────┘
```

- **Capture Pipeline** — Launches Mihomo (TUN mode), tshark on both TUN and physical interfaces, Chrome with NetLog enabled, visits each target domain, collects all artifacts.
- **Analysis Pipeline** — Offline processing: parses Chrome NetLog for 5-tuples, matches with Mihomo tracing logs to correlate pre-proxy and post-proxy connections, splits pcap files per flow.

The two pipelines run independently. Capture first to collect data; analyze later against any session.

## Prerequisites

| Component | Purpose |
|-----------|---------|
| Python 3.10+ | Runtime (stdlib + pyyaml) |
| Mihomo | Proxy, from [../mihomo](../mihomo/) TrafficTracer branch |
| tshark | Packet capture (included in Wireshark) |
| Chrome / Chromium | Browser with `--log-net-log` support (Chrome 109+) |
| tcpdump / libcap | Capture privilege (may need `sudo setcap` for tshark) |

## Installation

```bash
# Clone and enter the repo
git clone <this-repo> && cd TrafficTracer

# Create conda environment
conda create -n traffictracer python=3.12 -y
conda activate traffictracer
pip install pyyaml
```

### Install Chrome

```bash
# Ubuntu / Debian
wget -q -O /tmp/google-chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i /tmp/google-chrome.deb || sudo apt-get install -f -y

# Verify
google-chrome --version
```

### Install tshark

```bash
# Ubuntu / Debian
sudo apt-get install -y tshark

# Grant non-root capture capability (optional)
sudo setcap cap_net_raw,cap_net_admin=eip $(which tshark)
```

### Build Mihomo (TrafficTracer branch)

```bash
cd ../mihomo
git checkout TrafficTracer
make  # or go build
```

## Quick Start

### 1. Write a config file

Copy the example and fill in your environment:

```bash
cp sites.example.yaml sites.yaml
```

Edit `sites.yaml`:

```yaml
global:
  mihomo:
    binary: /path/to/mihomo              # compiled from TrafficTracer branch
    config: /path/to/mihomo.yaml         # TUN mode config with tracing: true
    api: "http://127.0.0.1:9090"
  chrome:
    binary: google-chrome
    user_data_dir: /tmp/chrome-profile
    headless: false                       # set true for headless server
  network:
    tun_interface: utun                   # TUN virtual NIC name
    phys_interface: eth0                  # physical NIC name
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

### 2. Run capture

```bash
# Capture all sites in config
python capture.py --config sites.yaml

# Capture a single site
python capture.py --config sites.yaml --only bilibili.com
```

This produces a session directory:

```
output/
  2025-07-05_14-30-00/
    captures/
      bilibili.com/
        tun.pcap              # raw TUN interface capture
        phys.pcap             # raw physical interface capture
    logs/
      netlog_bilibili.com.json   # Chrome NetLog
      mihomo_trace_bilibili.com.jsonl  # Mihomo tracing log
```

### 3. Run analysis

```bash
python analyze.py --session output/2025-07-05_14-30-00/
```

This enriches the session with:

```
output/2025-07-05_14-30-00/
  captures/
    bilibili.com/
      flows/                       # per-flow filtered pcaps
        bilibili.com/
          www.bilibili.com/
            pre_proxy.pcap         # traffic before proxy
            post_proxy.pcap        # traffic after proxy
  results/
    correlation.json               # full correlation table
```

### 4. Read correlation results

`correlation.json` maps each domain's connections to their pre- and post-proxy 5-tuples:

```json
{
  "bilibili.com": [
    {
      "name": "https://www.bilibili.com",
      "relation": "same_site",
      "pre_proxy": {"src": "127.0.0.1:51891", "dst": "127.0.0.1:7890", "proto": "tcp"},
      "post_proxy": {"src": "192.168.1.100:41234", "dst": "1.2.3.4:443", "proto": "tcp"}
    }
  ]
}
```

## Configuration Reference

### `global`

| Key | Description |
|-----|-------------|
| `mihomo.binary` | Path to Mihomo executable (TrafficTracer branch) |
| `mihomo.config` | Path to Mihomo YAML config (TUN mode, `tracing: true`) |
| `mihomo.api` | Mihomo REST API address (default `http://127.0.0.1:9090`) |
| `chrome.binary` | Chrome executable name or path |
| `chrome.user_data_dir` | Dedicated profile directory (avoids polluting daily profile) |
| `chrome.headless` | Run Chrome in headless mode (`true` for servers) |
| `network.tun_interface` | TUN virtual NIC name (e.g. `utun`, `tun0`) |
| `network.phys_interface` | Physical NIC name (e.g. `eth0`, `enp0s3`) |
| `output.base_dir` | Root directory for capture sessions |

### `sites`

| Key | Description |
|-----|-------------|
| `domain` | Target domain name (used for file naming and NetLog analysis) |
| `url` | Full URL to visit |
| `wait` | Seconds to wait after page load before stopping capture (default: 10) |
| `traffic_type` | `all`, `tcp`, or `udp` (filter hint, currently informational) |

## Mihomo Configuration

Your Mihomo config must enable TUN mode and tracing. Minimal example:

```yaml
# mihomo.yaml
tun:
  enable: true
  stack: system
  mtu: 1500
  device: utun

experimental:
  tracing: true

external-controller: "127.0.0.1:9090"
```

The Mihomo TrafficTracer branch adds connection-level event logging via the `component/tracer` package. Each TCP connection emits three JSON Lines events:

```json
{"type":"tcp_connect","conn_id":"...","src":"...","dst":"...","host":"..."}
{"type":"tcp_proxy_dial","conn_id":"...","out_src":"...","proxy_addr":"..."}
{"type":"tcp_close","conn_id":"...","bytes_up":...,"bytes_down":...,"duration_ms":...}
```

These are cross-referenced with Chrome NetLog 5-tuples to produce the correlation table.

## NetLog Parser (Legacy)

The `netlog_parser.py` CLI and `parser/` package provide standalone Chrome NetLog analysis without the full capture pipeline.

```bash
# Full analysis
python netlog_parser.py chrome-net-export-log.json

# Domain analysis — group connections by site relationship
python netlog_parser.py -d bilibili.com log.json

# JSON export
python netlog_parser.py -d bilibili.com --json log.json

# Load from chrome://net-export ZIP
python netlog_parser.py net-export-log.zip
```

For full NetLog Parser usage, see the [original documentation](#netlog-parser-usage) below.

## Project Structure

```
TrafficTracer/
├── capture.py                         # Capture pipeline CLI
├── analyze.py                         # Analysis pipeline CLI
├── netlog_parser.py                   # Standalone NetLog parser CLI
├── sites.example.yaml                 # Capture config template
├── traffictracer/                     # Main package
│   ├── config.py                      # YAML config loading & validation
│   ├── utils.py                       # Shared utilities
│   ├── capture/
│   │   ├── pipeline.py                # Capture orchestrator (per-domain loop)
│   │   ├── mihomo.py                  # Mihomo process manager & tracing API
│   │   ├── tshark.py                  # tshark subprocess (SIGTERM→wait→SIGKILL)
│   │   └── chrome.py                  # Chrome launch (--log-net-log) & kill
│   └── analyze/
│       ├── pipeline.py                # Analysis orchestrator
│       ├── netlog.py                  # NetLog → 5-tuple extraction
│       ├── mihomo_log.py              # Mihomo JSONL trace parser
│       ├── correlator.py              # 5-tuple matching engine
│       └── pcap_splitter.py           # Per-flow pcap filtering (tshark -Y)
├── parser/                            # Chromium NetLog parser (standalone)
│   ├── constants.py                   # Source/event type constants
│   ├── source_entry.py                # Per-source event grouping
│   ├── event_processor.py             # Event processing pipeline
│   ├── dependency_graph.py            # Connection chain tracing & 5-tuple
│   ├── dns_resolver.py                # DNS cache extraction
│   ├── domain_analyzer.py             # Domain-level connection analysis
│   └── output.py                      # Formatted output
└── test/
    ├── test_parser.py                 # NetLog parser tests
    ├── test_config.py                 # Config loading tests
    ├── test_capture_pipeline.py       # Capture pipeline tests
    ├── test_mihomo.py                 # Mihomo manager tests
    ├── test_tshark.py                 # tshark manager tests
    ├── test_chrome.py                 # Chrome manager tests
    ├── test_netlog.py                 # 5-tuple extractor tests
    ├── test_mihomo_log.py             # Tracing log parser tests
    ├── test_correlator.py             # Correlation engine tests
    ├── test_pcap_splitter.py          # pcap splitter tests
    ├── test_analyze_pipeline.py       # Analysis pipeline tests
    └── test_integration.py            # End-to-end analysis test
```

## Running Tests

```bash
# Run all tests
python test/test_config.py && \
python test/test_mihomo.py && \
python test/test_tshark.py && \
python test/test_chrome.py && \
python test/test_capture_pipeline.py && \
python test/test_netlog.py && \
python test/test_mihomo_log.py && \
python test/test_correlator.py && \
python test/test_pcap_splitter.py && \
python test/test_analyze_pipeline.py && \
python test/test_integration.py && \
python test/test_parser.py
```

## Troubleshooting

**Chrome fails to start with "user data directory is already in use"**
Kill any lingering Chrome processes and try again, or use a different `user_data_dir`.

**tshark "Permission denied"**
Run `sudo setcap cap_net_raw,cap_net_admin=eip $(which tshark)` or use `sudo`.

**Mihomo API unreachable**
Verify the `external-controller` address in your Mihomo config matches `api` in `sites.yaml`.

**Analysis produces empty correlation**
Check that the Mihomo trace file contains `tcp_connect` events with `src`/`dst` matching the NetLog 5-tuples. The capture must use TUN mode with `tracing: true`.

---

# NetLog Parser Usage

This section documents the standalone `netlog_parser.py` CLI.

## Quick Start

```bash
# Full analysis
python netlog_parser.py chrome-net-export-log.json

# Domain analysis
python netlog_parser.py -d bilibili.com log.json

# Domain analysis with JSON export
python netlog_parser.py -d bilibili.com --json log.json

# Summary only
python netlog_parser.py --summary log.json

# Connection chains only
python netlog_parser.py --chains log.json

# Chain filtering by URL pattern
python netlog_parser.py --chains --url "*bilibili*" log.json

# DNS records only
python netlog_parser.py --dns log.json

# Load from chrome://net-export ZIP
python netlog_parser.py net-export-log.zip
```

## CLI Arguments

| Flag | Description |
|------|-------------|
| `FILE` | Path to a NetLog JSON file or ZIP archive |
| `-d`, `--domain` | Analyze all connections for a specific domain |
| `--summary` | Print source type breakdown and error counts |
| `--chains` | Print connection dependency chains (URL_REQUEST → TCP/TLS) |
| `--dns` | Print DNS resolver cache entries |
| `--sessions` | Print HTTP/2 and QUIC session reuse |
| `--json` | Export parsed data as JSON |
| `--output`, `-o` | Write output to file instead of stdout |
| `--start-from` | Chain root type: `url_request` (default) or `socket` |
| `--url` | Filter chains by URL glob pattern |

## Domain Analysis

```bash
python netlog_parser.py -d bilibili.com log.json
```

```
  [SAME_SITE] https://www.bilibili.com
  Site:       https://bilibili.com
  Connections: 1
  Addresses:
    127.0.0.1:51891  ->  127.0.0.1:7890

  [CROSS_SITE] https://s1.hdslb.com
  Site:       https://bilibili.com
  Connections: 1
  Addresses:
    127.0.0.1:51924  ->  127.0.0.1:7890
```

## Programmatic API

```python
from parser.domain_analyzer import get_domain_connections

results = get_domain_connections("chrome-net-export-log.json", "bilibili.com")

for item in results:
    print(f"[{item['relation']}] {item['name']}: {item['connection_num']} connections")
    for addr in item["connection_detail"]:
        print(f"  {addr['local_address']} -> {addr['remote_address']}")
```

## Capturing NetLogs Manually

In Chrome/Chromium:

1. Navigate to `chrome://net-export`
2. Click **Start Logging to Disk**
3. Reproduce the network activity
4. Click **Stop Logging**
5. The log is saved as JSON or ZIP
