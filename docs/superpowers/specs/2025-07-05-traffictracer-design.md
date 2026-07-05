# TrafficTracer Design Spec

## Overview

Build a complete traffic capture and analysis pipeline that correlates Chrome browsing traffic before and after Mihomo proxy, achieving precise domain-level pre/post proxy traffic association.

The system consists of two independent pipelines:

- **Capture Pipeline**: Automates traffic collection for a list of target domains — launches Mihomo proxy (TUN mode), runs tshark on both TUN and physical interfaces, opens Chrome with NetLog, visits each domain, and collects all artifacts.
- **Analysis Pipeline**: Offline processing — parses Chrome NetLog for 5-tuples, matches with Mihomo tracing logs to correlate pre-proxy and post-proxy connections, then splits pcap files per-flow.

## Architecture

```
┌──────────────┐     ┌──────────────┐
│  Capture     │──▶  │  Analysis    │
│  Pipeline    │     │  Pipeline    │
└──────────────┘     └──────────────┘
   (online)            (offline)
```

Two pipelines run independently. Capture runs first to collect all data; analysis can be run later against any capture session.

## Configuration File (YAML)

File: `sites.yaml` (or user-specified)

```yaml
global:
  mihomo:
    binary: /path/to/mihomo
    config: /path/to/mihomo.yaml     # TUN mode config with tracing: true
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
    wait: 10                         # seconds to wait after page load
    traffic_type: all                # all | tcp | udp
  - domain: youtube.com
    url: "https://www.youtube.com"
    wait: 15
    traffic_type: tcp
```

## Project Structure

```
TrafficTracer/
├── traffictracer/                  # new main package
│   ├── __init__.py
│   ├── config.py                   # YAML config loading and validation
│   ├── capture/
│   │   ├── __init__.py
│   │   ├── pipeline.py             # capture main loop
│   │   ├── mihomo.py               # Mihomo process management + API control
│   │   ├── tshark.py               # tshark subprocess management
│   │   └── chrome.py               # Chrome subprocess management
│   ├── analyze/
│   │   ├── __init__.py
│   │   ├── pipeline.py             # analysis main flow
│   │   ├── netlog.py               # wraps parser/ calls, extracts 5-tuples
│   │   ├── mihomo_log.py           # parses tracing JSONL, builds conn_id map
│   │   ├── correlator.py           # 5-tuple matching engine
│   │   └── pcap_splitter.py        # tshark-based pcap splitting by flow
│   └── utils.py                    # shared utilities (dirs, process cleanup, logging)
├── parser/                         # existing, unchanged
│   ├── __init__.py
│   ├── constants.py
│   ├── source_entry.py
│   ├── event_processor.py
│   ├── dependency_graph.py
│   ├── dns_resolver.py
│   ├── domain_analyzer.py
│   └── output.py
├── netlog_parser.py                # existing CLI, unchanged
├── capture.py                      # capture pipeline CLI entry
├── analyze.py                      # analysis pipeline CLI entry
└── sites.example.yaml              # example config
```

## Capture Pipeline

### CLI

```bash
python capture.py --config sites.yaml              # run all sites
python capture.py --config sites.yaml --only bilibili.com  # single site
```

### Per-Domain Loop

For each site in the config:

1. Ensure Mihomo is running (start if not)
2. Enable tracing via `PATCH /experimental/tracing` with output path set to per-domain trace file
3. Start tshark on TUN interface → `captures/<domain>/tun.pcap`
4. Start tshark on physical interface → `captures/<domain>/phys.pcap`
5. Launch Chrome as subprocess:
   ```
   chrome --user-data-dir=<dir> \
          --log-net-log=<netlog_path> \
          --proxy-server=<mihomo_addr> \
          <url>
   ```
6. Wait for configured duration (e.g., 10s)
7. Kill Chrome process → NetLog flushed on process exit
8. Send `SIGTERM` to both tshark processes, `wait()` for clean exit with 5s timeout before `SIGKILL` fallback
9. Move artifacts to `output/<session>/captures/<domain>/`
10. Optionally disable tracing

### Key Behaviors

- Mihomo stays running for the entire session; only tracing output path changes between domains
- Chrome is a fresh process per domain, killed after each run
- Signal handlers ensure subprocess cleanup on `SIGINT`/`SIGTERM`
- tshark graceful shutdown: SIGTERM first, wait with timeout, SIGKILL as fallback

## Analysis Pipeline

### CLI

```bash
python analyze.py --session output/2025-07-05_14-30-00/
```

### Step 1: NetLog → 5-Tuples

For each domain's NetLog JSON, use existing `parser/domain_analyzer.py` to extract all related connections. Output for each connection:

```
(src_ip, src_port, dst_ip, dst_port, protocol)
```

Protocol is extracted from SSL_CONNECT events when available; may be empty.

### Step 2: Parse Mihomo Tracing Logs

Parse the JSONL tracing file, building a per-connection map:

```
conn_id → {
  tcp_connect: {src, dst, host, process, ...}
  tcp_proxy_dial: {proxy, proxy_addr, out_src, ...}
  tcp_close: {bytes_up, bytes_down, duration_ms}
}
```

### Step 3: Correlation Matching

Match NetLog 5-tuples against Mihomo logs:

1. NetLog 5-tuple `(src_ip:src_port, dst_ip:dst_port)` is matched against Mihomo `tcp_connect.src` (the connection as seen by TUN)
2. The matching yields a `conn_id`
3. From `tcp_connect.dst` → post-proxy target address
4. From `tcp_proxy_dial.out_src` → physical egress 5-tuple

### Output Structure

```json
{
  "domain.com": [
    {
      "name": "sub.domain.com",
      "relation": "same_site",
      "pre_proxy": {"src": "127.0.0.1:51891", "dst": "127.0.0.1:7890", "proto": "tcp"},
      "post_proxy": {"src": "192.168.1.100:41234", "dst": "1.2.3.4:443", "proto": "tcp"}
    }
  ]
}
```

### Step 4: pcap Splitting

For each matched flow, use tshark display filters to extract per-flow pcaps:

```bash
tshark -r tun.pcap -Y "tcp.port==51891" -w pre_proxy.pcap
tshark -r phys.pcap -Y "tcp.port==41234" -w post_proxy.pcap
```

Files written to: `output/<session>/captures/<domain>/flows/<root_domain>/<relative_domain>/`

## Output Directory Structure

```
output/
  2025-07-05_14-30-00/                   # one capture session
    captures/
      bilibili.com/
        tun.pcap                         # raw TUN interface capture
        phys.pcap                        # raw physical interface capture
        flows/
          bilibili.com/                  # root domain
            www.bilibili.com/            # relative domain
              pre_proxy.pcap             # per-flow pre-proxy traffic
              post_proxy.pcap            # per-flow post-proxy traffic
            api.bilibili.com/
              pre_proxy.pcap
              post_proxy.pcap
      youtube.com/
        ...
    logs/
      netlog_bilibili.com.json           # Chrome NetLog per domain
      netlog_youtube.com.json
      mihomo_trace.jsonl                 # Mihomo tracing log (all domains)
      chrome_stderr.log                  # Chrome stderr
    results/
      correlation.json                   # full correlation table
```

## Error Handling

- **Mihomo fails to start**: exit with clear error, suggest checking binary path and config
- **tshark not found**: exit with "install tshark/wireshark" message
- **Chrome not found**: exit with error, suggest checking binary path
- **NetLog JSON empty/corrupt**: skip domain in analysis, log warning, continue with remaining
- **Mihomo trace missing conn_id**: log warning, mark as uncorrelated, continue
- **pcap filtering yields empty file**: log warning, write empty file or skip

## Environment

- Conda environment: `traffictracer`
- Python 3.10+ (stdlib only, no pip packages outside stdlib)
- tshark (Wireshark CLI)
- Mihomo binary (custom TrafficTracer branch, from `../mihomo/`)
- Chrome/Chromium browser

## Testing Strategy

- Unit tests for config parsing, Mihomo log parsing, correlation matching, pcap filter string generation
- Integration test: a small script that verifies the full pipeline with a controlled setup
- Existing `test/test_parser.py` remains as-is
