# TrafficTracer

Capture and correlate network traffic before and after Mihomo proxy at domain-level granularity. Orchestrates Chrome NetLog capture, dual-interface packet sniffing, and Mihomo connection tracing to produce per-flow correlation tables and filtered pcap files.

TrafficTracer now supports CDP-based request-level logging.

CDP is used to collect browser-side request semantics:
tab/page request, URL, resource type, frameId, requestId, response status and timestamps.

NetLog is still used for Chrome network-stack information:
URL_REQUEST, DNS, socket, TLS, QUIC, cache and proxy events.

pcap is still used for real packet-level traffic.

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

A minimal working example — capture bilibili.com traffic and run correlation. **The capture pipeline auto-starts and stops mihomo** — no manual start needed.

### 1. One-Time Setup

```bash
# Grant TUN capability to mihomo binary
sudo setcap cap_net_admin+eip ../mihomo/bin/mihomo-traffictracer

# Find your active physical NIC (use this for phys_interface)
ip route show default
# default via 192.168.5.1 dev wlp2s0 ...  ← your phys_interface
```

### 2. Write sites.yaml

```yaml
global:
  mihomo:
    binary: ../mihomo/bin/mihomo-traffictracer
    config: mihomo-configs/config.yaml
    api: "http://127.0.0.1:9099"
  chrome:
    binary: google-chrome
    user_data_dir: chrome-profile
    headless: true
  network:
    tun_interface: utun
    phys_interface: wlp2s0        # from 'ip route show default'
  output:
    base_dir: /data/datasets/ttTest-0705

sites:
  - domain: bilibili.com
    url: "https://www.bilibili.com"
    wait: 15
    traffic_type: video-mainpage
```

### 3. Run Capture

The pipeline auto-starts mihomo (TUN mode), enables tracing, captures on both interfaces, launches Chrome, waits 15s, then stops everything.

```bash
python capture.py --config sites.yaml --only bilibili.com
```

Produces a session directory:

```
output/2026-07-07_10-35-05/
  captures/bilibili.com/
    tun.pcap              # raw TUN interface capture (pre-proxy)
    phys.pcap             # raw physical interface capture (post-proxy)
  logs/
    netlog_bilibili.com.json          # Chrome NetLog
    cdp_bilibili.com.json             # CDP request events
    mihomo_trace_bilibili.com.jsonl   # Mihomo connection trace (JSONL)
    proxy_info_bilibili.com.json      # proxy node info at capture time
```

### 4. Run Analysis

```bash
python analyze.py --session output/2026-07-07_10-35-05/
```

> **NetLog truncated?** Chrome is now closed through CDP `Browser.close` when CDP is enabled.
> If NetLog is still truncated, TrafficTracer backs up the original file as `*.truncated.bak`
> and attempts conservative repair automatically. No manual fix needed.

Enriches the session with per-flow pcaps and a correlation table:

```
session/
  captures/bilibili.com/flows/
    bilibili.com/
      www.bilibili.com/
        pre_proxy.pcap      # traffic entering proxy
        post_proxy.pcap     # traffic leaving proxy
      api.bilibili.com/
        pre_proxy.pcap
        post_proxy.pcap
  results/
    correlation.json         # full correlation table
```

### 5. Read Correlation Results

```bash
python3 -c "
import json
with open('output/2026-07-05_21-45-51/results/correlation.json') as f:
    data = json.load(f)
for domain, flows in data.items():
    print(f'{domain}: {len(flows)} flows')
"
# bilibili.com: 17 flows
```

`correlation.json` maps each connection to its pre- and post-proxy 5-tuples:

```json
{
  "bilibili.com": [
    {
      "name": "https://www.bilibili.com",
      "relation": "same_site",
      "pre_proxy":  {"src": "198.18.0.1:49812", "dst": "223.111.250.57:443"},
      "post_proxy": {"src": "192.168.5.101:53652", "dst": "223.111.250.57:443"}
    }
  ]
}
```

- **pre_proxy** — traffic seen on the TUN interface (fake-ip `198.18.0.1`)
- **post_proxy** — traffic leaving the physical NIC (real machine IP)
- **relation** — `same_site` (main domain) or `cross_site` (third-party sub-resources)

### 6. Manual Mihomo Control

The capture pipeline manages mihomo automatically. Use these scripts when you need to start/stop mihomo independently (e.g. for testing proxy connectivity):

```bash
bash scripts/start-mihomo.sh   # start with TUN (saves routes)
bash scripts/stop-mihomo.sh    # safe stop (restores routes first)
```

The stop script **restores original network routes before killing mihomo**, so your terminal's network connection stays alive.

## Mihomo Proxy Operations

The capture pipeline automatically starts and stops mihomo. This section explains how to manage mihomo manually for testing, debugging, or custom workflows.

### Configuring the proxy

A mihomo config directory must contain:

```
mihomo-configs/
├── config.yaml       # main config (ports, TUN, proxies, rules, tracing)
├── geosite.dat       # domain categorization rules
├── geoip.dat         # IP geo-location data
└── geoip.metadb      # MaxMind GeoIP database
```

Key sections in `config.yaml`:

```yaml
# ——— Ports ———
mixed-port: 7890                 # HTTP(S) + SOCKS5 proxy (Chrome connects here)
external-controller: 127.0.0.1:9099  # REST API (tracing control)

# ——— DNS ———
dns:
  enable: true
  enhanced-mode: fake-ip         # returns 198.18.0.x for proxied domains
  nameserver: [223.5.5.5, 119.29.29.29]
  fallback: ['https://cloudflare-dns.com/dns-query', ...]

# ——— Proxies ———
proxies:
  - { name: 'HK-BGP1', type: vless, server: ..., port: ..., uuid: ..., ... }
  - { name: 'JP-Tokyo-01', type: vless, server: ..., port: ..., uuid: ..., ... }

# ——— Proxy Groups ———
proxy-groups:
  - { name: '🚀 节点选择', type: select, proxies: ['♻️ Auto', 'HK-BGP1', ...] }
  - { name: '🐟 漏网之鱼', type: select, proxies: ['🚀 节点选择', DIRECT] }

# ——— Rules ———
rules:
  - DOMAIN-SUFFIX,bilibili.com,DIRECT    # domestic site → direct
  - GEOIP,cn,DIRECT                       # China IP → direct
  - MATCH,🐟 漏网之鱼                      # everything else → proxy

# ——— TUN (traffic interception) ———
tun:
  enable: true
  stack: gvisor                  # userspace TCP/IP stack (requires cap_net_admin)
  device: utun                   # virtual NIC name
  auto-route: true               # redirect all system traffic through TUN
  auto-detect-interface: true    # auto-detect physical NIC
  dns-hijack:
    - any:53                     # intercept all DNS queries

# ——— Tracing (TrafficTracer) ———
experimental:
  tracing: true
```

### Starting mihomo

```bash
# Start with a config directory (NOT -f for single file — geodata won't load)
/path/to/mihomo-linux-amd64 -d /tmp/mihomo-test &

# Wait for startup (~2-3 seconds for large configs)
sleep 3
```

### Checking mihomo status

```bash
API="http://127.0.0.1:9099"

# Version
curl -s $API/version
# {"meta":true,"version":"0897f41f"}

# Current proxy node
curl -s $API/proxies | python3 -c "import json,sys; d=json.load(sys.stdin);
print(d['proxies']['GLOBAL']['now'])"

# Tracing status
curl -s $API/experimental/tracing
# {"enabled":false}
```

### Selecting a proxy node

```bash
# List available proxies in a group
curl -s $API/proxies | python3 -c "
import json,sys
d=json.load(sys.stdin)
for k in d['proxies']['🚀 节点选择']['all']:
    print(k)
"

# Switch to a specific node
curl -s -X PUT $API/proxies/🚀%20节点选择 \
  -H "Content-Type: application/json" \
  -d '{"name":"HK-BGP1"}'
```

### Testing proxy connectivity

```bash
# Test HTTP proxy directly
curl -s -x http://127.0.0.1:7890 -o /dev/null -w "%{http_code}" \
  --connect-timeout 5 https://www.google.com
# Expected: 200 (or 302 redirect)

# Test domestic site (should go DIRECT per rules)
curl -s -x http://127.0.0.1:7890 -o /dev/null -w "%{http_code}" \
  --connect-timeout 5 https://www.baidu.com
# Expected: 200
```

### Enabling TUN mode

TUN mode is configured in `config.yaml` at startup — it cannot be toggled at runtime. After starting mihomo with TUN enabled:

```bash
# Check TUN virtual NIC
ip link show utun
# utun: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> ...

# With auto-route:true, ALL system traffic goes through TUN.
# Test connectivity through TUN:
curl -so /dev/null -w "%{http_code}" https://www.baidu.com       # → 200 (DIRECT)
curl -so /dev/null -w "%{http_code}" https://www.google.com      # → 200 (via proxy)
curl -so /dev/null -w "%{http_code}" https://github.com          # → 200 (via proxy)
```

### Disabling TUN mode temporarily

If you need mihomo as a regular proxy without TUN, remove the `tun:` and `experimental:` sections from the config and restart:

```bash
python3 -c "
with open('/tmp/mihomo-test/config.yaml') as f:
    lines = f.readlines()
skip = False
result = []
for line in lines:
    if line.startswith('tun:') or line.startswith('experimental:'):
        skip = True; continue
    if skip and line[0] not in (' ', '\t'):
        skip = False
    if not skip:
        result.append(line)
with open('/tmp/mihomo-test/config.yaml', 'w') as f:
    f.writelines(result)
"

# Restart mihomo without TUN
pkill mihomo-linux-amd64
mihomo-linux-amd64 -d /tmp/mihomo-test &
```

### Stopping mihomo

```bash
# Graceful shutdown
pkill mihomo-linux-amd64

# Wait for TUN device cleanup
sleep 2
ip link show utun   # should show "Device not found"
```

### Tracing API (TrafficTracer-specific)

```bash
API="http://127.0.0.1:9099"

# Enable tracing (writes JSONL events to file)
curl -s -X PATCH $API/experimental/tracing \
  -H "Content-Type: application/json" \
  -d '{"enabled":true,"output":"/tmp/trace.jsonl"}'

# ... run your traffic ...

# Disable tracing (finalizes the file)
curl -s -X PATCH $API/experimental/tracing \
  -H "Content-Type: application/json" \
  -d '{"enabled":false}'

# Read trace
head -3 /tmp/trace.jsonl
# {"ts":"...","type":"tcp_connect","conn_id":"...","src":"198.18.0.1:48126","dst":"180.163.151.33:443"}
# {"ts":"...","type":"tcp_proxy_dial","conn_id":"...","out_src":"192.168.5.101:51496","proxy_addr":"..."}
# {"ts":"...","type":"tcp_close","conn_id":"...","bytes_up":...,"bytes_down":...,"duration_ms":...}
```

Each TCP connection produces three events: `tcp_connect` (client side), `tcp_proxy_dial` (proxy side), `tcp_close` (summary). These are cross-referenced with Chrome NetLog 5-tuples to produce the correlation table.

### Handling TUN auto-route

When `auto-route: true`, mihomo redirects **all** system traffic through the TUN interface. This means:

- Your terminal/SSH sessions' new connections go through TUN
- If mihomo is healthy (proxy chains working), everything works transparently
- If you kill mihomo, TUN routing is removed and traffic falls back to the default gateway

**If your session loses connectivity during TUN activation**, run capture commands as a background script:

```bash
# Write capture commands to a script
cat > /tmp/capture.sh << 'EOF'
# ... capture steps ...
EOF

# Run in background (survives TUN routing changes)
nohup bash /tmp/capture.sh &>/tmp/capture.log &
```

**If you cannot tolerate TUN routing at all**, skip TUN and use explicit proxy mode:
- Remove `tun:` and `experimental:` sections from config (see above)
- Set `tun_interface: lo` in sites.yaml (capture loopback instead of TUN)
- Chrome will use system proxy or `--proxy-server` to connect to `127.0.0.1:7890`

## End-to-End Operation Guide

This section documents a complete capture-and-correlation test session, including environment setup, proxy handling, and all commands executed.

### Environment

| Item | Value |
|------|-------|
| Physical NIC | `eno1` (10.201.22.219), also `wlp2s0` (192.168.5.101) |
| Mihomo binary | `../mihomo/bin/mihomo-linux-amd64` (gvisor TUN, cap_net_admin=eip) |
| Mihomo proxy config | `~/data/tools/mihomo-config.yaml` (9368 lines, VLESS/Hysteria2 proxies) |
| Output base | `/data/datasets/ttTest-0705` |
| Target | `www.bilibili.com`, 15s wait, traffic_type=video-mainpage |

### Step 1: Prepare Mihomo TUN config

Create a mihomo config directory with TUN mode, tracing, geodata files, and proxy rules.

```bash
# Create config directory
mkdir -p /tmp/mihomo-test

# Copy your full proxy config (proxies, proxy-groups, rules) as the base
cp ~/data/tools/mihomo-config.yaml /tmp/mihomo-test/config.yaml

# Copy geodata files from an existing mihomo installation
cp /home/ytluo/.local/share/io.github.clash-verge-rev.clash-verge-rev/{geosite.dat,geoip.dat,Country.mmdb} /tmp/mihomo-test/
cp /etc/mihomo/geoip.metadb /tmp/mihomo-test/

# Append TUN and tracing sections to the config
cat >> /tmp/mihomo-test/config.yaml << 'EOF'
tun:
  enable: true
  stack: gvisor
  device: utun
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53

experimental:
  tracing: true
EOF
```

> **TUN requires `CAP_NET_ADMIN`.** Grant the capability:
> ```bash
> sudo setcap cap_net_admin+eip /path/to/mihomo-linux-amd64
> # or with pkexec if sudo needs password:
> pkexec setcap cap_net_admin+eip /path/to/mihomo-linux-amd64
> ```

> **Use `-d` (directory mode), not `-f` (single file).** When the config references geodata files, mihomo must run in directory mode so it can find `geoip.dat`, `geosite.dat`, `geoip.metadb` alongside `config.yaml`. The capture pipeline's `mihomo.py` has been updated accordingly.

Validate the config:

```bash
mihomo-linux-amd64 -t -d /tmp/mihomo-test
# Expected: configuration file /tmp/mihomo-test/config.yaml test is successful
```

### Step 2: Install Chrome (without sudo)

If `dpkg -i` is unavailable, extract Chrome from the `.deb`:

```bash
wget --no-proxy -O /tmp/google-chrome.deb \
  https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb

mkdir -p /tmp/chrome-extract
dpkg-deb -x /tmp/google-chrome.deb /tmp/chrome-extract

# Chrome needs --no-sandbox when run without suid installation
cat > /tmp/chrome-wrapper.sh << 'EOF'
#!/bin/bash
exec /tmp/chrome-extract/opt/google/chrome/chrome --no-sandbox "$@"
EOF
chmod +x /tmp/chrome-wrapper.sh

# Verify
/tmp/chrome-wrapper.sh --version
# Google Chrome 150.0.7871.46
```

### Step 3: Write sites.yaml

```yaml
global:
  mihomo:
    binary: /data/ytluo/projects/mihomo/bin/mihomo-linux-amd64
    config: /tmp/mihomo-test/config.yaml
    api: "http://127.0.0.1:9099"
  chrome:
    binary: /tmp/chrome-wrapper.sh
    user_data_dir: /tmp/chrome-profile-tt
    headless: true
  network:
    tun_interface: utun
    phys_interface: eno1
  output:
    base_dir: /data/datasets/ttTest-0705

sites:
  - domain: bilibili.com
    url: "https://www.bilibili.com"
    wait: 15
    traffic_type: video-mainpage
```

### Step 4: Handle proxy environment

The running opencode/terminal session may have `http_proxy=http://127.0.0.1:7897` inherited from `~/.bashrc`. When TUN mode activates, mihomo takes over routing — the old proxy address becomes dead.

**Option A: Remove proxy from bashrc (recommended)**

```bash
# In ~/.bashrc, comment out:
#export http_proxy=http://127.0.0.1:7897
#export https_proxy=http://127.0.0.1:7897
#export all_proxy=socks5://127.0.0.1:7897

# Restart terminal session, verify direct connectivity:
curl -s https://api.deepseek.com/v1/models
# Expected: HTTP 401 (reachable without proxy)
```

**Option B: Port forwarding (if proxy cannot be removed)**

```bash
# Start mihomo on port 7890 first, then forward legacy 7897 → 7890
python3 -c "
import socket, select
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 7897))
srv.listen(32)
while True:
    c, _ = srv.accept()
    r = socket.create_connection(('127.0.0.1', 7890))
    # ... bidirectional forward
" &
```

### Step 5: Verify TUN mode connectivity

Before running the full capture, confirm TUN mode routes traffic correctly:

```bash
# Start mihomo in background
mihomo-linux-amd64 -d /tmp/mihomo-test &>/tmp/mihomo.log &
sleep 3

# Check API and TUN device
curl -s http://127.0.0.1:9099/version
ip link show utun

# Connectivity test through TUN
curl -so /dev/null -w "%{http_code}" --connect-timeout 8 https://www.baidu.com     # → 200 (DIRECT)
curl -so /dev/null -w "%{http_code}" --connect-timeout 8 https://www.bilibili.com  # → 200 (DIRECT)
curl -so /dev/null -w "%{http_code}" --connect-timeout 8 https://www.google.com    # → 200 (via proxy)
curl -so /dev/null -w "%{http_code}" --connect-timeout 8 https://github.com        # → 200 (via proxy)
```

All targets should respond. If any fail, check mihomo logs at `/tmp/mihomo.log`.

### Step 6: Run capture

Because TUN auto-route redirects all system traffic, in-line bash commands may time out. Use a **background capture script**:

```bash
cat > /tmp/capture_run.sh << 'SCRIPT'
#!/bin/bash
SESSION_DIR="/data/datasets/ttTest-0705/$(date +%Y-%m-%d_%H-%M-%S)"
mkdir -p "$SESSION_DIR/captures/bilibili.com" "$SESSION_DIR/logs"

# Enable mihomo tracing via API
curl -s -X PATCH http://127.0.0.1:9099/experimental/tracing \
  -H "Content-Type: application/json" \
  -d "{\"enabled\":true,\"output\":\"$SESSION_DIR/logs/mihomo_trace_bilibili.com.jsonl\"}"

# Start tshark on both interfaces
tshark -i utun -w "$SESSION_DIR/captures/bilibili.com/tun.pcap" &>/dev/null &
TUN_PID=$!
tshark -i eno1 -w "$SESSION_DIR/captures/bilibili.com/phys.pcap" &>/dev/null &
PHYS_PID=$!
sleep 1

# Launch Chrome with NetLog
/tmp/chrome-wrapper.sh --headless=new --no-first-run --no-default-browser-check \
  --user-data-dir=/tmp/chrome-profile-tt \
  --log-net-log="$SESSION_DIR/logs/netlog_bilibili.com.json" \
  "https://www.bilibili.com" &>/tmp/chrome.log &
CHROME_PID=$!

# Wait for page load + traffic
sleep 15

# Graceful shutdown
kill $CHROME_PID 2>/dev/null && sleep 2
kill -SIGTERM $TUN_PID $PHYS_PID 2>/dev/null && sleep 3

# Disable tracing
curl -s -X PATCH http://127.0.0.1:9099/experimental/tracing \
  -H "Content-Type: application/json" -d '{"enabled":false}'

echo "DONE: $SESSION_DIR"
SCRIPT

# Run in background to survive TUN routing activation
nohup bash /tmp/capture_run.sh &>/tmp/capture_output.log &
```

After ~25 seconds, check results:

```bash
cat /tmp/capture_output.log
# DONE: /data/datasets/ttTest-0705/2026-07-05_21-45-51
```

### Step 7: Fix truncated NetLog (if needed)

When Chrome is killed with SIGTERM, `--log-net-log` may produce truncated JSON. Fix it:

```bash
python3 -c "
path = 'SESSION_DIR/logs/netlog_bilibili.com.json'
with open(path) as f:
    data = f.read()
fixed = data.rstrip().rstrip(',') + '\n]}\n'
with open(path, 'w') as f:
    f.write(fixed)
"
```

### Step 8: Run analysis

```bash
cd /data/ytluo/projects/TrafficTracer
python3 analyze.py --session SESSION_DIR
```

### Step 9: Verify output

```bash
SESSION=SESSION_DIR

# Check file structure
find $SESSION -type f | sort

# View correlation summary
python3 -c "
import json
with open('$SESSION/results/correlation.json') as f:
    data = json.load(f)
for domain, flows in data.items():
    print(f'{domain}: {len(flows)} flows')
    for f in flows[:2]:
        pre = f['pre_proxy']
        post = f['post_proxy']
        print(f'  [{f[\"relation\"]}] {f[\"name\"]}')
        print(f'    pre:  {pre[\"src\"]} -> {pre[\"dst\"]}')
        print(f'    post: {post[\"src\"]} -> {post[\"dst\"]}')
"
```

Expected output:

```
bilibili.com: 17 flows correlated across 6 subdomains:
  - https://www.bilibili.com       (main page)
  - https://api.bilibili.com       (API server)
  - https://data.bilibili.com      (analytics)
  - https://i0.hdslb.com           (static CDN)
  - https://s1.hdslb.com           (static CDN)
  - https://impression.biligame.com (ad/tracking)
```

### Step 10: Restore system state

```bash
# Kill TUN mihomo
pkill -f "mihomo-linux-amd64"

# Restore regular proxy (if applicable)
/usr/bin/verge-mihomo -d ~/.local/share/io.github.clash-verge-rev.clash-verge-rev \
  -f ~/.local/share/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml \
  -ext-ctl-unix /tmp/verge/verge-mihomo.sock &>/dev/null &

# Optional: re-enable proxy in ~/.bashrc
```

### Key Files Produced

```
SESSION_DIR/
├── captures/
│   └── bilibili.com/
│       ├── tun.pcap              # raw TUN interface (pre-proxy traffic)
│       ├── phys.pcap             # raw physical interface (post-proxy traffic)
│       └── flows/
│           └── bilibili.com/
│               ├── www.bilibili.com/
│               │   ├── pre_proxy.pcap
│               │   └── post_proxy.pcap
│               ├── api.bilibili.com/
│               │   ├── pre_proxy.pcap
│               │   └── post_proxy.pcap
│               └── ...
├── logs/
│   ├── mihomo_trace_bilibili.com.jsonl   # Mihomo connection trace (JSONL)
│   └── netlog_bilibili.com.json          # Chrome NetLog (JSON)
└── results/
    └── correlation.json                  # full correlation table
```

## Data Pipeline

After a CDP-enabled capture, one visit sample contains:

```
CDP:
  Page request semantics, URL, resourceType, requestId, frameId, timestamp

NetLog:
  Chrome network stack events, DNS, socket, TLS, QUIC, cache, proxy

Mihomo trace:
  pre-proxy / post-proxy connection mapping

pcap:
  TUN and physical NIC real packet sequences
```

Correlation target:

```
CDP request
  → NetLog URL_REQUEST / socket / QUIC session
  → Mihomo pre/post proxy mapping
  → pcap flow
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
| `chrome.enable_cdp` | Enable CDP request-level collection (default: `true`) |
| `chrome.remote_debugging_port` | Chrome DevTools debugging port (default: `9222`) |
| `chrome.netlog_capture_mode` | NetLog capture mode for `--net-log-capture-mode` (default: `Default`) |
| `chrome.graceful_close_timeout` | Seconds to wait for Chrome graceful exit (default: `20`) |
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
| `wait_load_timeout` | Max seconds to wait for Page.loadEventFired in CDP mode (default: `30`) |

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

**Chrome needs `--no-sandbox` (extracted from .deb without suid)**
Use a wrapper script: `exec /path/to/chrome --no-sandbox "$@"`. This is safe for headless testing on trusted machines.

**tshark "Permission denied"**
Run `sudo setcap cap_net_raw,cap_net_admin=eip $(which tshark)` or use `sudo`.

**Mihomo API unreachable**
Verify the `external-controller` address in your Mihomo config matches `api` in `sites.yaml`. Also ensure the mihomo process had enough time to start (at least 2-3 seconds for configs with many proxy groups).

**Mihomo TUN creation fails: "operation not permitted"**
The mihomo binary needs `CAP_NET_ADMIN`: `sudo setcap cap_net_admin+eip /path/to/mihomo-linux-amd64`.

**Mihomo hangs on startup with `-f` flag**
When the config references geodata files (GeoIP, GeoSite), use `-d <config_dir>` instead of `-f <config_file>`. The `-d` flag tells mihomo to look for `geoip.dat`, `geosite.dat`, `geoip.metadb` in the same directory as `config.yaml`. The capture pipeline's `mihomo.py` automatically derives the directory from the config path.

**Bash commands time out when TUN mode activates**
`auto-route: true` redirects all system traffic through the TUN interface. In-line bash calls may lose connectivity during the transition. Run capture as a background script (`nohup bash script.sh &`) and check the log file afterwards.

**Chrome NetLog JSON is truncated**
When Chrome is killed with SIGTERM, `--log-net-log` may produce incomplete JSON (missing closing `]}`). Fix by appending: `fixed = data.rstrip().rstrip(',') + '\n]}\n'`.

**Mihomo can't download geodata files on startup**
Without proxy, mihomo cannot reach GitHub to download `geoip.metadb` or `geosite.dat`. Copy these files from an existing mihomo installation into the config directory before starting.

**Analysis produces empty correlation**
Check that the Mihomo trace file contains `tcp_connect` events with `src`/`dst` matching the NetLog 5-tuples. The capture must use TUN mode with `tracing: true`. Also verify that the NetLog JSON is well-formed (not truncated).

**OpenCode API calls fail after killing old proxy**
If opencode inherits `http_proxy=http://127.0.0.1:7897` from the shell, and that proxy is stopped, API calls will fail. Either remove the proxy env vars from `~/.bashrc` (if the API is directly reachable), or use port forwarding to bridge the old proxy port to the new one.

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
