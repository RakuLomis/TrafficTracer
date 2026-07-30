# TrafficTracer

Capture and correlate browser-attributed network traffic before and after a Mihomo proxy. Orchestrates Chrome NetLog capture, dual-interface packet sniffing, and Mihomo connection tracing to produce per-flow correlation tables and filtered pcap files.

TrafficTracer now supports CDP-based request-level logging.

CDP is used to collect browser-side request semantics:
tab/page request, URL, resource type, frameId, requestId, response status and timestamps.

NetLog is still used for Chrome network-stack information:
URL_REQUEST, DNS, socket, TLS, QUIC, cache and proxy events.

pcap is still used for real packet-level traffic.

## TrafficTracer 三仓联动 QuickStart

这套流程对应以下分支，并以三个仓库位于同一父目录为例：

| 组件 | 分支 | 职责 |
|---|---|---|
| `mihomo` | `TrafficTracer` | 生成规范化的 `pre_flow` / `post_flow` JSONL 事件 |
| `clash-verge-rev` | `feat/traffic-tracer` | 导入配置、选择核心、测速/选节点、系统代理、TUN 和追踪 UI |
| `TrafficTracer` | `alpha` | 采集 Chrome/CDP/NetLog/pcap，关联代理前后五元组并查询结果 |

目前已验证的平台是 Linux x86-64。代码接口已经对齐，但运行时必须在 Clash Verge 中选择 `verge-mihomo-tt`；标准 `verge-mihomo` 不包含 `/experimental/tracing`，会返回 `404`。

### 1. 检出对应分支

```bash
export TT_WORKSPACE=/path/to/projects

git -C "$TT_WORKSPACE/mihomo" switch TrafficTracer
git -C "$TT_WORKSPACE/clash-verge-rev" switch feat/traffic-tracer
git -C "$TT_WORKSPACE/TrafficTracer" switch alpha
```

### 2. 构建 mihomo-traffictracer

```bash
cd "$TT_WORKSPACE/mihomo"
go mod download
make linux-amd64-compatible

./bin/mihomo-linux-amd64-compatible -v
```

这里生成的核心是 `bin/mihomo-linux-amd64-compatible`。如果仓库中已有确认过版本的 `bin/mihomo-traffictracer-v2`，也可以直接使用它。

### 3. 准备并启动 Clash Verge

先关闭系统中已安装的其他 Clash Verge 实例，避免两个实例争用服务进程和 `/tmp/verge/verge-mihomo.sock`。

```bash
cd "$TT_WORKSPACE/clash-verge-rev"
corepack enable
pnpm install

MIHOMO_TRAFFIC_TRACER_BIN="$TT_WORKSPACE/mihomo/bin/mihomo-linux-amd64-compatible" \
  pnpm prebuild --force

test -x src-tauri/sidecar/verge-mihomo-tt-x86_64-unknown-linux-gnu
pnpm dev
```

在 UI 中依次完成：

1. 打开“订阅/Profiles”，导入可用的 Mihomo YAML 配置。
2. 打开“设置 → Clash 设置 → Clash Core”，选择 `verge-mihomo-tt`，等待核心重启。
3. 打开“代理/Proxies”，运行节点延迟测试并选择目标节点或策略组。
4. 按需开启“系统代理”。需要捕获透明代理流量时，安装 Clash Verge 服务并开启 TUN。
5. 开启 TUN 前用 `ip route show default` 记录物理出口网卡；开启后用 `ip -brief link` 记录新出现的 TUN 网卡名。

验证当前运行的是 TrafficTracer 核心：

```bash
curl --unix-socket /tmp/verge/verge-mihomo.sock \
  http://localhost/experimental/tracing
```

成功时返回至少包含 `enabled` 的 JSON。返回 `404` 表示仍选择了标准核心，需要重新选择 `verge-mihomo-tt` 并重启。

### 4. 验证 UI 追踪开关

```bash
mkdir -p /tmp/mihomo-traffictracer
```

进入“设置 → Clash 设置”：

1. 开启“TrafficTracer/流量追踪”。
2. 将输出路径设置为绝对路径 `/tmp/mihomo-traffictracer/manual.jsonl`。
3. 访问一个网页，然后检查日志：

```bash
tail -n 20 /tmp/mihomo-traffictracer/manual.jsonl
```

父目录必须预先存在且对核心可写。空输出路径表示写到核心标准输出。完成手工验证后可以关闭 UI 追踪；TrafficTracer 采集程序会按访问任务临时开启追踪，并在结束或异常时恢复原状态和原输出路径。

### 5. 配置 TrafficTracer 采集器

```bash
cd "$TT_WORKSPACE/TrafficTracer"
python -m venv .venv
. .venv/bin/activate
pip install pyyaml websockets pytest

sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v dumpcap)"
```

找到 Clash Verge 生成的核心配置。开发版通常位于：

```text
~/.local/share/io.github.clash-verge-rev.clash-verge-rev.dev/clash-verge.yaml
```

安装版通常位于：

```text
~/.local/share/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml
```

也可以从正在运行的核心命令行中查看 `-f` 后面的实际路径：

```bash
ps -eo args | grep '[v]erge-mihomo-tt'
```

复制 `sites.clash-verge.example.yaml` 为 `sites.yaml`，然后填写真实绝对路径和网卡名：

```yaml
global:
  mihomo:
    managed: false
    binary: /absolute/path/to/mihomo/bin/mihomo-linux-amd64-compatible
    config: /absolute/path/to/clash-verge.yaml
    api: "unix:///tmp/verge/verge-mihomo.sock"
    secret: ""  # 空值时从上面的 Clash Verge 生成配置读取

  chrome:
    binary: google-chrome
    user_data_dir: /tmp/traffictracer-chrome
    headless: false
    enable_cdp: true

  network:
    tun_interface: Mihomo  # 替换为 ip -brief link 显示的实际 TUN 名
    phys_interface: wlp2s0 # 替换为开启 TUN 前的默认出口网卡

  output:
    base_dir: /absolute/path/to/traffictracer-output

sites:
  - domain: example.com
    url: https://example.com
    wait: 10
    traffic_type: all
```

联合模式必须使用 `managed: false`，因为核心生命周期由 Clash Verge 管理。`api` 显式指向 Unix Socket；`secret` 留空时 TrafficTracer 从 `config` 指定的生成配置读取。日志路径会在发送给外部核心前转换为绝对路径。

### 6. 采集与分析

保持 Clash Verge、目标代理节点和 TUN 运行：

```bash
cd "$TT_WORKSPACE/TrafficTracer"
. .venv/bin/activate

python capture.py --config sites.yaml --only example.com
```

命令会打印本次 session 目录。随后运行：

```bash
python analyze.py --session /absolute/path/to/traffictracer-output/YYYY-MM-DD_HH-MM-SS
```

主要产物包括：

```text
<session>/logs/mihomo_trace_<domain>_<run>.jsonl
<session>/logs/cdp_<domain>_<run>.json
<session>/logs/netlog_<domain>_<run>.json
<session>/captures/<domain>/<run>/tun.pcap
<session>/captures/<domain>/<run>/phys.pcap
<session>/results/correlation.json
```

`correlation.json` 同时保留兼容字段和规范化字段：`pre_flow`、`post_flow`、`match_status`、`match_confidence`、`conn_id`、`outer_conn_id`。完整规范化五元组使用：

```text
<tcp|udp>|<src_ip>:<src_port>|<dst_ip>:<dst_port>
```

IPv6 端点使用方括号，例如 `tcp|[2001:db8::1]:50000|[2001:db8::2]:443`。

### 7. 用代理前五元组查询代理后五元组

```bash
cd "$TT_WORKSPACE/TrafficTracer"
python query_flow.py \
  /absolute/path/to/mihomo_trace_example.com_all_1.jsonl \
  tcp \
  198.18.0.1 44000 \
  1.1.1.1 443
```

匹配成功时输出一个数组，其中 `pre_flow` 是代理前五元组，`post_flow` 是核心实际建立的代理后五元组。无匹配时输出 `[]` 并返回退出码 `1`。同一代理前五元组如果在不同时间被复用，结果会保留多个会话；`post_flow.shared: true` 表示复用的外层连接，不能解释为逻辑流独占的 NAT 映射。

### 8. 常见故障

- `mihomo returned 404`：当前是标准核心；切换到 `verge-mihomo-tt` 并重启。
- `No core binaries found`：重新执行带 `--force` 的 `pnpm prebuild`，确认目标 sidecar 存在且可执行。
- `IPC path not ready`：关闭重复 UI/残留核心，确认 service install/uninstall helper 与主程序同目录，然后在 UI 中重试安装或修复服务。
- TUN 无法开启：先安装/修复 Clash Verge 服务，并检查系统授权；仅系统代理模式不等同于 TUN 双接口采集。
- trace 文件不存在：使用绝对路径，先创建父目录，并确认核心进程对目录有写权限。
- TrafficTracer 无法连接控制器：确认 `/tmp/verge/verge-mihomo.sock` 存在、Clash Verge 核心正在运行，且 `sites.yaml` 的生成配置路径正确。
- `post_flow` 为空：连接可能尚未拨号成功、被拒绝/取消，或当前协议只能提供共享/不完整的外层端点；结合 `status`、`stage`、`error` 和 `shared` 判断。


## Architecture

TrafficTracer consists of two independent pipelines:

```
┌──────────────┐     ┌──────────────┐
│  Capture     │──▶  │  Analysis    │
│  Pipeline    │     │  Pipeline    │
└──────────────┘     └──────────────┘
```

- **Capture Pipeline** — Optionally manages Mihomo, enables per-visit tracing,
  captures the TUN and physical interfaces, launches an isolated Chrome with
  NetLog, and uses CDP for request-level attribution when enabled.
- **Analysis Pipeline** — Runs offline. It maps CDP requests to NetLog
  transports, correlates those transports with Mihomo pre/post-proxy events,
  and extracts per-flow pcaps. Older sessions without CDP use a domain-based
  fallback.

The two pipelines run independently. Capture first to collect data; analyze later against any session.

## Prerequisites

| Component | Purpose |
|-----------|---------|
| Python 3.10+ | Runtime (PyYAML + websockets) |
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
pip install pyyaml websockets
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
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v dumpcap)"
```

### Build Mihomo (TrafficTracer branch)

```bash
cd ../mihomo
git checkout TrafficTracer
make  # or go build
```

## Quick Start

This example captures one browser visit, correlates the browser requests with
Mihomo connections, and writes per-flow pcap files. The default path uses the
CDP-first analysis pipeline and works with both headless and visible Chrome.

### 1. Prepare capture permissions

```bash
# Allow the TrafficTracer Mihomo build to create and configure a TUN device.
sudo setcap cap_net_admin+eip ../mihomo/bin/mihomo-traffictracer

# Allow tshark to capture without running the whole pipeline as root.
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v dumpcap)"

# Find the physical interface that carries traffic after the proxy.
ip route show default
# default via 192.168.5.1 dev wlp2s0 ...
```

The TUN interface in `sites.yaml` must match the device configured in the
Mihomo config. The Mihomo config must also expose its controller API and enable
the TrafficTracer tracing endpoint. See [Mihomo Configuration](#mihomo-configuration).

### 2. Create `sites.yaml`

```yaml
global:
  mihomo:
    binary: ../mihomo/bin/mihomo-traffictracer
    config: mihomo-configs/config.yaml
    api: "http://127.0.0.1:9090"
    managed: true

  chrome:
    binary: google-chrome
    user_data_dir: chrome-profile
    headless: true
    enable_cdp: true
    remote_debugging_port: 9222
    netlog_capture_mode: Default
    graceful_close_timeout: 20
    disable_background_networking: true

  network:
    tun_interface: utun
    phys_interface: wlp2s0

  output:
    base_dir: ./output

sites:
  - domain: bilibili.com
    url: "https://www.bilibili.com"
    wait: 15
    wait_load_timeout: 30
    traffic_type: video-mainpage
```

Important settings:

- `mihomo.managed: true` starts Mihomo once for the capture session and stops
  the process started by TrafficTracer when the session ends. A compatible
  TrafficTracer Mihomo already listening on the configured API is reused.
- `mihomo.managed: false` uses an externally managed Mihomo process and never
  starts or stops it.
- `chrome.enable_cdp: true` enables request-level attribution. It is independent
  of `chrome.headless`.
- `wait_load_timeout` limits the wait for `Page.loadEventFired`; `wait` is the
  additional collection period after navigation.
- `traffic_type` is currently a run label, not a packet-capture filter.

### 3. Capture a visit

```bash
python capture.py --config sites.yaml --only bilibili.com
```

Omit `--only` to capture every entry in `sites`, sequentially:

```bash
python capture.py --config sites.yaml
```

A successful capture prints the new session directory. Every visit receives a
run tag of `<traffic_type>_<N>`, so repeated visits do not overwrite each other:

```text
output/2026-07-29_12-34-56/
├── captures/
│   └── bilibili.com/
│       └── video-mainpage_1/
│           ├── tun.pcap
│           └── phys.pcap
└── logs/
    ├── cdp_bilibili.com_video-mainpage_1.json
    ├── mihomo_trace_bilibili.com_video-mainpage_1.jsonl
    ├── netlog_bilibili.com_video-mainpage_1.json
    └── proxy_info_bilibili.com_video-mainpage_1.json
```

The capture order is Mihomo tracing, dual-interface tshark, Chrome NetLog/CDP,
then graceful shutdown. If Chrome leaves a truncated NetLog, TrafficTracer
backs it up as `*.truncated.bak` and attempts a conservative repair.

### 4. Analyze the session

Capture and analysis are independent. Analyze the printed session at any time:

```bash
python analyze.py --session output/2026-07-29_12-34-56
```

The analyzer uses CDP attribution when a valid CDP file is available. It then:

1. matches CDP requests to NetLog `URL_REQUEST` entries;
2. traces NetLog dependency chains to TCP sockets or QUIC sessions;
3. matches the pre-proxy connection with Mihomo tracing events;
4. uses CDP remote endpoints and UDP host data as a compensation path;
5. extracts matching packets from the TUN and physical-interface pcaps.

If the CDP file is absent or cannot be parsed, the analyzer falls back to the
legacy domain-based NetLog path.

Analysis adds:

```text
output/2026-07-29_12-34-56/
├── captures/
│   └── bilibili.com/
│       └── video-mainpage_1/
│           └── flows/
│               └── <sanitized-request-url>/
│                   ├── pre_proxy.pcap
│                   └── post_proxy.pcap
└── results/
    └── correlation.json
```

### 5. Inspect correlation results

```bash
python - <<'PY'
import json

path = "output/2026-07-29_12-34-56/results/correlation.json"
with open(path, encoding="utf-8") as f:
    results = json.load(f)

for domain, result in results.items():
    print(
        domain,
        f"requests={result['cdp_request_count']}",
        f"connections={result['netlog_connection_count']}",
        f"flows={len(result['flows'])}",
    )
PY
```

A CDP-first flow has this shape:

```json
{
  "url": "https://cdn.example.net/video.m4s",
  "resource_type": "Media",
  "target_type": "page",
  "relation": "cross_site",
  "pre_proxy_src": "198.18.0.1:49812",
  "pre_proxy_dst": "1.2.3.4:443",
  "post_proxy_src": "192.168.5.101:53652",
  "post_proxy_dst": "proxy.example.net:443",
  "protocol": "HTTP2",
  "request_ids": ["921.18", "921.19"],
  "connection_reused": true
}
```

`relation` is metadata only. `same_site` means the request host contains the
configured domain; `cross_site` covers third-party APIs, CDNs, media, and other
subresources attributed to the visit by CDP.

### 6. Optional external Mihomo control

For debugging or `mihomo.managed: false`, use the helper scripts:

```bash
bash scripts/start-mihomo.sh
bash scripts/stop-mihomo.sh
```

The stop helper restores saved routes before terminating Mihomo. The detailed
manual procedure is documented below.

## Mihomo Proxy Operations

With `mihomo.managed: true`, the capture pipeline starts and stops the Mihomo process it owns. This section explains manual management for debugging and external mode.

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
mixed-port: 7890                 # HTTP(S) + SOCKS5 proxy (local mixed proxy port)
external-controller: 127.0.0.1:9090  # REST API (tracing control)

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
API="http://127.0.0.1:9090"

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
API="http://127.0.0.1:9090"

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


## Data Pipeline

TrafficTracer deliberately separates collection from offline analysis:

```text
capture.py                                      analyze.py
    │                                               │
    ├─ Mihomo tracing ───── JSONL ──────────────────┤
    ├─ Chrome CDP ───────── request JSON ───────────┤
    ├─ Chrome NetLog ────── network-stack JSON ─────┤
    └─ tshark ───────────── TUN + physical pcap ────┘
                                                    │
                                                    ├─ correlation.json
                                                    └─ per-flow pcaps
```

### Capture pipeline

`capture.py` loads the YAML configuration, creates one timestamped session,
and visits the selected site entries sequentially. For each visit it creates a
unique `<traffic_type>_<N>` run directory and performs the following sequence.

1. **Prepare Mihomo.** Managed mode starts the configured TrafficTracer build;
   external mode checks the configured API but leaves process ownership to the
   user. The API address is taken from Mihomo's `external-controller` setting
   when it can be read from the configured YAML.
2. **Enable per-run tracing.** The tracer writes TCP and UDP lifecycle events to
   `mihomo_trace_<domain>_<run_tag>.jsonl`. Current proxy-node metadata is saved
   beside it.
3. **Start packet capture.** Two tshark processes run concurrently. `tun.pcap`
   records traffic entering Mihomo; `phys.pcap` records traffic leaving through
   the physical interface.
4. **Launch an isolated Chrome profile.** Chrome always writes NetLog. With CDP
   enabled it first opens `about:blank`, while TrafficTracer attaches at the
   browser target level.
5. **Attach and navigate through CDP.** `Target.setAutoAttach` covers existing
   and later page, iframe, and worker targets. Network events are enabled for
   each attached session. TrafficTracer creates a new page, waits for its exact
   session, navigates it, waits for `Page.loadEventFired` up to
   `wait_load_timeout`, and then collects for `wait` more seconds.
6. **Persist and shut down.** Structured CDP data is written before Chrome is
   closed through `Browser.close`. TrafficTracer repairs a truncated NetLog
   when possible, stops both tshark processes, disables tracing, and finally
   stops only the Mihomo process it started.

When CDP is disabled, Chrome opens the URL directly, sleeps for `wait` seconds,
and produces NetLog and pcaps without a CDP artifact.

The cleanup path runs after normal completion, errors, and `SIGINT`, so active
Chrome, tshark, tracing, and managed Mihomo resources are released as far as the
current process can reach them.

### Artifacts and responsibilities

| Artifact | What it contributes |
|----------|---------------------|
| CDP JSON | Visit attribution, URL, request ID, resource and target type, response endpoint, connection reuse |
| Chrome NetLog | `URL_REQUEST` entries, dependency graph, socket/QUIC transport and five-tuples |
| Mihomo trace JSONL | Proxy-side TCP/UDP connection identity and pre/post-proxy mapping |
| `tun.pcap` | Real packets before proxy processing |
| `phys.pcap` | Real packets after proxy processing |
| Proxy info JSON | Selected proxy groups, nodes, types, servers, and ports at capture time |

The on-disk layout is keyed by domain and run tag:

```text
SESSION_DIR/
├── captures/
│   └── <domain>/
│       └── <traffic_type>_<N>/
│           ├── tun.pcap
│           ├── phys.pcap
│           └── flows/
│               └── <sanitized-request-url>/
│                   ├── pre_proxy.pcap
│                   └── post_proxy.pcap
├── logs/
│   ├── cdp_<domain>_<run_tag>.json
│   ├── mihomo_trace_<domain>_<run_tag>.jsonl
│   ├── netlog_<domain>_<run_tag>.json
│   └── proxy_info_<domain>_<run_tag>.json
└── results/
    └── correlation.json
```

### CDP-first analysis path

For every domain/run directory, `analyze.py` requires the matching NetLog. A
missing NetLog causes that run to be skipped. When a readable CDP file exists,
the current analysis path is:

```text
CDP attributed request
    │
    ├─ normalize URL to scheme + host + path
    │  (query and fragment are ignored for matching)
    ▼
NetLog URL_REQUEST
    │
    ├─ traverse dependency graph
    ▼
TCP socket / QUIC transport connection
    │
    ├─ exact src+dst match, then src-only TCP match
    ▼
Mihomo tcp_connect / tcp_proxy_dial
    │
    ├─ derive pre-proxy and post-proxy endpoints
    ▼
correlated flow
    │
    ├─ tshark display filters
    ▼
pre_proxy.pcap + post_proxy.pcap
```

Several browser requests may map to one transport connection, which preserves
HTTP/2 multiplexing as multiple `request_ids` on one flow. A transport
connection is emitted only when it matches a Mihomo connection.

After NetLog correlation, TrafficTracer attempts two compensation paths for
uncovered CDP requests:

- **CDP endpoint to TCP:** match `remote_ip:remote_port` from the CDP response
  against Mihomo's TCP destination.
- **CDP host to UDP:** match the request host against Mihomo `udp_connect`
  events, primarily for QUIC traffic.

`same_site` and `cross_site` are computed after attribution and are never used
to decide whether a request belongs to the visit.

### Legacy fallback path

The legacy path is used when the per-run CDP file is absent or cannot be read or
parsed:

```text
configured domain
    → domain-related NetLog entries
    → NetLog five-tuples
    → Mihomo TCP connections
    → correlation.json and per-flow pcaps
```

This preserves compatibility with older sessions and captures made with
`chrome.enable_cdp: false`, but it may miss requests to unrelated CDN or API
hostnames. A valid but empty CDP file remains on the CDP-first path; it does not
trigger domain fallback. If transport tracing fails, the analyzer repairs the
NetLog when possible and then continues with the CDP direct compensation paths.

### Analysis output semantics

`results/correlation.json` is keyed by configured domain. Each CDP-first domain
result contains:

- `visit_url`: URL recorded for the visit;
- `flows`: correlated request/connection records;
- `cdp_request_count`: parsed attributed requests;
- `netlog_connection_count`: CDP-matched NetLog transport connections.

For repeated runs of one domain, flow arrays are appended to the same domain
entry. Per-run flow pcaps remain under their own run directories. Requests or
transport connections without a Mihomo match are not emitted as correlated
flows.

## Configuration Reference

### `global`

| Key | Description |
|-----|-------------|
| `mihomo.binary` | Path to Mihomo executable (TrafficTracer branch) |
| `mihomo.config` | Path to Mihomo YAML config (TUN mode, `tracing: true`) |
| `mihomo.api` | Mihomo REST API address (default `http://127.0.0.1:9090`) |
| `mihomo.managed` | Start/stop Mihomo as part of capture (`true` by default); set `false` for an external process |
| `chrome.binary` | Chrome executable name or path |
| `chrome.user_data_dir` | Dedicated profile directory (avoids polluting daily profile) |
| `chrome.headless` | Run Chrome in headless mode (`true` for servers) |
| `chrome.enable_cdp` | Enable CDP request-level collection (default: `true`) |
| `chrome.remote_debugging_port` | Chrome DevTools debugging port (default: `9222`) |
| `chrome.netlog_capture_mode` | NetLog capture mode for `--net-log-capture-mode` (default: `Default`) |
| `chrome.graceful_close_timeout` | Seconds to wait for Chrome graceful exit (default: `20`) |
| `chrome.disable_background_networking` | Add Chrome flags that reduce background update and sync traffic (default: `false`) |
| `network.tun_interface` | TUN virtual NIC name (e.g. `utun`, `tun0`) |
| `network.phys_interface` | Physical NIC name (e.g. `eth0`, `enp0s3`) |
| `output.base_dir` | Root directory for capture sessions |

### `sites`

| Key | Description |
|-----|-------------|
| `domain` | Target domain name (used for file naming and NetLog analysis) |
| `url` | Full URL to visit |
| `wait` | Seconds to wait after page load before stopping capture (default: 10) |
| `traffic_type` | Run label used in `<traffic_type>_<N>` directory and log names; it does not filter packets |
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

```text
TrafficTracer/
├── capture.py                         # Capture pipeline CLI
├── analyze.py                         # Analysis pipeline CLI
├── netlog_parser.py                   # Standalone NetLog parser CLI
├── sites.example.yaml                 # Capture configuration template
├── traffictracer/
│   ├── config.py                      # YAML loading and validation
│   ├── models.py                      # Shared CDP/transport/flow data models
│   ├── utils.py                       # Logging and filesystem helpers
│   ├── capture/
│   │   ├── pipeline.py                # Per-session and per-visit orchestration
│   │   ├── mihomo.py                  # Mihomo ownership and tracing API
│   │   ├── tshark.py                  # Dual-interface tshark lifecycle
│   │   ├── chrome.py                  # Isolated Chrome and NetLog launch
│   │   ├── cdp.py                     # Auto-attached structured CDP collector
│   │   └── netlog_fix.py              # NetLog validation and repair
│   └── analyze/
│       ├── pipeline.py                # CDP-first analysis and fallback
│       ├── cdp_attribution.py         # CDP JSON to attributed requests
│       ├── netlog_transport.py        # URL_REQUEST to socket/QUIC tracing
│       ├── netlog.py                  # Legacy domain five-tuple extraction
│       ├── mihomo_log.py              # TCP/UDP tracing log parser
│       ├── correlator.py              # Transport and Mihomo correlation
│       └── pcap_splitter.py           # Per-flow pcap extraction
├── parser/                            # Standalone Chromium NetLog library
└── test/                              # Unit and integration tests
```

## Running Tests

Run the complete suite:

```bash
pytest -q test/
```

The test files also support direct execution when a focused standalone check is
useful, for example:

```bash
python test/test_cdp.py
python test/test_capture_pipeline.py
python test/test_analyze_pipeline.py
```

## Troubleshooting

**Chrome fails to start with "user data directory is already in use"**
Kill any lingering Chrome processes and try again, or use a different `user_data_dir`.

**Chrome needs `--no-sandbox` (extracted from .deb without suid)**
Use a wrapper script: `exec /path/to/chrome --no-sandbox "$@"`. This is safe for headless testing on trusted machines.

**tshark "Permission denied"**
Run `sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v dumpcap)"` or use `sudo`.

**Mihomo API unreachable**
Verify the `external-controller` address in your Mihomo config matches `api` in `sites.yaml`. Also ensure the mihomo process had enough time to start (at least 2-3 seconds for configs with many proxy groups).

**Mihomo TUN creation fails: "operation not permitted"**
The mihomo binary needs `CAP_NET_ADMIN`: `sudo setcap cap_net_admin+eip /path/to/mihomo-linux-amd64`.

**Mihomo hangs on startup with `-f` flag**
When the config references geodata files (GeoIP, GeoSite), use `-d <config_dir>` instead of `-f <config_file>`. The `-d` flag tells mihomo to look for `geoip.dat`, `geosite.dat`, `geoip.metadb` in the same directory as `config.yaml`. The capture pipeline's `mihomo.py` automatically derives the directory from the config path.

**Bash commands time out when TUN mode activates**
`auto-route: true` redirects all system traffic through the TUN interface. In-line bash calls may lose connectivity during the transition. Run capture as a background script (`nohup bash script.sh &`) and check the log file afterwards.

**Chrome NetLog JSON is truncated**
Chrome is now closed through CDP `Browser.close` when CDP is enabled. If NetLog is still truncated, TrafficTracer backs up the original file as `*.truncated.bak` and attempts conservative repair automatically. No manual fix needed.

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
