# TrafficTracer

Capture and correlate browser-attributed network traffic before and after a Mihomo proxy. Orchestrates Chrome NetLog capture, dual-interface packet sniffing, and Mihomo connection tracing to produce per-flow correlation tables and filtered pcap files.

TrafficTracer now supports CDP-based request-level logging.

CDP is used to collect browser-side request semantics:
tab/page request, URL, resource type, frameId, requestId, response status and timestamps.

NetLog is still used for Chrome network-stack information:
URL_REQUEST, DNS, socket, TLS, QUIC, cache and proxy events.

pcap is still used for real packet-level traffic.

## TrafficTracer Complete

`Complete` 分支是推荐的一体化入口，通过固定的 Git submodule 组合：

- `mihomo-traffictracer`：输出规范化 `pre_flow` / `post_flow` 事件；
- TrafficTracer Worker：采集、分析、Session 恢复和 Flow 索引；
- Clash Verge UI：配置导入、核心/节点选择、系统代理、TUN、捕获与查询。

```bash
git clone --branch Complete --recurse-submodules \
  git@github.com:RakuLomis/TrafficTracer.git
cd TrafficTracer
make bootstrap
```

安装版用户在 UI 中依次导入代理 YAML、选择 `verge-mihomo-tt`、测速选节点、安装服务并开启 TUN，然后在“流量追踪”页选择手工目标，或加载预先编写的 `sites.yaml` 并全选/选择子集。多目标严格按 YAML 顺序串行执行捕获、Chrome 清理、分析和 checkpoint；失败或 Worker 中断后可从准确目标继续。每个子目标生成独立 Session，并可用代理前五元组查询全部匹配逻辑流及实际观测到的代理后五元组，无需运行 Python 命令。

新版捕获在资源停稳后向 Mihomo 写入并持久化 `trace_barrier`，分析只使用截止序号以内的事件；截止后的长连接 close 作为 late event 保留和计数，不再令同一 Session 的重复分析结果漂移。REJECT、REJECT-DROP、internal DNS 与 PASS 等显式无 socket 结果单列为 `not_applicable_outcome`，不会被误报为 post-flow 缺失。旧 Session 没有 barrier 时仍可分析，但 UI 标记为 `legacy_unbounded`。

Complete 的推荐目标配置显式填写 `page_type`：

```yaml
global:
  output:
    base_dir: ./traffictracer-sessions  # UI 预览建议值；最终目录仍由 UI 确认
sites:
  - domain: bilibili.com
    url: https://www.bilibili.com/
    page_type: main-page
    traffic_type: all
    wait: 15
  - domain: bilibili.com
    url: https://www.bilibili.com/video/BV1xx
    page_type: video-play1
    traffic_type: all
    wait: 30
```

`page_type` 只能使用小写字母、数字和连字符，并且在同一 YAML 中必须唯一。旧配置没有该字段时仍会规范化：`video-mainpage` 变为 `main-page`，重复的 `video-play` 按顺序变为 `video-play1`、`video-play2`。`traffic_type` 继续只负责兼容的网络/运行标签语义。

一次 UI 启动对应一个 Capture group，用户可见目录固定为：

```text
<session-root>/<YYYYMMDD-HHMMSS-mmm>/
└── bilibili.com/
    ├── main-page__https_www.bilibili.com/
    │   ├── raw/       # NetLog、CDP、Mihomo trace、双侧原始 PCAP
    │   └── analysis/  # correlation、request/connection/pcap index
    └── video-play1__https_www.bilibili.com_video_BV1xx/
        ├── raw/
        └── analysis/
            └── pcap/
                └── 0001__https_cdn.example_video.m4s/
                    ├── mapping.json  # canonical/alternative connections、全部 URLs/request_ids
                    ├── pre.pcap
                    ├── post.pcap
                    └── alternative-01-udp-pre.pcap  # 仅在备选连接确有报文时存在
```

UI 的 `Analysis storage` 默认使用 `Standard`：上述 `analysis/pcap/` 派生目录不会立即生成，但双侧原始 PCAP、完整 URL、request/connection/PCAP 索引及 pre/post 五元组关联全部保留，之后可用 `Full` 重新分析生成派生文件。`Full` 会在分析阶段直接生成每连接 pre/post PCAP，适合立即交付 Wireshark，但空间占用更高。旧任务未携带该选项时继续按 `Full` 执行；切换档位不会自动删除已有文件。

UI 的 `Browser cache policy` 默认使用 `Cold`：每个 Session 使用独立 Chrome profile，CDP 在导航前禁用 HTTP cache 并绕过 Service Worker；Chrome 进程树确认退出后删除该临时 profile。需要专门测量缓存命中行为时才选择 `Warm`，它会按 domain/page type 复用 profile。实际策略写入 `raw/capture-context.json.cache_mode`；旧任务没有该字段时按 `Warm` 读取，避免重解释历史实验。

Standard 的 `PCAP extraction requested=false` 表示“本次未请求派生包验证”，不是“PCAP 不可用”；UI 会显示 `Packet verification not requested (Standard) · raw captures retained`，并可用 `Verify packet evidence (Full)` 对当前 Session 按需生成每连接 pre/post PCAP。

连接 ID 仍是索引中的稳定机器标识，但不再作为用户可见流目录名。恢复失败目标时保留原目录并写入 `__retryN` 页面目录。

同一网络资源的 transport 重试（例如 QUIC 尝试后回落 TCP）使用通用的
“同源 + 同路径”分组，不依赖域名或特定 query 参数名。只有原 transport
PCAP 为空、且恰好存在一个完成 Mihomo 关联并实际捕获到报文的候选时，才将
该候选选为 canonical connection；完整 query、所有 candidate connection ID、
协议和 `empty/not_requested` 状态仍保存在 request/connection index、
`mapping.json` 与 PCAP index 中。

`request-index-v2.json` 保留每个完整 URL/request ID，并使用 PCAP 证据解决
“空 QUIC 尝试后回落 TCP”的 transport race；candidate connection 不会被删除。
对于已经通过 NetLog 确认的连接，后续收到响应且明确复用同一个正数 CDP
`connectionId` 的请求会先按 response endpoint，再按请求与 transport
生命周期消歧。只有 endpoint 唯一、时间区间唯一或最近前序请求证据唯一时才以
`cdp_connection_reuse` 关联；零 ID、无响应或时间证据并列时不会猜测。决策证据
同时写入 request/connection index，CDP 的 request/response/completion 时间和
失败状态也保存在 V2 产物中。
新捕获还记录 CDP 的 disk cache、Service Worker 和 prefetch 标志，在 coverage
中将无需网络 transport 的请求单列为 `non_network`。 如果目标主文档的全部 Document 观测都属于这些非网络来源，分析会输出 `TARGET_DOCUMENT_NON_NETWORK` 并将页面质量标记为 `degraded`，避免把没有实际网络实验的页面误报为通过。`connection-index-v2.json`
提供 `egress.mode/selection_chain` 以及 `sharing` 的三种独立原因：请求复用、
post-flow 共享和外层连接复用；旧 `shared` 布尔字段继续保留用于兼容。

Coverage 同时提供 `page_attributed` 和 `capture_global`：前者只统计当前页面的
浏览器请求、transport connection 与逻辑流，后者保留捕获窗口中所有 Mihomo
核心流用于后台诊断。旧的扁平字段继续输出供旧 UI 读取，但不能把全局核心流
当作页面关联率。连接终止错误还会输出稳定的 `error_class`，用于按域名聚合
IPv4 超时、IPv6 不可达和其他拨号错误。 未绑定到页面 request ID 的 loopback 探测也会根据 connection 端点或终止错误中的 `127.0.0.0/8`、`::1` 在 capture-global 范围标记为 local N/A；代理节点连接超时和 DNS 解析失败分别输出 `PROXY_NODE_TIMEOUT`、`DNS_RESOLUTION`。
无 Mihomo connection ID、无终止事件且无 post flow 的空 QUIC/UDP 候选只保留在
`transport_connections` 层，不进入 `page_attributed.logical_flows` 分母；它仍保留
完整候选和 PCAP empty 状态，因此不会通过压缩统计丢失连接证据。
分析产物以同一代的 `request-index-v2.json`、`connection-index-v2.json` 和
`pcap-index-v1.json` 为权威事实源。`correlation.json` 仅由 V2 索引生成兼容投影，
不会再把 disk cache、Service Worker、prefetch cache 或浏览器内部响应写成
`host_fallback` flow。`flow-index.json` 继续保留捕获窗口内全部 Mihomo 核心流，
并通过 `mihomo_connection_id` 确定性回填页面相关的 `request_ids`、
`connection_ids`、`primary_url` 与完整 `urls`；没有页面归属的后台流保持空关联。
`summary.json.consistency` 在 Session 完成前校验 request → connection → core flow
→ PCAP 以及 legacy 投影的跨索引引用和 generation，一旦冲突就以
`ANALYSIS_CONSISTENCY_FAILED` 结束分析，而不会把该代产物登记为成功结果。

`connection-index-v2.json.protocol` 只表示真实传输层 `tcp/udp`；
`application_protocol` 使用 `h2/h3/unknown`，失败但保留证据的 QUIC 尝试写入
`attempted_protocols`。因此 TCP 回退不会再因为曾尝试 QUIC 或 CDP
`connectionReused` 而被标成 QUIC。HTTP(S) URL 依赖图中的 53 端口 resolver
socket 只作为 DNS 证据，不会生成业务 transport connection；无法找到真实 socket
的请求会保守地留在 request index 中并标为 unmatched。

HTTP/3 使用 QUIC session 的 `self_address/peer_address` 或其下游 UDP socket 恢复
代理前五元组，随后与 Mihomo UDP trace 一同进入和 TCP 相同的候选排名器。完整
五元组是主要证据；Chrome 单调时钟与 Mihomo UTC 无法精确对齐时，唯一完整候选
仍可关联，多个同分候选继续保持 ambiguous。对于 HTTP/2，已经确认的业务 TCP
socket 是权威端点；复用 dependency graph 下游出现的 UDP/DoH socket 不得覆盖该
端点，也不能把 `2001:4860:4860::8888:443` 等解析通道误写成页面业务连接。

`summary.json.quality_state` 只评价当前页面，值为
`passed/degraded/failed`；`capture_global_quality_state` 单独评价捕获窗口内全部
Mihomo 流。`quality.page_attributed` 与 `quality.capture_global` 提供显式分层，
原有扁平 `quality` 页面计数继续保留用于旧消费者。每条 warning 带
`scope`、`severity` 和 `affects_page_quality`；没有 URL/request ID/页面 transport
归属的后台流即使缺少 post-flow，也只降低 capture-global 状态，不能污染页面质量。
Job 可以正常 `completed`，但页面或全局捕获质量仍可能是 `degraded`，UI 和自动化
消费者不得将这些状态混为一谈。

`network_observation=local_endpoint` 表示请求已经关联到回环目标；判定同时使用 CDP
地址、代理前五元组和 Mihomo 拨号终态中的回环地址。此类记录保留 connection ID、
URL、代理前流和失败终态，但 post-flow 在语义上不适用，不计入出口失败或 post-PCAP
缺失。对应质量字段为
`egress_establishment.not_applicable_local_endpoint`、
`pcap_extraction.applicable` 和 `pcap_extraction.post_not_applicable`。若 CDP 带有
cache 标记但 NetLog 同时证明存在真实 socket，该请求按 `network` 处理，避免缓存
提示覆盖实际网络证据。


“会话”区域按时间戳 Capture group 浏览，不再默认汇总整个 Session root：捕获运行时自动选中本次时间戳目录；没有活动捕获时默认不显示历史内容，可通过“选择文件夹”手动打开当前输出根目录下的时间戳目录。旧版直属 `<timestamp>_<session-id>` 目录仍可选择。扫描器只识别合法的新旧 Session 布局，并忽略 `.chrome-profiles`、`.batches` 及 Chrome 扩展自己的 `manifest.json`；选定目录内真正损坏的 Session manifest 仍会单独报告。

开发入口：

```bash
make check-toolchain
make dev
```

Linux x86-64 打包入口：

```bash
make package-linux
sha256sum -c dist/packages/x86_64-unknown-linux-gnu/SHA256SUMS
```

发布候选必须从干净工作树生成许可证、CycloneDX SBOM、组件来源和审计报告：

```bash
make release-linux
make audit-release
```

完整的依赖安装、UI 操作、权限、服务 IPC、故障恢复、协议版本与非目标见 [Complete QuickStart](docs/complete/quickstart.md)；正式发布前执行 [Release Checklist](docs/release-checklist.md)。

> 下文保留 TrafficTracer Python 库与独立 CLI 的架构和参考资料；Complete 的常规 UI 流程不要求使用这些 CLI。

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

## Standalone CLI Installation

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

## Standalone CLI Quick Start

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
    traffic_type: video-mainpage  # run label; normalized network is "all"
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
- `traffic_type` is a compatibility field used during target normalization:
  exact lowercase `tcp`, `udp`, or `all` becomes both the network selector and
  run label; any other safe label becomes the run label while `network`
  defaults to `all`.

#### Target YAML normalization

Each item under `sites` is normalized to a fixed target containing `url`,
`domain`, `duration_seconds`, `wait_load_timeout`, `network`, `run_label`,
`page_type`, and its original list index. Complete prefers an explicit
`page_type`; legacy files derive it deterministically from `traffic_type`. The
current YAML format keeps the legacy `traffic_type` field and interprets it as follows:

| YAML value | Normalized `network` | Normalized `run_label` | Result |
|---|---|---|---|
| `tcp` | `tcp` | `tcp` | TCP target |
| `udp` | `udp` | `udp` | UDP target |
| `all` or omitted | `all` | `all` | TCP and UDP target |
| `Video-mainpage` | `all` | `Video-mainpage` | Safe run label; Complete UI shows an informational fallback warning |

The three network keywords are case-sensitive. Labels must contain 1–64
letters, digits, `.`, `_`, or `-`, and must start with a letter or digit;
unsafe values such as `../video` are rejected. The current schema does not yet
accept independent `network` and `run_label` keys, so a custom label cannot be
combined with a TCP-only or UDP-only selector. When multiple sites are selected
in Complete, their original YAML order and indexes are preserved, including
entries with duplicate URL/domain values.

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
flows. For CDP-first analysis this file is a legacy compatibility projection of
the canonical v2 request and connection indexes, not an independent attribution
source. Consumers must use `summary.json.consistency` and the v2 indexes for
coverage. `flow-index.json` remains capture-global and carries browser
attribution only where its Mihomo connection ID has an exact v2 mapping.

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
| `traffic_type` | Compatibility field: lowercase `tcp`, `udp`, or `all` selects the normalized network; any other safe value is a run label and falls back to network `all` |
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
