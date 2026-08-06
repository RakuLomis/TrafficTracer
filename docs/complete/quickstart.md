# TrafficTracer Complete QuickStart

TrafficTracer Complete 把定制 Mihomo、TrafficTracer Worker 和 Clash Verge UI 固定在一个仓库中。本文档以 Linux x86-64 为已验证目标，不依赖同级 sibling 仓库，也不需要手工复制二进制。

## 1. 组件与版本

`complete/components.lock.yaml` 是组件和协议版本的事实来源。当前产品版本为 `0.1.0-dev`：

| 协议 | 版本 |
| --- | --- |
| Worker JSONL API | 2 |
| Job schema | 2 |
| Session manifest | 2 |
| Flow result | 1 |
| Connection index | 2 |
| Request index | 2 |
| PCAP index | 1 |
| Batch manifest | 1 |
| Mihomo tracing API | 1 |
| Mihomo event schema | 1 |

构建和启动时会校验固定的 submodule 提交；不要在 Complete 构建中用任意 sibling checkout 替换它们。

## 2. 使用安装包

需要 Chrome/Chromium 以及 Wireshark CLI：

```bash
sudo apt-get install tshark
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v dumpcap)"
dumpcap -D
```

若发行版使用 `wireshark` 用户组，请按软件包提示添加当前用户并重新登录。

安装 Complete Deb：

```bash
sudo apt install ./Clash\ Verge_2.5.2_amd64.deb
```

或运行 AppImage：

```bash
chmod +x ./Clash\ Verge_2.5.2_amd64.AppImage
./Clash\ Verge_2.5.2_amd64.AppImage
```

文件名随版本变化。Complete 包必须同时包含 `verge-mihomo-tt`、`traffictracer-worker`、标准/Alpha 核心、特权服务及其安装/卸载 helper。上游 Clash Verge 包不等价。Worker API v2 与对应 UI 必须成套安装，不能只替换 Worker 或只替换 UI。

## 3. 从源码开发

```bash
git clone --branch Complete --recurse-submodules \
  git@github.com:RakuLomis/TrafficTracer.git
cd TrafficTracer
make bootstrap
```

准备工具链和依赖：

```bash
python -m pip install -r requirements.txt -r requirements-build.txt
corepack enable
cd components/clash-verge-rev
pnpm install --frozen-lockfile
cd ../..
make check-toolchain
```

`make check-toolchain` 检查 Python 3.12+、Go、Rust/Cargo、pnpm、PyInstaller、Chrome、tshark 和 dumpcap。

建议先运行源码和跨组件合同测试：

```bash
make test-python
make test-contracts
```

只编译核心与 Worker、注入开发 sidecar，但不启动第二个 Clash Verge：

```bash
make prepare-dev
```

产物位于：

```text
dist/core/verge-mihomo-tt-x86_64-unknown-linux-gnu
dist/worker/traffictracer-worker-x86_64-unknown-linux-gnu
components/clash-verge-rev/src-tauri/sidecar/
```

启动开发 UI：

```bash
make dev
```

该命令会执行与 `make prepare-dev` 相同的重建和校验，然后启动 Tauri 开发 UI。不要让它与已安装的 Clash Verge 同时运行并争用控制器/socket；若当前 Clash Verge 正在提供网络，应先使用 `make prepare-dev` 或构建安装包，等到可接受的网络维护窗口再从 UI 正常退出旧实例后启动开发版。不要用强制 kill 作为常规切换方式。

如果当前 checkout 含有尚未提交的开发改动，`make prepare-dev` 和 `make package-linux` 可以生成本地测试构建，但 `COMPONENTS` 中记录的是当前提交而不是未提交 diff，不能作为正式发布包。正式候选必须先提交 UI 子模块改动、更新根仓库 gitlink/组件锁并保持受跟踪工作树干净。

## 4. UI 全流程

1. 在“订阅/Profiles”导入并激活 Mihomo YAML。
2. 在“设置 → Clash 设置 → Clash Core”选择 `verge-mihomo-tt`。
3. 在“代理/Proxies”执行延迟测试并选择节点/策略组。
4. 按需开启系统代理。
5. 安装 Clash Verge 服务并开启 TUN。
6. 打开“流量追踪”，选择“手工输入”并填写单目标，或选择“YAML 配置”加载 `sites.yaml` 后全选/选择子集；再填写 TUN/物理接口、Chrome 绝对路径和输出绝对目录。
7. 点击“检测环境”，关闭所有阻断项。
8. 点击“开始捕获”。所选目标组成一个 Capture group，并强制每项完成分析后才进入下一项。
9. Capture group 卡片展示当前 N/total、阶段、页面 Session 和错误；可请求取消，failed/interrupted 状态可从准确目标继续。
10. 捕获运行时“会话”自动选中本次时间戳目录并只显示该 Capture group；空闲时默认不显示历史内容，可点击“选择文件夹”打开当前输出根目录下的历史时间戳目录，再查看状态、警告、产物或“重新分析”。
11. 在“规范化流”输入代理前五元组，查询全部 Session。

诊断覆盖 TT 核心能力、控制器、TUN 服务、两个接口、捕获工具/权限、浏览器和存储空间。捕获期间核心、配置、tracing、TUN、系统代理与服务控制会锁定，避免运行时状态漂移。

目标 YAML 兼容独立版的 `sites` 列表，例如：

```yaml
sites:
  - domain: example.com
    url: https://example.com/
    wait: 15
    traffic_type: all
    page_type: main-page
    wait_load_timeout: 30
```

UI 只应用 `sites` 目标；`global.output.base_dir` 仅作为输出目录建议值预览，必须由用户在 UI 确认。文件中的 `global.mihomo`、`global.chrome` 和 `global.network` 不会覆盖 Clash Verge 运行环境。`wait` 映射为捕获持续时间，`wait_load_timeout` 映射为页面加载超时，`page_type` 决定页面目录标签；`traffic_type` 为 `tcp`、`udp` 或 `all` 时决定捕获协议，其他安全值作为兼容运行标签且协议回退为 `all`。

加载时 Worker 仅返回规范化目标、绝对路径、警告和文件 SHA-256，不返回代理 secret 或其他 `global` 内容。开始捕获前 UI 后端会重新读取文件并比对 SHA-256、目标序号及所有规范化字段；文件若已变化，必须点击刷新并重新选择，避免预览与实际任务不一致。选择一项时走普通捕获 API；选择多项时按 YAML 原始顺序建立固定目标快照，即使 URL/domain 重复也以配置索引区分。批次最大子任务并发为 1，严格执行 capture → Chrome quiescence → analysis → checkpoint；只有上一个受管 Chrome 进程组清理完毕后才会启动下一项，不会按进程名终止用户的其他 Chrome。

目标文件应放在不会随重启清理的持久目录，不要放在 `/tmp`。文件必须是 UTF-8、扩展名为 `.yaml` 或 `.yml`、不超过 1 MiB，并包含非空 `sites` 列表。字段约束如下：

| 字段 | 约束/默认值 |
| --- | --- |
| `domain` | 必填，有效 DNS 名称 |
| `url` | 必填，绝对 `http://` 或 `https://` URL |
| `wait` | 1–86400 的整数，默认 10 秒 |
| `wait_load_timeout` | 1–3600 的整数，默认 30 秒 |
| `traffic_type` | 默认 `all`；1–64 位字母、数字、点、下划线或连字符，首位必须是字母或数字 |
| `page_type` | 推荐显式填写；小写字母、数字和连字符，配置内唯一；旧 YAML 会从 `traffic_type` 稳定推导 |

### P0 工作区与 TUN 约定

TrafficTracer 页面是 Complete 捕获功能的唯一入口；“设置 → Clash 设置”中不再提供单独的 tracing 开关。开始任务时由 Complete 自动开启 Mihomo tracing，任务完成、取消或失败后自动恢复，避免两个入口争用同一状态。

“会话输出目录”是 Worker 的工作区根目录，不再固定为应用数据目录。它必须是绝对路径；环境检测会创建目录、检查写权限并将其规范化。切换目录后再次点击“检测环境”：

- Worker 处于空闲状态时会优雅切换到新工作区；
- 有捕获或分析任务运行时返回 `SESSION_ROOT_BUSY`，不会中断任务；
- 切换失败时会尝试恢复原工作区；
- 切换不会搬移旧 Session，新旧目录中的历史记录彼此独立。

TUN 的配置名、自动默认名和实际捕获接口是三个不同概念：Linux 的 TUN `device` 留空时由 Mihomo 自动使用 `Meta`；显式填写时使用填写值。环境检测展示配置值、自动默认值和当前实际捕获接口。若系统中只发现一个 TUN 候选会自动选中；发现多个候选时必须人工选择，避免把 `Meta`、`Meta0` 等接口猜错。每次捕获还会把最终使用的 TUN/物理接口写入页面 Session 的 `raw/capture-context.json` 并登记为 artifact，供后续审计和关联分析使用。

Linux 可用以下命令辅助选择接口：

```bash
ip route show default
ip -brief link
```

## 5. 服务权限与 IPC

Linux 安装服务时会出现管理员授权，例如：

```text
/usr/bin/sh -c /usr/bin/clash-verge-service-install
```

确认 helper 与当前 Clash Verge 主程序同目录后授权。两个 socket 用途不同：

| 路径 | 用途 |
| --- | --- |
| `/run/clash-verge-service/service.sock` | Linux Clash Verge 特权服务 IPC（service v2.6.1） |
| `/tmp/verge/verge-mihomo.sock` | Mihomo 控制器 IPC |

Complete 将 service 客户端、service 发行包和协议固定为 v2.6.1（协议 2.2）。出现 `IPC path not ready` 时，不要停止当前正在提供网络的 Clash Verge；先只读检查：

```bash
ls -l /usr/bin/clash-verge-service*
pgrep -af 'clash-verge-service|clash-verge'
systemctl status clash-verge-service --no-pager
ls -l /run/clash-verge-service/service.sock
```

如果 `/run/clash-verge-service/service.sock` 已存在且服务为 active，而 UI 仍在检查 `/tmp/verge/clash-verge-service.sock`，运行的是旧 UI 客户端；应安装同一 Complete 构建中的 UI 与 service，不要反复重装健康服务。只有实际 socket 缺失或 UI 明确报告协议不兼容时，才在可接受的网络维护窗口内使用“修复/重新安装服务”。不要同时手工启动 helper 和点击 UI 安装，也不要删除正在使用的 socket。

## 6. Session、恢复与取消

一次启动在输出根目录创建一个时间戳 Capture group，每个目标页面是独立 Session。manifest 记录状态、组件版本、接口、警告、错误和 artifact，是 UI/Worker 的事实来源：

```text
<output-root>/<YYYYMMDD-HHMMSS-mmm>/
└── <domain>/
    └── <page_type>__<readable-target-url>/
        ├── raw/
        └── analysis/
            └── pcap/
                └── <ordinal>__<readable-request-url>/
                    ├── mapping.json
                    ├── pre.pcap
                    └── post.pcap
```

“会话”始终以一个时间戳目录为浏览作用域：活动捕获自动选择当前 Capture group，任务结束后自动选择会清空；用户手动选择的目录会保留到切换输出根目录或点击“清除选择”。不能选择输出根目录本身、domain/page 子目录、隐藏运行目录、外部目录或软链接。旧版直属 `<timestamp>_<session-id>` 目录作为单 Session 作用域兼容。`.chrome-profiles` 中 Chrome 扩展的 `manifest.json` 不属于 TrafficTracer Session，不会参与损坏检测。

- “取消任务”会触发协作式取消、终止受管子进程并恢复 Mihomo tracing；
- 关闭 TrafficTracer 页面不会取消后台任务；
- Capture group 不依赖页面持续打开，刷新后会从 Worker manifest 恢复进度；
- Capture group 默认 fail-fast；修复故障后可从失败项继续，已完成项不会重跑；
- 应用/Worker 异常退出后，下次启动会把未完成 Session 恢复为 `interrupted`；
- 恢复警告不会阻止读取历史 Session；
- 分析失败保留原始 trace、CDP、NetLog 和 pcap，可从 UI 重新分析；
- 任务运行时不要移动或修改 Session 目录。
- 不要在 Capture group 中途修改目标 YAML；继续操作会校验启动时 SHA，拒绝静默使用变化后的文件。

如果 Worker 显示 unavailable 或 API mismatch，安装版应重装同一 Complete 包；开发版运行 `make prepare-dev` 后重启 UI。

## 7. Flow 查询语义

查询键是规范化代理前五元组：协议、源 IP/端口、目的 IP/端口。一个五元组可能跨时间复用，所以结果可以是零条、一条或多条逻辑流。

- `matched`：明确关联；
- `ambiguous`：多个候选，需要结合时间和浏览器请求；
- `unmatched`：证据不足；
- `post_flow.shared=true`：多个逻辑流共享外层连接，不是一对一 NAT；
- `post_flow=null`：没有观测到完整拨号结果，不会用 `pre_flow` 伪造。

启用拆分时，`analysis/pcap` 为每个稳定连接生成一组双侧 PCAP；HTTP/2、QUIC 等复用连接可对应多个请求 URL，完整集合记录在同目录 `mapping.json` 和 connection/request index 中。

## 8. Linux 打包

开发测试可使用 `make package-linux`。该入口会先重建核心和 Worker、注入并核对 sidecar，再调用 Tauri；不要直接从 UI 子仓库运行裸 `pnpm tauri build`。正式发布候选必须从三个仓库均无已
跟踪改动的工作树执行：

```bash
make release-linux
make test-package-linux
make audit-release
```

release-linux 会生成 CycloneDX 1.6 SBOM，校验组件提交、Deb/AppImage
SHA-256、安装路径权限、敏感文件/secret 模式和发行元数据。逐项人工签字要求见
[Release Checklist](../release-checklist.md)。

首次打包：

```bash
make package-linux
sha256sum -c dist/packages/x86_64-unknown-linux-gnu/SHA256SUMS
```

默认输出目录已存在时不会覆盖。为新的本地候选使用新的绝对目录，例如：

```bash
cd /absolute/path/to/TrafficTracer
TT_PACKAGE_OUTPUT_DIR="$PWD/dist/packages/target-config-v2" make package-linux
sha256sum -c dist/packages/target-config-v2/SHA256SUMS
```

这里的 `$PWD` 必须是 TrafficTracer `Complete` 仓库根目录；如果命令在 `~` 中执行，它会错误地指向 `$HOME/dist/...`。

流水线重新构建核心/Worker，调用 Tauri 生成 Deb/AppImage，解包验证 7 个可执行文件，最后才原子发布：

```text
dist/packages/x86_64-unknown-linux-gnu/
├── Clash Verge_<version>_amd64.deb
├── Clash Verge_<version>_amd64.AppImage
├── COMPONENTS
├── SHA256SUMS
├── LICENSE / NOTICE / THIRD_PARTY_NOTICES.md
├── SBOM.cdx.json
├── RELEASE-AUDIT.json
└── METADATA.sha256
```

正式候选的默认输出已存在时同样拒绝覆盖；为新候选指定新目录：

```bash
TT_PACKAGE_OUTPUT_DIR="$PWD/dist/packages/rc-2" make release-linux
```

未配置 `TAURI_SIGNING_PRIVATE_KEY` 时生成经过布局验证的 unsigned 包；发布 updater artifact 时必须配置私钥。任一构建、验证或校验步骤失败，最终输出目录不会创建。

安装或升级本地 Deb 会替换系统中的 Clash Verge 文件，但不会让已经运行的旧进程自动变成新版本。先完成构建和校验；到维护窗口后从旧 UI 正常退出，再安装并启动新包：

```bash
cd /absolute/path/to/TrafficTracer
sudo apt install "$PWD/dist/packages/target-config-v2/Clash Verge_2.5.2_amd64.deb"
```

升级后保留原有用户配置，但仍应确认核心选择为 `verge-mihomo-tt`、服务 socket 为 `/run/clash-verge-service/service.sock`，并重新执行流量追踪环境检测。不要从可能被重启清理的 `/tmp` 路径安装。

## 9. 验证

```bash
python -m pytest -q
python -m compileall -q traffictracer traffictracer_worker.py
make test-contracts
```

安装包验收至少包括：导入配置、选择 TT 核心、节点测速/选择、系统代理/TUN、环境诊断、UI 捕获/自动分析、Session artifact，以及已知代理前五元组的 Flow 查询。

## 10. 当前非目标

最小完整版本当前不承诺：

- Windows、macOS 或 Linux 非 x86-64 的可安装 Complete 包；
- 解密 TLS/QUIC 应用载荷；
- 每个代理前五元组都必然存在独占代理后五元组；
- 将 shared 外层连接解释为一对一 NAT；
- 每条 Flow 独立 pcap 的 schema 保证；
- 多个并发捕获任务；
- 用上游 Clash Verge、标准 Mihomo 或任意版本组件替换固定组件后仍兼容。

独立 Python CLI 仍保留用于自动化、研究和兼容场景，但不是 Complete UI 常规操作的前置步骤。
