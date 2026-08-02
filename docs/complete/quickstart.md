# TrafficTracer Complete QuickStart

TrafficTracer Complete 把定制 Mihomo、TrafficTracer Worker 和 Clash Verge UI 固定在一个仓库中。本文档以 Linux x86-64 为已验证目标，不依赖同级 sibling 仓库，也不需要手工复制二进制。

## 1. 组件与版本

`complete/components.lock.yaml` 是组件和协议版本的事实来源。当前产品版本为 `0.1.0-dev`，以下协议均为 v1：

| 协议 | 版本 |
| --- | --- |
| Worker JSONL API | 1 |
| Session manifest | 1 |
| Flow result | 1 |
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

文件名随版本变化。Complete 包必须同时包含 `verge-mihomo-tt`、`traffictracer-worker`、标准/Alpha 核心和三个服务 helper。上游 Clash Verge 包不等价。

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

启动开发 UI：

```bash
make dev
```

该命令会重新构建固定 Mihomo 核心和 Worker，强制注入 UI sidecar，校验文件一致性并打印组件提交和 artifact SHA-256。只准备而不启动 UI：

```bash
make prepare-dev
```

## 4. UI 全流程

1. 在“订阅/Profiles”导入并激活 Mihomo YAML。
2. 在“设置 → Clash 设置 → Clash Core”选择 `verge-mihomo-tt`。
3. 在“代理/Proxies”执行延迟测试并选择节点/策略组。
4. 按需开启系统代理。
5. 安装 Clash Verge 服务并开启 TUN。
6. 打开“流量追踪”，填写 URL、协议、持续时间、TUN/物理接口、Chrome 绝对路径和输出绝对目录。
7. 点击“检测环境”，关闭所有阻断项。
8. 点击“开始捕获”；启用“自动分析”时捕获后自动进入分析。
9. 在“会话”查看状态、警告和产物，或点击“重新分析”。
10. 在“规范化流”输入代理前五元组，查询全部 Session。

诊断覆盖 TT 核心能力、控制器、TUN 服务、两个接口、捕获工具/权限、浏览器和存储空间。捕获期间核心、配置、tracing、TUN、系统代理与服务控制会锁定，避免运行时状态漂移。

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
| `/tmp/verge/clash-verge-service.sock` | Clash Verge 特权服务 IPC |
| `/tmp/verge/verge-mihomo.sock` | Mihomo 控制器 IPC |

出现 `IPC path not ready` 时，关闭重复 UI，只启动当前版本，然后检查：

```bash
ls -l /usr/bin/clash-verge-service*
pgrep -af 'clash-verge-service|clash-verge'
ls -l /tmp/verge/clash-verge-service.sock
```

回到 UI 使用“修复/重新安装服务”，并查看“设置 → 日志”。不要同时手工启动 helper 和点击 UI 安装，也不要删除正在使用的 socket。

## 6. Session、恢复与取消

每次捕获在输出根目录创建独立 Session。manifest 记录状态、组件版本、接口、警告、错误和 artifact，是 UI/Worker 的事实来源。

- “取消任务”会触发协作式取消、终止受管子进程并恢复 Mihomo tracing；
- 关闭 TrafficTracer 页面不会取消后台任务；
- 应用/Worker 异常退出后，下次启动会把未完成 Session 恢复为 `interrupted`；
- 恢复警告不会阻止读取历史 Session；
- 分析失败保留原始 trace、CDP、NetLog 和 pcap，可从 UI 重新分析；
- 任务运行时不要移动或修改 Session 目录。

如果 Worker 显示 unavailable 或 API mismatch，安装版应重装同一 Complete 包；开发版运行 `make prepare-dev` 后重启 UI。

## 7. Flow 查询语义

查询键是规范化代理前五元组：协议、源 IP/端口、目的 IP/端口。一个五元组可能跨时间复用，所以结果可以是零条、一条或多条逻辑流。

- `matched`：明确关联；
- `ambiguous`：多个候选，需要结合时间和浏览器请求；
- `unmatched`：证据不足；
- `post_flow.shared=true`：多个逻辑流共享外层连接，不是一对一 NAT；
- `post_flow=null`：没有观测到完整拨号结果，不会用 `pre_flow` 伪造。

当前 pcap artifact 属于 Session；schema 不承诺每条 Flow 都有独立 pcap。

## 8. Linux 打包

开发测试可使用 `make package-linux`。正式发布候选必须从三个仓库均无已
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

流水线重新构建核心/Worker，调用 Tauri 生成 Deb/AppImage，解包验证 8 个可执行文件，最后才原子发布：

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

默认输出已存在时脚本拒绝覆盖。可移动旧目录，或为新候选指定新目录：

```bash
TT_PACKAGE_OUTPUT_DIR="$PWD/dist/packages/rc-2" make release-linux
```

未配置 `TAURI_SIGNING_PRIVATE_KEY` 时生成经过布局验证的 unsigned 包；发布 updater artifact 时必须配置私钥。任一构建、验证或校验步骤失败，最终输出目录不会创建。

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
