# Clash Verge TrafficTracer Complete UI — 原子实施计划

仓库：`clash-verge-rev`
目标分支：`feat/traffic-tracer`（稳定后可新建 `feat/traffictracer-complete`）
任务前缀：`UI-*`
首发范围：Linux x86-64、单采集任务、Worker sidecar、现有 profile/proxy/TUN 能力复用。

## 1. 现有能力复用点

- 核心发现：`src-tauri/src/core/discovery.rs`。
- 核心切换：`src-tauri/src/cmd/clash.rs` 与 `ClashCoreViewer`。
- tracing API：`src-tauri/src/cmd/tracing.rs`、`src/hooks/use-tracing.ts`。
- profile 导入与当前配置：现有 Profiles/Config manager。
- 节点测速与选择：现有 mihomo API plugin 和 Proxies 页面。
- TUN/系统代理/服务安装：现有 switches、service hooks 和 Rust service manager。
- sidecar 预构建：`scripts/prebuild.mjs`。
- Linux externalBin：`src-tauri/tauri.linux.conf.json`。

Complete 不重新实现上述功能，只增加任务编排、锁定和 Session/Flow UI。

## 2. Rust 后端原子任务

### UI-001 — 定义 Worker Rust 协议类型

依赖：TrafficTracer `TT-007` 至 `TT-009`。
文件：新增 `src-tauri/src/core/traffic_tracer/protocol.rs`。
动作：定义 request/response/error/notification、版本常量和 serde 类型。
测试：golden JSON roundtrip、未知字段策略。
完成标准：不使用 `serde_json::Value` 贯穿业务层。
验证：`cargo test --manifest-path src-tauri/Cargo.toml traffic_tracer::protocol`。
提交：`feat: define TrafficTracer Worker protocol types`

### UI-002 — 增加 Worker sidecar 配置

依赖：TrafficTracer `TT-033`。
文件：`src-tauri/tauri.linux.conf.json`、必要 capability 配置。
动作：将 `traffictracer-worker` 加入 externalBin；只允许应用自身调用。
测试：Tauri config schema/构建配置测试。
完成标准：Linux 包含目标后缀 Worker。
验证：`pnpm tauri build --debug --no-bundle` 或项目等价命令。
提交：`build: bundle TrafficTracer Worker sidecar`

### UI-003 — 扩展 prebuild Worker resolver

依赖：UI-002。
文件：`scripts/prebuild.mjs`。
动作：支持 `TRAFFICTRACER_WORKER_BIN`；默认从 Complete 总仓 dist 查找；`--force` 必须覆盖 stale 文件。
测试：临时文件 resolver 测试或脚本模块化测试。
完成标准：缺失 Worker 时输出目标 triple 和修复命令。
验证：`TRAFFICTRACER_WORKER_BIN=... pnpm prebuild --force`。
提交：`build: prepare TrafficTracer Worker sidecar`

### UI-004 — 实现 Worker 子进程封装

依赖：UI-001、UI-003。
文件：`src-tauri/src/core/traffic_tracer/worker.rs`。
动作：启动 sidecar、保存 CommandChild、读取 stdout 行、stderr 写应用日志、检测退出。
测试：假 Worker 启动/退出/坏行。
完成标准：Worker 只能有一个实例，stop 幂等。
验证：Rust 单测。
提交：`feat: manage TrafficTracer Worker process`

### UI-005 — 实现请求 ID 与 pending map

依赖：UI-004。
文件：`worker.rs`、`client.rs`。
动作：生成请求 ID、写 stdin、按 ID 完成 oneshot、请求超时、退出时失败全部 pending。
测试：乱序响应、重复 ID、超时、EOF。
完成标准：没有永久悬挂 Promise。
验证：Rust async tests。
提交：`feat: correlate Worker requests and responses`

### UI-006 — 实现 hello/version 握手

依赖：UI-005。
文件：`client.rs`。
动作：启动后调用 worker.hello，比较 worker API/session/flow 版本与应用支持范围。
测试：匹配、过旧、过新、缺字段。
完成标准：版本不兼容时 Worker 不进入 Ready。
验证：Rust tests。
提交：`feat: negotiate TrafficTracer Worker versions`

### UI-007 — 转发 Worker notification 为 Tauri Event

依赖：UI-005。
文件：`worker.rs`、`events.rs`。
动作：将 job.event/log/completed/failed 转为固定事件名；限制 payload 和日志频率。
测试：事件映射和超大 payload。
完成标准：前端不直接接触 stdout。
验证：Rust tests。
提交：`feat: bridge Worker progress to Tauri events`

### UI-008 — 增加 Worker manager 全局状态

依赖：UI-006、UI-007。
文件：`src-tauri/src/core/traffic_tracer/mod.rs`、应用初始化。
动作：定义 Stopped/Starting/Ready/Busy/Failed，提供全局 manager。
测试：合法状态转换、并发 start。
完成标准：状态由单一 owner 管理。
验证：Rust tests。
提交：`feat: add TrafficTracer Worker state manager`

### UI-009 — 增加环境诊断 command

依赖：UI-008、TrafficTracer `TT-027`。
文件：`src-tauri/src/cmd/traffic_tracer.rs`、`lib.rs`。
动作：实现 `tt_get_environment`，合并 Worker diagnose、当前核心、服务/TUN 状态。
测试：Ready/warning/blocking。
完成标准：404 被映射为 CORE_NOT_TRAFFIC_TRACER。
验证：Rust command test。
提交：`feat: expose Complete environment diagnostics`

### UI-010 — 增加采集 commands

依赖：UI-008、TrafficTracer `TT-030`。
文件：`cmd/traffic_tracer.rs`。
动作：实现 start/get/cancel；start 前验证绝对路径、单任务和环境。
测试：非法 spec、busy、cancel 幂等。
完成标准：前端不能绕过诊断直接创建危险任务。
验证：Rust tests。
提交：`feat: expose TrafficTracer capture commands`

### UI-011 — 增加 Session commands

依赖：UI-008、TrafficTracer `TT-016`。
文件：`cmd/traffic_tracer.rs`。
动作：list/get/open artifact；路径由 Worker 返回的 artifact ID 解析，不接受任意系统路径。
测试：路径逃逸、损坏 manifest、空列表。
完成标准：open artifact 受 Session root 限制。
验证：Rust tests。
提交：`feat: expose TrafficTracer Session commands`

### UI-012 — 增加分析与 Flow commands

依赖：UI-011、TrafficTracer `TT-025`。
文件：`cmd/traffic_tracer.rs`。
动作：analysis.start、flow.query，校验五元组端口/IP/network。
测试：IPv4/IPv6、无匹配、多个会话、shared。
完成标准：无匹配返回空数组，不作为内部错误。
验证：Rust tests。
提交：`feat: expose analysis and Flow lookup commands`

### UI-013 — 实现应用启动恢复

依赖：UI-008、TrafficTracer `TT-031`。
文件：manager 初始化与 shutdown hook。
动作：启动 Worker 后等待 recovery 完成；关闭应用先请求 graceful shutdown，再超时 kill。
测试：interrupted session、worker hang、恢复失败。
完成标准：恢复失败显示 warning，但历史 Session 可读。
验证：Rust integration test。
提交：`feat: recover TrafficTracer jobs on app lifecycle`

### UI-014 — 建立 CaptureLock

依赖：UI-010。
文件：`src-tauri/src/core/traffic_tracer/lock.rs`。
动作：活动 capture 时提供全局只读锁，暴露 reason/job_id。
测试：获取/释放、Worker 崩溃释放、重复释放。
完成标准：锁不会因前端页面卸载而消失。
验证：Rust tests。
提交：`feat: lock proxy state during TrafficTracer capture`

## 3. 前端状态与基础组件

### UI-015 — 增加 TypeScript 类型与 commands wrapper

依赖：UI-009 至 UI-012。
文件：`src/types/global.d.ts` 或独立类型文件、`src/services/cmds.ts`。
动作：定义 Environment、Job、Session、Flow；封装 invoke。
测试：`pnpm typecheck`。
完成标准：页面不手写 invoke 字符串。
提交：`feat: add TrafficTracer Complete frontend types`

### UI-016 — 增加 Worker/Job hooks

依赖：UI-015。
文件：`src/hooks/use-traffic-tracer-worker.ts`、`use-capture-job.ts`。
动作：React Query 获取状态；订阅 Tauri event；卸载时解除监听；失败回滚。
测试：hook tests/mock events。
完成标准：刷新页面仍能从后端恢复活动 Job。
提交：`feat: add TrafficTracer Worker and job hooks`

### UI-017 — 增加 Session/Flow hooks

依赖：UI-015。
文件：`use-traffic-tracer-sessions.ts`、`use-flow-query.ts`。
动作：分页/刷新/重新分析/query cache；按 session/job key 隔离。
测试：空列表、invalidate、多个结果。
完成标准：分析完成自动刷新 Session。
提交：`feat: add TrafficTracer Session and Flow hooks`

### UI-018 — 增加导航与路由

依赖：UI-016。
文件：现有 router/navigation 配置、新增 `src/pages/traffic-tracer/index.tsx`。
动作：增加 TrafficTracer 页面入口，懒加载，保留原 Settings tracing 开关。
测试：route render 和权限条件。
完成标准：旧导航不回归。
提交：`feat: add TrafficTracer Complete workspace route`

### UI-019 — 增加环境状态卡

依赖：UI-016、UI-018。
文件：`src/components/traffic-tracer/environment-card.tsx`。
动作：显示核心、controller、TUN、接口、dumpcap、Chrome、输出目录；提供修复入口。
测试：ready/warning/error snapshot。
完成标准：每个阻断项有明确 remediation。
提交：`feat: show TrafficTracer environment readiness`

### UI-020 — 增加采集表单

依赖：UI-019。
文件：`capture-form.tsx`。
动作：URL/domain、时长、接口、Chrome、output、CDP、pcap、自动分析；自动填充诊断候选。
测试：表单验证、绝对路径、domain 推导。
完成标准：阻断诊断未解决时不能提交。
提交：`feat: add TrafficTracer capture form`

### UI-021 — 增加任务进度和取消

依赖：UI-016、UI-020。
文件：`job-progress.tsx`。
动作：阶段、进度、日志、开始时间、取消确认；Canceling 时禁用重复操作。
测试：正常、失败、取消、重连。
完成标准：UI 不把关闭页面当作取消。
提交：`feat: display and cancel TrafficTracer jobs`

### UI-022 — 增加 Session 列表

依赖：UI-017、UI-018。
文件：`sessions-view.tsx`、`session-card.tsx`。
动作：状态、URL、时间、节点、统计、重新分析、打开目录。
测试：loading/empty/corrupt/completed。
完成标准：损坏 Session 单独标红，不拖垮列表。
提交：`feat: add TrafficTracer Session browser`

### UI-023 — 增加 Session 详情与 artifacts

依赖：UI-022。
文件：`session-detail.tsx`、`artifact-list.tsx`。
动作：组件版本、接口、警告、artifact 大小/打开、分析状态。
测试：缺失 artifact、failed analysis。
完成标准：路径以逻辑名称展示，不暴露 secret。
提交：`feat: show TrafficTracer Session artifacts`

### UI-024 — 增加 Flow 表格

依赖：UI-017、UI-023。
文件：`flow-table.tsx`。
动作：TCP/UDP、pre/post、match、shared、URL；筛选/分页。
测试：post null、IPv6、多个相同 pre key。
完成标准：shared 有醒目标识。
提交：`feat: add normalized Flow explorer`

### UI-025 — 增加 Flow 详情

依赖：UI-024。
文件：`flow-detail.tsx`。
动作：完整 tuple、conn IDs、bytes/status/error/request IDs、pcap artifacts。
测试：legacy fallback、exact/shared/error。
完成标准：不把 incomplete post_flow 填充成伪完整 tuple。
提交：`feat: add TrafficTracer Flow details`

### UI-026 — 增加五元组查询表单

依赖：UI-024。
文件：`flow-query-form.tsx`。
动作：network/src/dst IP/port，IPv6 支持，展示所有匹配会话。
测试：非法 IP/port、空结果、多结果。
完成标准：查询 key 语义与 Python FlowIndex 一致。
提交：`feat: query post-proxy flows from pre-proxy tuples`

## 4. 全局控制锁与体验

### UI-027 — 锁定核心/profile/tracing 控件

依赖：UI-014、UI-016。
文件：ClashCoreViewer、profile 控件、`setting-clash.tsx`。
动作：活动 capture 时禁用切换/手工 tracing，并显示 job 原因。
测试：锁定/释放/worker crash。
完成标准：不能在 capture 中途改变核心或 tracing output。
提交：`feat: guard core and tracing controls during capture`

### UI-028 — 锁定 TUN/系统代理破坏性操作

依赖：UI-014。
文件：现有 proxy-control-switches 和 service hooks。
动作：capture 期间关闭 TUN/卸载服务需阻止；非破坏性状态读取保持。
测试：按钮、托盘/快捷入口后端二次校验。
完成标准：不只依赖前端 disabled。
提交：`feat: guard TUN lifecycle during capture`

### UI-029 — 增加中英文文案

依赖：UI-018 至 UI-028。
文件：`src/locales/zh/settings.json`、`en/settings.json` 及项目要求的资源类型生成。
动作：页面、阶段、错误码、remediation 文案；其他 locale 使用英文 fallback 或同步键。
测试：i18n key generation/check。
完成标准：无 raw key，现有 locale CI 通过。
提交：`feat: localize TrafficTracer Complete UI`

## 5. 打包、测试和文档

### UI-030 — 增加 Rust Worker integration tests

依赖：UI-013。
文件：`src-tauri/tests/traffic_tracer_worker.rs`、假 Worker fixture。
动作：hello、乱序响应、progress、cancel、crash、shutdown。
验证：`cargo test --manifest-path src-tauri/Cargo.toml traffic_tracer`。
完成标准：不依赖真实 Chrome/TUN。
提交：`test: cover TrafficTracer Worker orchestration`

### UI-031 — 增加前端页面测试

依赖：UI-029。
文件：页面/component 测试。
动作：环境阻断、表单、进度、Session、Flow、锁定。
验证：项目现有 test 命令；若尚无 runner，先单独原子任务引入。
完成标准：关键按钮和错误状态有自动测试。
提交：`test: cover TrafficTracer Complete workspace`

### UI-032 — 完成 Linux bundle 配置

依赖：UI-002、UI-003、UI-029。
文件：Tauri Linux config、resources、安装后检查。
动作：同时打包 standard core、TT core、Worker、service helpers；设置可执行位。
验证：deb/AppImage 内容检查。
完成标准：安装后动态核心列表包含 `verge-mihomo-tt`。
提交：`build: package TrafficTracer Complete on Linux`

### UI-033 — 更新 UI QuickStart 和排障

依赖：UI-032。
文件：`README.md`、`docs/TRAFFIC_TRACER_QUICKSTART.md`。
动作：Complete 总仓入口、环境诊断、服务授权、IPC path、Session/Flow 操作。
验证：干净安装包按文档操作。
完成标准：不再要求用户手工运行 Python capture/analyze。
提交：`docs: publish TrafficTracer Complete UI guide`

## 6. UI 完成门禁

```bash
pnpm typecheck
pnpm lint
cargo test --manifest-path src-tauri/Cargo.toml traffic_tracer
TRAFFICTRACER_WORKER_BIN=/absolute/path/to/worker pnpm prebuild --force
pnpm build
```

额外检查：

- 不存在 raw shell command 拼接。
- Worker stdout 不进入普通日志 parser。
- CaptureLock 在 Rust 层强制，不仅是按钮 disabled。
- artifact open 不能访问 Session root 之外。
- UI 不读取或显示配置 secret。
- Worker/核心版本不匹配时给出明确升级指引。

## 7. 非目标

- 重写现有 Proxies/Profile 页面。
- 自动绕过系统服务授权。
- Windows Named Pipe 和 macOS Network Extension。
- 多 Worker、多并发 capture。
- 实时 pcap 解码和逐包图形化。
