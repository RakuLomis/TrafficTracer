# TrafficTracer Complete 输出、关联与批处理原子实施计划

日期：2026-08-03  
设计依据：`docs/superpowers/specs/2026-08-03-output-correlation-batch-optimization-design.md`

## 1. 执行规则

- 每个原子任务只修改一个仓库，并包含实现、单元测试和必要文档。
- 协议变更先进入 TrafficTracer contracts，再进入 Python、Rust/TS；最后更新总仓 gitlink 与 lock。
- 一个任务一个提交；跨仓集成提交只更新 gitlink、lock、fixture 和集成文档。
- 开发和测试不得终止当前用户运行的 Clash Verge、mihomo 或普通 Chrome。
- 先完成 P0 正确性，再做 P1 目录与覆盖优化，最后做 P2 批处理。

## 2. 依赖总览

```text
P0: UI-034 → UI-035 → UI-036
    UI-037 → UI-038

P1: TT-037 → TT-038 → TT-039 → TT-040 → TT-041
                         └──────────────→ UI-039

P2: TT-042 → TT-043 → TT-044 → TT-045 → TT-046
                                      └→ UI-040 → UI-041

Gate: INT-008 → INT-009 → INT-010 → INT-011 → INT-012
```

其中 UI 编号延续原 Clash Verge 计划的 `UI-001..033`，Worker 编号延续 `TT-001..036`，集成编号延续 `INT-001..007`。

## 3. P0 — 冲突入口、TUN 和工作区

### UI-034 — 删除 Settings 历史 tracing 开关

仓库：`components/clash-verge-rev`  
依赖：无。  
文件范围：`src/components/setting/setting-clash.tsx`、`src/hooks/use-tracing.ts`、相关 service/type/locale、`src-tauri/src/cmd/tracing.rs` 及 command 注册。

动作：

1. 删除 Settings 中可写的 TrafficTracer/tracing 项及 output 显示。
2. 全仓检索调用；若 Rust command 无其他消费者，删除 command 和注册，否则改为内部诊断接口且不暴露设置入口。
3. 保留 mihomo `/experimental/tracing` 和 Complete Capture Job 的控制路径。
4. 调整 CaptureLock 文案，避免再提“Settings tracing switch”。

测试：组件渲染中不存在该开关；捕获命令仍能启用/恢复 tracing；全仓无悬空 locale/type/import。  
完成标准：tracing 只有 Capture Job/兼容 CLI 两个明确所有者，桌面用户不能在 Settings 制造状态漂移。  
建议提交：`refactor: remove legacy tracing settings control`

### UI-035 — 统一 TUN 配置语义与默认展示

仓库：`components/clash-verge-rev`  
依赖：UI-034。  
文件范围：`tun-viewer.tsx`、capture form model、network interface command/types、locale。

动作：

1. 删除 Linux 前端硬编码回退 `Mihomo`。
2. 空值展示为“自动（核心默认 Meta）”，保持配置值为空，不因打开/保存页面而写入假值。
3. 建模 `configured_device`、`capture_interface`，接口候选带来源与是否可抓取。
4. 显式配置优先精确匹配；自动模式不再无提示取多个候选中的第一项。

测试：空值不写回；显式 `Mihomo` 仍按用户配置保存；Meta/Meta0/多 TUN/无 TUN fixtures。  
完成标准：Settings 展示与 mihomo 默认一致，TrafficTracer 捕获使用实际接口。  
建议提交：`fix: align TUN device selection with mihomo runtime`

### UI-036 — 增加 TUN 捕获前诊断与可追溯字段

仓库：`components/clash-verge-rev`  
依赖：UI-035。  
文件范围：TrafficTracer environment/capture command、诊断 UI、Session request/manifest 映射。

动作：捕获前重新枚举接口，返回 configured/candidates/selected；0 个候选阻断，多候选要求选择；把最终接口名写入 Job spec 和 Session 组件信息。

测试：接口在诊断后消失、配置名与实际名不一致、非特权不可抓取、选择后成功。  
完成标准：任何 PCAP 都能从 manifest 追溯到当时实际接口。  
建议提交：`feat: diagnose and record effective capture interfaces`

### UI-037 — 实现空闲 Worker 的 Session root 原子切换

仓库：`components/clash-verge-rev`  
依赖：无。  
文件范围：`src-tauri/src/core/traffic_tracer/manager.rs`、`cmd/traffic_tracer.rs`、错误类型与测试。

动作：

1. 新增异步 `ensure_session_root()`，在 lifecycle mutex 内完成比较、停旧 Worker、启新 Worker。
2. Ready 时优雅 shutdown/restart；Stopped/Failed 直接启动；Busy 返回 `SESSION_ROOT_BUSY`。
3. 目录启动前 create/canonicalize/write-probe/free-space 检查。
4. 切换失败时尽可能恢复旧 Worker/root，并返回两个阶段的结构化错误。

测试：同路径、`..`/symlink 等价路径、Ready 切换、Busy 拒绝、启动回滚、不可写目录。  
完成标准：所有需要 root 的 command 统一调用 ensure，而不是各自 `require_session_root`。  
建议提交：`fix: switch TrafficTracer workspace when worker is idle`

### UI-038 — 完成输出目录选择与 Session 工作区体验

仓库：`components/clash-verge-rev`  
依赖：UI-037。  
文件范围：TrafficTracer form/hooks/session list、持久化配置、locale。

动作：

1. 用目录选择器选择绝对路径，默认 app-data `traffictracer-sessions`。
2. 切换成功后刷新 environment、Session list 和缓存；失败则恢复输入框旧值。
3. 明示“切换工作区不会移动或删除旧 Session”。
4. 把 root 保存到 Verge 配置或专用持久化模型，避免 localStorage 与后端状态分裂。

测试：重启恢复、自定义含空格路径、取消选择、Busy 错误、在两个 root 间往返。  
完成标准：用户可在任意用户可写目录完成 capture、analysis、list、artifact open。  
建议提交：`feat: support selectable TrafficTracer workspaces`

## 4. P1 — 连接中心目录与覆盖率

### TT-037 — 定义 Session v2 与 PCAP index contract

仓库：TrafficTracer。  
依赖：无。  
文件范围：`contracts/session.schema.json`、`contracts/flow.schema.json`、新增 `contracts/pcap-index.schema.json`、fixtures、版本常量。

动作：定义扁平 `capture/analysis` artifact roles、connection/request 分离、stable connection ID、split mode、coverage 和 unmatched reason；明确 v1/v2 discriminator。

测试：shared HTTP/2、重复 URL、IPv4/IPv6/TCP/UDP、ambiguous、missing post fixtures。  
完成标准：schema 可表达多请求共享连接且不复制 Flow 记录。  
建议提交：`feat: define connection-centric session artifacts`

### TT-038 — 实现稳定连接索引与关联分层

仓库：TrafficTracer。  
依赖：TT-037。  
文件范围：`traffictracer/analyze/correlator.py`、新 connection index 模块、模型与测试。

动作：

1. 将 request 和 unique connection 分开聚合。
2. 按 request→NetLog socket→exact pre_flow→endpoint/time→host/time 分层匹配。
3. 多候选不再取 `candidates[0]`，输出候选、评分与 ambiguous。
4. 跨站 CDN 全量保留，仅设置 relation 标签。

测试：连接复用、同 endpoint 多时窗、相同五元组复用、QUIC host 多候选、无时间字段降级。  
完成标准：所有自动关联都有 method/confidence/evidence，无法唯一判断时不伪装 exact。  
建议提交：`fix: preserve ambiguity in request flow correlation`

### TT-039 — 每个唯一连接只导出一组 PCAP

仓库：TrafficTracer。  
依赖：TT-038。  
文件范围：`traffictracer/analyze/pcap_splitter.py`、artifact writer、测试。

动作：

1. 以 stable connection ID 去重，不再以 URL 建目录。
2. 实现 `none`/`unique_connections` 模式。
3. tshark 成功、输出可读后原子 rename；记录 filter、packet/byte count 和错误。
4. 保留 raw PCAP；失败不生成看似成功的空文件。

测试：8 URL 共用连接只调用 tshark 两次；重复 URL 不覆盖；哈希碰撞扩展；长 URL 不影响路径；tshark 失败。  
完成标准：样本中 28 个派生文件收敛为最多 6 个，关联信息数量不减少。  
建议提交：`refactor: split pcaps once per unique connection`

### TT-040 — 写入准确的分层覆盖率和诊断

仓库：TrafficTracer。  
依赖：TT-038、TT-039。  
文件范围：`traffictracer/analyze/artifacts.py`、pipeline、summary/flow-index tests。

动作：生成 browser request、transport connection、core logical flow 三组分母；统计 match method、歧义、缺失 post、shared 和 unmatched reason；验证 summary 可由索引重算。

测试：计数守恒、不允许 matched+ambiguous+unmatched 超过 total、空输入、partial trace。  
完成标准：UI 能解释“覆盖少在哪里”，而不是用单一百分比掩盖分母差异。  
建议提交：`feat: report layered correlation coverage`

### TT-041 — 增加 v1 Session 兼容读取与安全重分析

仓库：TrafficTracer。  
依赖：TT-037 至 TT-040。  
文件范围：Session reader、analysis pipeline、CLI、旧样本 fixtures。

动作：v1 继续只读；新采集写 v2；旧 Session 重分析写独立 generation，不覆盖/删除旧 flows；提供显式清理重复派生物的预览 API，首轮不自动删除。

测试：现有 bilibili 样本结构 fixture、混合 v1/v2 list/query、重分析中断、路径逃逸。  
完成标准：升级后旧 Session 可查看、查询和重分析。  
建议提交：`feat: read legacy sessions with v2 analysis output`

### UI-039 — 展示连接中心结果与分层覆盖率

仓库：`components/clash-verge-rev`。  
依赖：TT-037 至 TT-041。  
动作：Session detail 以请求表、唯一连接表和 coverage 卡片展示；多个 URL 链接到同 connection；ambiguous 展示候选；artifact 浏览适配 v1/v2。

测试：shared、ambiguous、missing post、legacy Session snapshots。  
完成标准：用户无需浏览复杂目录即可从 URL 或代理前五元组找到连接及代理后 Flow。  
建议提交：`feat: present connection-centric TrafficTracer results`

## 5. P2 — YAML 串行捕获与 Chrome 屏障

### TT-042 — 强化 Chrome 进程所有权

仓库：TrafficTracer。  
依赖：无。  
文件范围：`traffictracer/capture/chrome.py`、`jobs/process_registry.py`、recovery journal、测试。

动作：Linux 为 Chrome 建独立 process session/group；登记 PID/PGID/start time/profile；清理只作用于受管身份；支持检查同 profile 派生进程。

测试：主进程先退但 child 残留、PID 复用、无关 Chrome、TERM 超时 KILL、幂等清理。  
完成标准：不使用进程名全局杀进程，清理报告能证明受管 Chrome 是否完全退出。  
建议提交：`fix: own the complete Chrome capture process group`

### TT-043 — 实现 Chrome quiescence barrier

仓库：TrafficTracer。  
依赖：TT-042。  
文件范围：CaptureJob cleanup、新 barrier 模块、错误码和测试。

动作：在 CaptureJob 终态前执行 profile/process identity 校验；超时返回 `CHROME_CLEANUP_INCOMPLETE`；清理失败不得被普通 capture 成功状态覆盖。

测试：正常退出、延迟退出、残留、取消期间残留、collector close 失败。  
完成标准：Job completed 意味着下一次捕获不会复用或撞上本 Job 的 Chrome。  
建议提交：`feat: verify Chrome quiescence after capture`

### TT-044 — 定义 Batch Job contract 与持久化模型

仓库：TrafficTracer。  
依赖：TT-037、TT-043。  
文件范围：job/worker schemas、models、`batch-manifest` schema、fixtures。

动作：定义 targets 快照、config path/SHA、顺序、current index、child sessions、stage、fail-fast/cancel/interrupted/resume 元数据；升级相关协议版本。

测试：重复 target、空 targets、SHA 不匹配、非法状态转换、序列化恢复。  
完成标准：批次进度和已完成结果不依赖 UI 内存。  
建议提交：`feat: define serial capture batch contract`

### TT-045 — 实现 Worker 串行 BatchJob

仓库：TrafficTracer。  
依赖：TT-044。  
文件范围：新 `traffictracer/jobs/batch.py`、job manager、capture/analyze orchestration、测试。

动作：持有一个父 Job，按 YAML 快照严格执行 capture→quiescence→analyze→checkpoint；最大 child 并发为 1；失败默认停止；取消等待当前 child 清理。

测试：3 targets 顺序、第二项失败、分析失败、取消、cleanup barrier 失败、进度单调、最大并发计数。  
完成标准：只有前一 child 达到终态且 Chrome barrier 成功后才创建下一 child。  
建议提交：`feat: run target captures as a serial batch`

### TT-046 — 暴露 Batch Worker API 与恢复

仓库：TrafficTracer。  
依赖：TT-045。  
文件范围：worker dispatcher/services/protocol、recovery、CLI、golden fixtures。

动作：增加 batch start/status/cancel/list/resume-from-failed；Worker 启动扫描 running batch 并标 interrupted；resume 需复用固定目标快照，禁止静默读取已变化 YAML。

测试：JSONL golden、Worker crash/restart、YAML 中途变化、事件乱序、取消幂等。  
完成标准：桌面端无需循环单 Job 即可管理完整批次。  
建议提交：`feat: expose recoverable capture batch jobs`

### UI-040 — 增加 YAML 多目标选择与批次启动

仓库：`components/clash-verge-rev`。  
依赖：TT-044、TT-046。  
动作：目标预览增加全选/子集/固定顺序；单目标走原 API，多目标发 Batch request；启动前重新验证 SHA；批次持有完整 CaptureLock。

测试：选择子集、顺序稳定、SHA 变化、重复 URL/domain、锁覆盖全部破坏性控件。  
完成标准：用户无需手填 URL/domain 即可串行处理 YAML 中多项。  
建议提交：`feat: start serial captures from target YAML`

### UI-041 — 增加批次进度、取消和继续界面

仓库：`components/clash-verge-rev`。  
依赖：UI-040。  
动作：展示 N/total、child stage/session、完成/失败列表；取消等待 cleanup；interrupted/failed 支持从失败项继续；每个 child 可直接打开分析结果。

测试：刷新后恢复、事件丢失后 status reconcile、取消、失败继续、输出 root Busy。  
完成标准：批次不依赖页面持续打开，任何终态都有可解释结果。  
建议提交：`feat: manage TrafficTracer capture batches`

## 6. 跨仓门禁

### INT-008 — 锁定新协议和三个组件提交

依赖：TT-037、TT-044、TT-046、UI-041。  
动作：更新 `components.lock.yaml`、gitlinks、协议版本表和跨语言 golden fixtures。  
验证：`make test-contracts`、组件锁测试。  
提交：`chore: lock output and batch protocol versions`

### INT-009 — 目录去重与覆盖率回归门禁

依赖：TT-041、UI-039。  
动作：引入脱敏的小型 shared-connection fixture；验证 8 requests→1 connection→2 PCAP、所有请求可查询、覆盖计数守恒、v1 可读。  
提交：`test: gate connection deduplication and coverage metrics`

### INT-010 — 自定义 Session root 端到端测试

依赖：UI-038。  
动作：在两个临时用户目录启动/切换 Worker，分别 capture/analyze/list/open；Busy 时尝试切换并确认不破坏任务。  
提交：`test: cover TrafficTracer workspace switching`

### INT-011 — YAML 串行与 Chrome 残留故障注入

依赖：TT-046、UI-041。  
动作：本地 3-target 服务模拟正常、Chrome 残留和分析失败；验证最大并发 1、fail-fast、无关 Chrome 不受影响、resume 从正确序号开始。  
提交：`test: gate serial capture and Chrome cleanup`

### INT-012 — 打包、QuickStart 与升级说明

依赖：INT-008 至 INT-011。  
动作：更新三仓 README、Complete QuickStart、release checklist；构建 deb/AppImage；安装包 smoke 覆盖 tracing 开关已移除、TUN 自动名、自定义 root、批次和 v1 Session。

验证：`make package-linux`、`make smoke-package-linux`，在受控测试环境完成一次 TUN batch。  
完成标准：新用户能从 YAML 到多 Session 分析全程使用 UI，旧 Session 不丢失。  
提交：`docs: publish optimized Complete workflow`

## 7. 推荐实施批次

1. 批次 A（低风险冲突修复）：UI-034、UI-035、UI-036、UI-037、UI-038、INT-010。
2. 批次 B（数据模型与空间优化）：TT-037 至 TT-041、UI-039、INT-009。
3. 批次 C（串行自动化）：TT-042 至 TT-046、UI-040、UI-041、INT-011。
4. 批次 D（冻结与发布）：INT-008、INT-012。

每一批结束后更新 Complete 子模块 gitlink并运行现有 Python、Go、Rust、TypeScript、contract 与 package smoke 全套门禁。批次 A 不要求修改 mihomo；若多 TUN 环境证明仅靠系统枚举无法得到有效名，再单独提出 CORE 任务扩展运行时状态 API。

