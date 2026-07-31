# TrafficTracer Complete — 跨仓原子实施主计划

日期：2026-07-30
目标分支：`TrafficTracer/Complete`
首发范围：Linux x86-64、单采集任务、系统 Chrome、系统 dumpcap/tshark、Clash Verge 管理核心与 TUN

## 1. 计划使用规则

- 一个原子任务只修改一个仓库，目标工作量控制在 0.5–1.5 天。
- 每个任务必须同时交付实现、测试和必要文档；测试未通过不得进入下一依赖任务。
- 每个任务原则上对应一个提交，提交信息使用任务中给出的建议文本。
- 跨仓协议先更新 `TrafficTracer/contracts`，再分别实现核心、Worker 和 UI。
- `Complete` 总仓通过子模块 gitlink 和 `components.lock.yaml` 固定三个兼容提交。
- 不在 GUI 或 Worker 中执行拼接后的 shell 字符串，不以 root 运行 GUI/Worker。

## 2. 项目计划索引

| 项目 | 文档 | 任务前缀 |
|---|---|---|
| TrafficTracer 总仓/Worker | `docs/superpowers/plans/2026-07-30-complete-worker-atomic-plan.md` | `TT-*` |
| mihomo 核心 | `docs/superpowers/plans/components/mihomo-complete-core-atomic-plan.md` | `CORE-*` |
| clash-verge-rev UI/编排 | `docs/superpowers/plans/components/clash-verge-complete-ui-atomic-plan.md` | `UI-*` |
| 跨仓集成门禁 | 本文 | `INT-*` |

## 3. 固定协议版本

| 协议 | MVP 版本 |
|---|---:|
| Worker JSONL API | 1 |
| Session manifest | 1 |
| Flow result | 1 |
| Mihomo tracing API | 1 |
| Mihomo event schema | 1 |

版本不匹配必须产生明确错误，禁止静默降级。旧 JSONL 仍由离线分析器兼容，但 Complete 实时任务要求上述版本。

## 4. 里程碑与依赖

### M0 — 可重复基线

完成：`TT-001` 至 `TT-005`。

验收：

- `Complete` 从 `alpha` 创建。
- 两个子模块固定到已验证分支提交。
- `make bootstrap` 和 `make test-python` 可运行。
- 工作区不依赖 `../mihomo` 或 `../clash-verge-rev` 的偶然状态。

### M1 — 协议冻结

完成：`TT-006` 至 `TT-009`、`CORE-001`。

验收：

- 四份 JSON Schema 有版本和 golden fixtures。
- Python 能验证 Job、Worker 消息、Session 和 Flow。
- 无协议字段仍处于口头约定状态。

### M2 — 可取消的 Worker

完成：`TT-010` 至 `TT-032`。

验收：

- 旧 `capture.py`、`analyze.py`、`query_flow.py` 不回归。
- Worker 可通过 stdin/stdout 接收请求、报告进度并取消。
- 正常、异常和取消都能停止子进程、恢复 tracing。
- Worker 重启能处理 interrupted Session。

### M3 — 核心能力可探测

完成：`CORE-002` 至 `CORE-010`。

验收：

- `/experimental/tracing/capabilities` 返回稳定版本。
- PATCH tracing 支持可选 `session_id`。
- 每条新事件包含 `schema_version`，有 session 时包含 `session_id`。
- 旧 GET/PATCH 行为和旧字段不变。

### M4 — 桌面后端编排

完成：`UI-001` 至 `UI-014`。

验收：

- Tauri 能打包、启动、监控和关闭 Worker sidecar。
- Worker 协议乱序、坏 JSON、退出均有稳定错误。
- Rust commands 覆盖诊断、采集、取消、Session、分析和 Flow 查询。

### M5 — 最小完整 UI

完成：`UI-015` 至 `UI-029`。

验收：

- UI 可完成环境诊断、开始/取消采集、自动分析、Session 列表、Flow 查询。
- 捕获期间禁止破坏任务的核心/profile/TUN/tracing 操作。
- 中英文文案和错误提示完整。

### M6 — 一键构建与发布

完成：`TT-033` 至 `TT-036`、`UI-030` 至 `UI-033`、全部 `INT-*`。

验收：

- `make dev` 启动完整开发环境。
- `make package-linux` 生成 deb/AppImage。
- 安装包内含 `verge-mihomo-tt` 和 `traffictracer-worker`。
- 干净 Linux x86-64 环境完成端到端冒烟测试。

## 5. 跨仓原子任务

### INT-001 — 锁定协议实现提交

依赖：M2、M3、M5。
修改：`complete/components.lock.yaml` 与两个子模块 gitlink。
动作：记录核心、UI、Worker 提交和五个协议版本。
验证：脚本比较 gitlink、lock 文件和二进制 `hello/capabilities` 返回值。
完成标准：任一不一致时构建失败。
提交：`chore: lock TrafficTracer Complete component versions`

### INT-002 — 建立跨语言 golden contract gate

依赖：TT-009、CORE-009、UI-008。
修改：`scripts/test-contracts.sh`。
动作：同一组 TCP/UDP/IPv4/IPv6/shared/error fixtures 依次通过 Python、Go、Rust 解析测试。
验证：`make test-contracts`。
完成标准：删除/改名任何必需字段都会使 CI 失败。
提交：`test: add cross-component tracing contract gate`

### INT-003 — 建立无特权 DIRECT 集成测试

依赖：M3、M4。
修改：`test/e2e/direct/`、`scripts/test-e2e-direct.sh`。
动作：启动隔离 Unix Socket 核心、Worker 和本地 HTTP 服务，不开启 TUN，验证 tracing 状态保存/恢复及分析输出。
验证：`make test-e2e-direct`。
完成标准：生成有效 manifest、trace、correlation 和可查询 Flow。
提交：`test: add unprivileged Complete direct-mode e2e`

### INT-004 — 建立特权 TUN 集成测试

依赖：INT-003、UI-024。
修改：`test/e2e/tun/`、自托管 Runner 工作流。
动作：在隔离测试机开启 TUN，验证双接口 pcap 与代理前后 Flow。
验证：`make test-e2e-tun`。
完成标准：tun/physical pcap 非空且至少一条 exact Flow 有完整 post_flow。
提交：`test: add privileged TUN capture e2e`

### INT-005 — 取消与恢复故障注入

依赖：TT-024、UI-013。
修改：`test/e2e/recovery/`。
动作：分别在 Chrome、dumpcap、分析阶段取消；强制终止 Worker；重启并恢复。
验证：`make test-recovery`。
完成标准：无残留受管子进程，tracing 恢复，Session 为 canceled/interrupted。
提交：`test: cover cancellation and crash recovery`

### INT-006 — 安装包冒烟测试

依赖：M6。
修改：`scripts/smoke-package-linux.sh`。
动作：安装包后检查 sidecars、服务 helper、核心发现、Worker hello 和 tracing capabilities。
验证：CI 在干净 VM 执行。
完成标准：无需源码目录即可启动 UI 并通过环境诊断。
提交：`test: add Linux package smoke test`

### INT-007 — 发布候选审计

依赖：INT-001 至 INT-006。
修改：`docs/release-checklist.md`。
动作：检查许可证、第三方依赖、secret 脱敏、路径权限、二进制校验和、SBOM。
验证：人工签字加 CI artifact 检查。
完成标准：所有阻断项关闭。
提交：`docs: add Complete release audit checklist`

## 6. CI 流水线

建议拆分为：

```text
python-unit
python-worker-contract
mihomo-unit
clash-typescript
clash-rust
cross-contract
unprivileged-e2e
linux-package
privileged-tun-e2e (self-hosted/manual)
```

普通 PR 必须通过前七项；特权 TUN 可由受控 Runner 或发布门禁触发。

## 7. 原子提交纪律

- 不在一个提交中同时更新 Python、Go 和 Rust/TS；通过后续 lock 提交组合。
- 重构提交不改变外部行为；功能提交单独跟随。
- 每个协议字段先有 schema/fixture，再有生产代码。
- 每个进程启动点必须在同一任务或下一紧邻任务补清理测试。
- UI 乐观更新必须有回滚测试。
- 任何吞掉异常的 `except Exception: pass` 都要替换为结构化警告或明确注释。

## 8. MVP 非目标

- Windows/macOS。
- 多个并发采集任务。
- 内置 Chromium、Wireshark。
- 远程 Worker 或远程 controller。
- 实时逐包瀑布图。
- 云同步和大规模数据库检索。
- 自动提升 GUI/Worker 权限。

## 9. 最终 Definition of Done

- 新用户从 `git clone --recurse-submodules` 开始，一条命令准备环境。
- UI 完成 profile 导入、TT 核心选择、节点测速/选择、TUN、采集、分析和 Flow 查询。
- 输入代理前五元组，UI 返回所有对应会话的 post_flow。
- shared 连接有明显警示，不宣称一对一映射。
- 任务取消、Worker 崩溃、应用重启后状态可恢复。
- GUI/Worker 普通用户运行，权限诊断可操作。
- 旧 CLI 和旧日志分析保持兼容。
- deb/AppImage 在干净 Linux x86-64 主机通过冒烟测试。
