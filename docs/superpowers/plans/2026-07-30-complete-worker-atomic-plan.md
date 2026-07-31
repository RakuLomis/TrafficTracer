# TrafficTracer Complete Worker — 原子实施计划

仓库：`TrafficTracer`
目标分支：`Complete`（执行时从 `alpha` 创建）
任务前缀：`TT-*`

## A. 分支、总仓与构建骨架

### TT-001 — 创建 Complete 分支

依赖：无。
动作：确认 `alpha` 与远端同步；保留未跟踪文件不入提交；创建并发布 `Complete`。
验证：`git status --short --branch`、`git log -1`。
完成标准：`Complete` 跟踪 `origin/Complete` 且基线等于预期 alpha 提交。
提交：无功能提交，仅分支操作。

### TT-002 — 增加子模块目录

依赖：TT-001。
文件：`.gitmodules`、`components/mihomo`、`components/clash-verge-rev`。
动作：分别固定核心 `TrafficTracer` 和 UI `feat/traffic-tracer` 已验证提交。
验证：`git submodule status --recursive`。
完成标准：干净 clone 可初始化两个组件。
提交：`chore: add Complete component submodules`

### TT-003 — 增加组件锁文件

依赖：TT-002。
文件：`complete/components.lock.yaml`、`traffictracer/version.py`。
动作：记录组件提交、目标平台和协议版本。
验证：新增 `test/test_component_lock.py`。
完成标准：lock 与 gitlink/本包版本不一致时测试失败。
提交：`chore: add Complete component lock manifest`

### TT-004 — 增加顶层 Makefile 入口

依赖：TT-003。
文件：`Makefile`、`scripts/bootstrap-complete.sh`。
动作：提供 `bootstrap`、`test-python`、`test-contracts`、`dev`、`package-linux` 空骨架和 help。
验证：`make help`、`make test-python`。
完成标准：命令错误时非零退出，不隐藏子命令失败。
提交：`build: add Complete orchestration entrypoints`

### TT-005 — 增加开发环境检查

依赖：TT-004。
文件：`scripts/check-toolchain.sh`。
动作：检查 Python 3.12、Go、Rust、pnpm、dumpcap/tshark、Chrome、PyInstaller。
验证：shell 测试覆盖缺失工具。
完成标准：输出结构化通过/失败列表和修复提示。
提交：`build: add Complete toolchain diagnostics`

## B. 协议与数据模型

### TT-006 — 定义 Job Schema

依赖：TT-001。
文件：`contracts/job.schema.json`、`test/fixtures/contracts/job-valid.json`。
动作：定义 CaptureJobSpec、AnalysisJobSpec、接口、输出和布尔选项。
验证：有效/无效 fixture schema 测试。
完成标准：拒绝相对 output_root、未知 network 和非法时长。
提交：`feat: define Complete job contract`

### TT-007 — 定义 Worker API Schema

依赖：TT-006。
文件：`contracts/worker-api.schema.json`。
动作：定义 request/response/error/notification envelope、方法和错误码。
验证：ID、result/error 互斥和版本测试。
完成标准：stdout 的每一种消息均可由 schema 判定。
提交：`feat: define Worker JSONL protocol`

### TT-008 — 定义 Session 与 Flow Schema

依赖：TT-006。
文件：`contracts/session.schema.json`、`contracts/flow.schema.json`。
动作：固定状态枚举、artifact、组件版本、FlowTuple、shared/match 字段。
验证：golden correlation/manifest fixtures。
完成标准：secret、订阅正文不属于可持久化 schema。
提交：`feat: define Session and Flow contracts`

### TT-009 — 增加 Python 协议验证层

依赖：TT-007、TT-008。
文件：`traffictracer/contracts.py`、`test/test_contracts.py`。
动作：加载 schema、缓存 validator、生成稳定 ValidationError。
验证：全部 fixtures。
完成标准：所有 Worker 边界入参与出参均能调用同一验证器。
提交：`feat: validate Complete protocol messages`

## C. Job 基础设施

### TT-010 — 增加 Job 数据类

依赖：TT-006。
文件：`traffictracer/jobs/models.py`。
动作：实现 CaptureJobSpec、JobState、ProgressEvent、CaptureJobResult。
验证：序列化、枚举和默认值测试。
完成标准：不依赖 YAML 即可构造 Job。
提交：`feat: add typed capture job models`

### TT-011 — 增加 CancellationToken

依赖：TT-010。
文件：`traffictracer/jobs/cancellation.py`。
动作：线程安全 cancel、reason、checkpoint 和 CancelledError。
验证：重复 cancel、并发读取、checkpoint。
完成标准：取消幂等且不会误报普通异常。
提交：`feat: add cooperative job cancellation`

### TT-012 — 增加 ProcessRegistry

依赖：TT-011。
文件：`traffictracer/jobs/process_registry.py`。
动作：登记 Popen、角色、PID、启动时间；按逆序 terminate/kill；幂等清理。
验证：假进程覆盖正常退出、超时、已退出。
完成标准：不再需要模块级 `_active_procs`。
提交：`feat: add job-scoped process registry`

### TT-013 — 增加进度回调器

依赖：TT-010。
文件：`traffictracer/jobs/progress.py`。
动作：规范 stage、单调 progress、节流高频消息。
验证：阶段跳转、非法回退和最终事件。
完成标准：UI 不需要解析日志推断阶段。
提交：`feat: add structured job progress events`

## D. Session 与恢复

### TT-014 — 实现 Session manifest

依赖：TT-008、TT-010。
文件：`traffictracer/session/manifest.py`。
动作：创建、加载、状态转换和时间字段。
验证：合法/非法状态转换。
完成标准：所有终态不可重新进入 capturing。
提交：`feat: add versioned Session manifest`

### TT-015 — 实现原子 JSON 写入

依赖：TT-014。
文件：`traffictracer/session/atomic.py`。
动作：同目录 tmp、flush/fsync、`os.replace`、目录 fsync（可用时）。
验证：写入失败不破坏旧文件。
完成标准：manifest/correlation 不出现半 JSON。
提交：`feat: add atomic artifact persistence`

### TT-016 — 实现 SessionStore

依赖：TT-015。
文件：`traffictracer/session/store.py`。
动作：UUID+时间目录、list/get、artifact 路径、删除前范围校验。
验证：排序、损坏 manifest、路径逃逸。
完成标准：只管理配置 output_root 下的 Session。
提交：`feat: add persistent Session store`

### TT-017 — 实现 recovery journal

依赖：TT-012、TT-016。
文件：`traffictracer/session/recovery.py`。
动作：记录 tracing snapshot 和受管进程身份；启动扫描 nonterminal Session。
验证：模拟 interrupted job。
完成标准：恢复操作幂等，PID 复用时不杀无关进程。
提交：`feat: add interrupted capture recovery journal`

## E. 采集与分析任务化

### TT-018 — 提取 Mihomo 外部连接解析

依赖：TT-010。
文件：`traffictracer/capture/controller_config.py`，调整 `capture/pipeline.py`。
动作：集中解析 Unix/TCP controller 和 secret；返回结构化错误。
验证：安装版/开发版 Clash Verge 配置 fixtures。
完成标准：删除 pipeline 中静默 `except Exception: pass`。
提交：`refactor: isolate external Mihomo controller config`

### TT-019 — 将单域捕获封装为 CaptureJob

依赖：TT-012、TT-013、TT-018。
文件：`traffictracer/capture/job.py`。
动作：将 `_capture_domain` 搬入对象，注入 registry/progress/cancellation/session。
验证：mock 生命周期顺序。
完成标准：库层不安装信号处理器。
提交：`refactor: make capture lifecycle job-scoped`

### TT-020 — 让 tshark/dumpcap 支持取消

依赖：TT-019。
文件：`traffictracer/capture/tshark.py`。
动作：返回受管进程描述；启动后验证存活；停止写尾并报告权限错误。
验证：启动失败、正常停止、强杀。
完成标准：CAPTURE_PERMISSION_DENIED 可被 UI 识别。
提交：`feat: make packet capture cancellable`

### TT-021 — 让 Chrome/CDP 支持取消

依赖：TT-019。
文件：`traffictracer/capture/chrome.py`、`capture/cdp.py`。
动作：等待循环检查 token；取消后先 Browser.close，再 terminate/kill。
验证：导航中取消、collect 中取消、Chrome 自退。
完成标准：取消在 2 秒内进入清理阶段。
提交：`feat: add cooperative Chrome capture cancellation`

### TT-022 — 增加 tracing 恢复持久化

依赖：TT-017、TT-019。
文件：`traffictracer/capture/job.py`。
动作：PATCH 前持久化 previous state；恢复成功后清 journal。
验证：PATCH 后模拟异常和 Worker 终止恢复。
完成标准：正常/异常/取消均恢复 enabled/output。
提交：`feat: persist and restore tracing ownership`

### TT-023 — 提供兼容 run_capture wrapper

依赖：TT-019 至 TT-022。
文件：`capture.py`、`traffictracer/capture/pipeline.py`。
动作：旧 YAML 转换为 JobSpec，CLI 自己处理 SIGINT。
验证：现有 capture tests 加 CLI smoke。
完成标准：旧命令和输出目录语义保持可用。
提交：`refactor: route legacy capture CLI through jobs`

### TT-024 — 分阶段改造分析器

依赖：TT-013、TT-016。
文件：`traffictracer/analyze/job.py`、调整 `analyze/pipeline.py`。
动作：在 CDP、NetLog、Mihomo、correlate、split、write 阶段发进度和 checkpoint。
验证：阶段顺序与中途取消。
完成标准：分析失败保留原始 artifact，manifest 记录错误。
提交：`refactor: expose progress-aware analysis jobs`

### TT-025 — 生成 flow-index 与 summary artifact

依赖：TT-024。
文件：`traffictracer/analyze/artifacts.py`。
动作：基于现有 FlowIndex 生成可分页 JSON、匹配统计和 warnings。
验证：重复 tuple、shared、post_flow null。
完成标准：UI 不必每次重扫 JSONL。
提交：`feat: persist Flow index and analysis summary`

### TT-026 — 保持 analyze/query CLI 兼容

依赖：TT-024、TT-025。
文件：`analyze.py`、`query_flow.py`。
动作：转调 Job/Session 层，维持参数兼容，新增 `--json`。
验证：CLI integration tests。
完成标准：旧自动化脚本无需 UI。
提交：`refactor: route analysis CLIs through Session jobs`

## F. Worker 与诊断

### TT-027 — 实现 environment.diagnose

依赖：TT-018、TT-020、TT-021。
文件：`traffictracer/diagnostics/*.py`。
动作：检查核心 endpoint、TUN、接口、dumpcap、Chrome、目录、磁盘。
验证：每个失败项独立 fixture/mock。
完成标准：结果含 code、severity、message、remediation。
提交：`feat: add Complete environment diagnostics`

### TT-028 — 实现 Worker JSONL framing

依赖：TT-007、TT-009。
文件：`traffictracer/worker/protocol.py`。
动作：逐行 UTF-8 JSON，限制消息大小，stdout 专用于协议。
验证：分片、坏 JSON、超大消息、非 UTF-8。
完成标准：单个坏请求不导致 Worker 崩溃。
提交：`feat: add robust Worker JSONL framing`

### TT-029 — 实现 Worker dispatcher

依赖：TT-027、TT-028。
文件：`traffictracer/worker/dispatcher.py`。
动作：实现 hello、diagnose、job/session/flow 方法路由和稳定错误。
验证：未知方法、无效 params、重复 ID。
完成标准：所有 response 通过 schema。
提交：`feat: dispatch Complete Worker requests`

### TT-030 — 实现单任务 JobManager

依赖：TT-023 至 TT-025、TT-029。
文件：`traffictracer/worker/job_manager.py`。
动作：后台线程执行单 capture/analyze，发送通知，拒绝第二采集。
验证：start/get/cancel/completed/failed。
完成标准：BUSY 错误稳定且取消幂等。
提交：`feat: manage Worker capture and analysis jobs`

### TT-031 — 实现 Worker 启动恢复

依赖：TT-017、TT-030。
文件：`traffictracer/worker/recovery.py`。
动作：启动扫描、清理受管进程、恢复 tracing、标记 interrupted。
验证：故障注入测试。
完成标准：恢复失败可见且不阻止读取历史 Session。
提交：`feat: recover interrupted Worker sessions`

### TT-032 — 增加 Worker 入口

依赖：TT-030、TT-031。
文件：`traffictracer_worker.py`。
动作：严格 stdout/stderr、SIGTERM 优雅关闭、hello 握手。
验证：subprocess protocol smoke。
完成标准：EOF/SIGTERM 后不残留活动任务。
提交：`feat: add TrafficTracer Worker executable`

## G. 打包、文档和发布

### TT-033 — 增加 PyInstaller spec

依赖：TT-032。
文件：`packaging/traffictracer-worker.spec`、`scripts/build-worker.sh`。
动作：打包依赖和 schema，生成目标命名 sidecar。
验证：在无 venv 的临时环境执行 hello/diagnose。
完成标准：二进制不依赖源码目录。
提交：`build: package TrafficTracer Worker sidecar`

### TT-034 — 实现统一 dev 构建

依赖：TT-002、TT-033、UI-006。
文件：`scripts/build-core.sh`、`build-ui.sh`、Makefile。
动作：构建核心、Worker，注入 Clash sidecar，启动 pnpm dev。
验证：`make dev`。
完成标准：不会复用 stale sidecar，打印组件哈希。
提交：`build: add one-command Complete development build`

### TT-035 — 实现 Linux package wrapper

依赖：TT-034、UI-029。
文件：`scripts/package-linux.sh`。
动作：固定目标、构建 sidecars、调用 Tauri build、收集 deb/AppImage/checksum。
验证：artifact 存在且可列出内含二进制。
完成标准：任一组件失败时不产出假成功包。
提交：`build: add Complete Linux packaging pipeline`

### TT-036 — 更新 Complete README

依赖：全部 MVP 任务。
文件：`README.md`、`docs/complete/`。
动作：安装、开发、UI 流程、权限、故障恢复、协议版本、非目标。
验证：干净 VM 按文档执行。
完成标准：不依赖未记录的 sibling repo 或手工复制。
提交：`docs: publish TrafficTracer Complete quickstart`

## H. Worker 完成门禁

```bash
python -m pytest -q
python -m compileall -q traffictracer traffictracer_worker.py
make test-contracts
scripts/build-worker.sh
./dist/traffictracer-worker-x86_64-unknown-linux-gnu --self-test
```

全部通过后才允许 UI 集成依赖该 Worker 提交。
