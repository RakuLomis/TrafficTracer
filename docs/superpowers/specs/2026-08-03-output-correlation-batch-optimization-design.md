# TrafficTracer Complete 输出、关联与批处理优化设计

日期：2026-08-03  
适用分支：`TrafficTracer/Complete`、`clash-verge-rev/feat/traffic-tracer`、`mihomo/TrafficTracer`

## 1. 目标与约束

本轮优化同时解决五类问题：

1. 简化 Session 输出目录，避免按 URL 重复导出相同连接的 PCAP。
2. 在不虚构关联、不丢弃原始证据的前提下，提高并准确表达请求、连接和代理前后 Flow 的关联覆盖率。
3. 删除 Clash Verge Settings 中与 Complete 编排冲突的历史手动 tracing 开关。
4. 统一 TUN “配置名、核心有效名、系统实际接口名”的语义，并支持切换任意合法 Session 输出目录。
5. 从目标 YAML 串行执行多组 URL/domain 的捕获和分析，且每组之间必须确认本任务拥有的 Chrome 进程已全部退出。

硬约束：

- `tun.pcap`、`physical.pcap`、mihomo trace、NetLog、CDP 原始记录仍是证据源，不以节省空间为由删除。
- 一个浏览器请求可以与其他请求共享一条连接；数据模型必须表达多对一，不能强行制造“一 URL 一 Flow”。
- 不并行运行多个捕获任务，不通过全局 `pkill chrome` 清理浏览器，不影响用户已有 Chrome/Clash Verge/mihomo 进程。
- 新版本必须能读取旧 Session；不自动原地改写旧 Session。

## 2. 源码与样本检查结论

### 2.1 目录复杂和空间重复的直接原因

当前 `split_flows_v2()` 遍历每一条 URL 关联记录，以 `_sanitize_name(flow.url)` 作为目录，再分别运行 tshark 导出 `pre_proxy.pcap` 和 `post_proxy.pcap`。这造成两个问题：

- URL 中的路径分隔符被保留，因此会形成多层、不可预测且可能过长的目录。
- HTTP/2、HTTP/3 或 keep-alive 下，多条 URL 共用同一五元组；程序仍会为每条 URL 重复导出整条连接的相同 PCAP。

对样本 Session `20260803T045446.025262Z_20057efa-547e-41ce-8373-c51dee45b152` 的检查结果：

- `flows/` 中有 28 个派生 PCAP，但按内容只有 6 个唯一文件。
- 派生 PCAP 总计 48,108,928 bytes，唯一内容约 9,636,292 bytes，约 79.97% 为重复数据。
- 15 条浏览器 URL 关联只对应 3 组唯一代理前/后连接。
- 相同 URL 再次出现时还可能落入同一路径，存在覆盖或含义混淆风险。

结论：当前目录是“请求视角命名、连接视角内容”，两种粒度混在一起才导致复杂和重复。

### 2.2 关联覆盖率不能只看一个百分比

该样本中 CDP 记录约 250 个请求，而 `correlation.json` 只有 15 个请求级关联；核心 trace 则记录 99 条逻辑流，其中 78 条有代理后 Flow，21 条缺少代理后 Flow。两组分母含义不同，不能合并成一个模糊的“覆盖率”。

必须分别报告：

- 浏览器请求总数、具备网络端点信息的请求数、关联到连接的请求数。
- 唯一浏览器传输连接数、关联到 mihomo 逻辑流的连接数。
- mihomo 逻辑流总数、完整代理前 Flow 数、完整代理后 Flow 数。
- exact、legacy、endpoint、host/time fallback、ambiguous、unmatched 的数量和原因。
- 多请求复用连接数、一个代理前 Flow 对应多个逻辑流的歧义数。

对视频站点尤其要保留跨站 CDN 请求。`relation=cross_site` 只是关系标签，不能作为过滤条件；否则会把真正承载视频数据的 CDN 连接排除。

### 2.3 Settings 中的 TrafficTracer 开关属于历史手动控制入口

`setting-clash.tsx` 中的 TrafficTracer 项通过 `use-tracing.ts` 调用 Tauri command，再直接操作 mihomo `/experimental/tracing`。它不是 Complete 的 Capture Job 开关。

Complete Capture Job 已负责：

1. 读取此前 tracing 状态。
2. 将 tracing 输出绑定到当前 Session。
3. 在正常、失败、取消和恢复流程中还原此前状态。

Settings 手动开关会在任务外留下 enabled/output 状态，形成两个所有者并引发状态漂移。捕获锁只能防止任务进行时修改，不能消除任务前后的冲突。因此 Complete 产品中应删除这个手动 UI 入口；保留 mihomo tracing API 和 Worker 内部调用能力，供 Capture Job 与解耦 CLI 使用。

### 2.4 `Meta` 与 `Mihomo` 不一致的真实来源

mihomo 核心配置的 `tun.device` 默认是空字符串。Linux 创建 TUN 时，如果名称为空或无效，`listener/sing_tun/server.go` 使用 `InterfaceName = "Meta"`，并通过 `CalculateInterfaceName` 处理重名，所以实际名称可能是 `Meta`、`Meta0` 等。

Clash Verge 的 TUN Settings 则在前端为空时显示/保存回退值 `Mihomo`。这个值是 UI 自己的默认值，不是当前核心的默认值。

TrafficTracer 表单并没有把 `Meta` 写死为唯一真值；它会从系统接口列表中优先选择名称匹配 `meta|mihomo|clash|utun|tun` 的实际接口。用户看到 `Meta`，通常是因为系统当时确实存在该接口。

因此三个概念必须分开：

- `configured_device`：YAML/Clash Verge 配置中显式填写的名称，可为空。
- `effective_device`：mihomo 根据默认值和重名规则最终选择的名称。
- `capture_interface`：操作系统中 tshark 实际可打开的接口名称。

捕获的最终真值是 `capture_interface`；设置页不得再用虚构的 `Mihomo` 占位值冒充有效值。

### 2.5 自定义 Session output directory 失败的直接原因

Worker 启动时以 `--output-root` 构造单一 SessionStore，`WorkerManager` 将该路径保存在 `session_root`。之后 UI 修改目录，`tt_get_environment` 等命令调用 `require_session_root()`，发现新旧路径不同便直接报错，并提示先停止 Worker。

所以问题不是只能写应用数据目录，而是缺少“空闲 Worker 切换工作区”的编排。修复应在 Worker 空闲时优雅重启并绑定新 root；Busy 时明确拒绝，不能在任务中途切换。

此外还应在启动前完成：绝对路径校验、目录创建、规范化、可写探针、可用空间检查和等价路径比较。

### 2.6 当前 Chrome 清理不足以作为批处理屏障

单次 Capture Job 已登记 Chrome 启动器进程，并在 finally 中 terminate/kill 和 wait；这能覆盖主进程。但 Chrome 是多进程程序，当前 `Popen` 未建立独立进程组，清理报告也没有验证同一个 `--user-data-dir` 对应的派生进程是否全部退出。

批处理不能只检查启动器 PID。应以“本任务专属 profile + 进程组/进程身份”为所有权边界，只清理由本任务创建的进程，并在开始下一目标前通过 PID/启动时间/profile 参数确认没有残留。

## 3. 目标输出模型

### 3.1 新 Session 布局

Complete 的一个 Capture Job 对应一个 Session，因此不再把 domain、URL 和 `run_1` 重复编码进目录。建议 Session schema v2 使用：

```text
<output-root>/
  <session-id>/
    manifest.json
    capture/
      tun.pcap
      physical.pcap
      mihomo.jsonl
      netlog.json
      cdp.json
      proxy.json
    analysis/
      summary.json
      correlation.json
      flow-index.json
      pcap-index.json
      connections/
        c_<stable-id>/
          metadata.json
          pre.pcap
          post.pcap
```

说明：

- domain、URL、network、目标配置摘要、批次 ID 和序号写入 manifest，不进入目录层级。
- `capture/` 保存不可替代的原始证据。
- `analysis/connections/` 每个唯一连接最多保存一份 pre 和一份 post PCAP。
- `correlation.json` 保存请求到连接的多对一/一对多关系；URL 不再作为文件名。
- `pcap-index.json` 保存连接 ID、过滤表达式、源 PCAP、派生文件、包数、字节数、生成状态和错误。
- 所有 JSON 使用临时文件加原子 rename；派生 PCAP 先写 `.partial`，tshark 成功且文件可读后再 rename。

### 3.2 稳定连接 ID

连接 ID 不应暴露完整 URL，也不能仅依赖数组序号。规范输入依次取：

1. `conn_id`/`outer_conn_id`（如果存在）。
2. 规范化的 pre/post Flow key、协议和方向。
3. 捕获开始时间窗口内的连接序号，用于解决完全相同五元组被复用后的碰撞。

对规范输入计算 SHA-256，目录使用前 16 个十六进制字符，如 `c_7e13c7a1f2ac09bd`；完整规范键保存在 `metadata.json`。若检测到哈希碰撞，延长摘要而不是覆盖目录。

### 3.3 请求与连接分离

`correlation.json` 至少包含两个集合：

- `connections[]`：唯一连接及 pre/post Flow、匹配等级、共享/歧义信息。
- `requests[]`：`request_id`、URL、resource/target type、时间范围、`connection_ids[]`、匹配状态和原因。

这样 8 个 URL 共用一个 HTTP/2 连接时只产生一组 PCAP，但 8 条请求信息均被保留。查询 URL 时跳转到连接；输入代理前五元组时仍通过 `flow-index.json` 返回全部逻辑流和代理后 Flow。

### 3.4 拆分策略

提供三种明确模式：

- `none`：只保留原始 PCAP 和索引。
- `unique_connections`：为每个唯一关联连接导出一次，作为 Complete 默认值。
- `on_demand`：首次从 UI 打开某连接时导出并缓存。

首轮实现 `none` 与 `unique_connections`；`on_demand` 可以后置。无论何种模式，`flow-index.json` 和关联信息必须完整生成。

## 4. 关联覆盖优化

### 4.1 分层匹配而非单一 fallback

匹配链按可信度执行，并保留所有候选：

1. CDP request/network ID → NetLog source/socket → 完整传输五元组。
2. 完整传输五元组 → mihomo `pre_flow.key` exact 匹配。
3. CDP remote endpoint + 协议 + 时间重叠 → mihomo connect endpoint。
4. host/SNI + 协议 + 时间窗 → 候选集合，仅当唯一时自动关联。
5. 多候选时标记 `ambiguous`，输出候选及评分，不选第一个冒充准确结果。

当前 `correlate_cdp_direct()` 在 endpoint 有多个候选时直接取 `candidates[0]`，应改为时间窗与协议评分，并显式处理歧义。UDP/QUIC 的 host fallback 同样不能默认取首条连接。

### 4.2 时间与复用信息

为请求、NetLog socket、mihomo connect/proxy_dial/close 统一标准化 UTC 时间或相对 monotonic offset。关联评分至少考虑：

- 请求时间是否落在连接生命周期内。
- endpoint 与协议是否一致。
- CDP `connectionId`/`connectionReused` 是否一致。
- pre_flow 是否 exact。
- 同一连接承载多个 request 是否符合复用事实。

### 4.3 覆盖率输出

`summary.json` 新增 `coverage`：

```json
{
  "browser_requests": {"total": 250, "matched": 0, "ambiguous": 0, "unmatched": 0},
  "transport_connections": {"total": 0, "matched_to_core": 0},
  "core_logical_flows": {"total": 99, "with_pre": 0, "with_post": 78},
  "match_methods": {"exact": 0, "endpoint_time": 0, "host_time": 0},
  "unmatched_reasons": {}
}
```

所有计数必须可由 `correlation.json`/`flow-index.json` 重新计算。UI 同时显示分子和分母，禁止只显示一个容易误解的百分比。

## 5. TUN 名称统一方案

1. 将 Clash Verge Linux 空值展示从 `Mihomo` 改为“自动（核心默认 Meta）”，不要在仅打开设置页时写回配置。
2. 若用户显式输入 device，则保存该值；若选择自动，则保持 YAML 中 device 为空，让核心执行默认/重名规则。
3. TrafficTracer 环境诊断返回 `configured_device`、接口候选列表和最终 `capture_interface`。
4. 捕获开始前重新枚举接口：优先选择与显式配置完全相同者；自动模式下选择已启用且符合核心 TUN 特征的实际接口。
5. 0 个候选时阻断并给出开启 TUN/安装服务提示；多个候选时要求用户选择，不静默取第一个。
6. 捕获请求保存最终接口名到 Session manifest，确保事后可追溯。

首轮不强制修改 mihomo 对外 API。若系统枚举无法在多 TUN 环境可靠识别，再以向后兼容字段补充核心“有效 TUN 名称”查询；这应作为独立后续任务，不能把猜测值写成真值。

## 6. 任意输出目录切换方案

在 Tauri `WorkerManager` 增加 `ensure_session_root()`：

- requested 与当前 root 规范化后相同：复用 Worker。
- Worker Stopped/Failed：创建并校验目录，再按 requested 启动。
- Worker Ready 且 root 不同：发送 `worker.shutdown`，等待任务和子进程清理，启动绑定新 root 的 Worker，再执行 hello/recovery/diagnose。
- Worker Busy：拒绝切换，返回结构化 `SESSION_ROOT_BUSY`，UI 保留旧值。

目录校验：

- 必须为绝对路径。
- 不存在时按当前桌面用户创建，权限 `0700`；不得调用 sudo。
- 解析 `.`、`..`、符号链接后的等价路径，避免同一路径被误判为不同 root。
- 创建并 fsync 一个小型探针文件后删除，以验证真实写权限；同时报告可用空间。
- Session 路径解析继续限制在 root 直接子目录，防止路径逃逸。

切换成功后 Session 列表只显示新 root 下内容；UI 明示这是“工作区切换”，而不是移动旧 Session。旧目录不删除、不迁移。

## 7. YAML 串行批处理方案

### 7.1 编排归属

批处理必须由 Python Worker 承担，不由 React 页面用循环拼接单任务。Worker 编排可在 UI 刷新、事件延迟时保持一致的锁、取消和恢复语义。

### 7.2 执行顺序

一次 Batch Job 固定加载时的 YAML SHA-256 和规范化 targets 快照，然后严格执行：

```text
target N capture
  → 停止 CDP/关闭浏览器
  → 清理本任务 Chrome 进程组
  → Chrome quiescence 校验
  → 停止抓包并恢复 tracing
  → analyze 当前 child Session
  → 写入 child 结果与 batch checkpoint
  → target N+1
```

同一时刻最多存在一个 child Capture/Analysis Job。Complete capture lock 在整个 Batch 生命周期内持有，防止中途切换 profile、核心、代理节点、TUN 和 tracing。

### 7.3 Chrome 所有权与安静屏障

- 每个 child 使用不可复用的 job-owned user-data-dir。
- Linux 启动 Chrome 时建立独立 session/process group，并记录 PID、进程启动时间、PGID、profile 参数。
- 优先 CDP `Browser.close`，然后等待；超时只 terminate/kill 已登记的进程组。
- 清理后再次检查该 profile 对应的受管 PID，不扫描或终止其他 profile 的 Chrome。
- 任何受管 Chrome 残留都使当前 child 失败，并阻止下一个 target 启动。
- 默认清理 job-owned profile；调试选项可保留，但不得影响进程判定。

### 7.4 失败、取消与恢复

- MVP 默认 fail-fast：任一 target 捕获、清理或分析失败后停止批次，已完成 Session 保留。
- 用户取消时取消当前 child，等待其完成清理，不再启动下一项。
- `batch-manifest.json` 原子记录目标快照、当前序号、child Session IDs、各阶段状态与错误。
- Worker 崩溃恢复后将运行中的 batch 标记 `interrupted`；不自动重新访问 URL，由用户从失败目标手动继续。
- 继续执行仍使用原始快照与 SHA；若用户选择重新加载已变化 YAML，则创建新 batch。

### 7.5 UI

- YAML 预览支持“全部目标”或勾选子集，显示预计串行数量和顺序。
- 单目标仍走原 Capture Job，避免扩大简单路径。
- 批量页显示 `3/12`、当前 domain/URL、capture/cleanup/analyze 阶段、已完成 child Session 链接。
- 批处理期间禁用所有会改变代理、TUN、核心、输出 root 和 tracing 状态的控件。

## 8. 兼容与迁移

- 新 Session 写 schema v2；分析器先识别 manifest schema，再路由 v1/v2 reader。
- v1 的 `captures/<domain>/<run>`、`logs/`、`results/flows/` 继续只读展示和查询。
- 对旧 Session 执行“重新分析”时默认把 v2 派生结果写到新的 analysis generation，不删除旧 flows；用户确认后才可清理重复派生物。
- 构建锁同步更新 Worker API、Job/Session/Flow schema 与三个组件提交。
- QuickStart 增加自动 TUN 名称、自定义工作区、批处理和旧 Session 兼容说明。

## 9. 验收指标

- 样本 Session 重新分析后，相同的 3 组唯一连接最多产生 6 个 pre/post PCAP，不再产生 28 个重复文件。
- 请求 URL、request ID、连接共享关系、完整 pre/post Flow 与原始 PCAP 均可查询。
- 派生 PCAP 内容重复率目标低于 5%；重复只能来自确有不同 connection identity 但数据相同的可解释情况。
- Settings 不再存在可写的 TrafficTracer/tracing 开关，Capture Job 仍能启用并恢复核心 tracing。
- TUN 自动模式显示核心默认 `Meta` 的语义，Session 保存实际抓取接口；配置/实际不一致时有明确诊断。
- Worker 空闲时可在两个用户可写绝对目录间往返切换并分别列出 Session；Busy 时切换被安全拒绝。
- 12 个 YAML targets 按固定顺序完成 capture→Chrome 清理→analyze，测试证明最大并发 child 数为 1，且无受管 Chrome 残留。

