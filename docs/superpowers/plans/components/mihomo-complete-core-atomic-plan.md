# Mihomo TrafficTracer Complete Core — 原子实施计划

仓库：`mihomo`
目标分支：`TrafficTracer`
任务前缀：`CORE-*`
范围：追踪能力探测、协议版本、Session 标识、兼容性和构建产物；不改变代理选择、路由或协议实现。

## 1. 兼容原则

- 保留现有 `GET/PATCH /experimental/tracing`。
- PATCH 的 `enabled`、`output` 语义不变。
- 原有事件字段不删除、不改名。
- `schema_version` 为新增必需字段；`session_id` 仅配置后输出。
- 旧 TrafficTracer Python 分析器应继续忽略新字段并正常解析。
- capabilities 经 Clash Verge Unix Socket 调用，不要求 UI 暴露 controller secret。

## 2. 原子任务

### CORE-001 — 固定协议常量

依赖：跨仓 `TT-006` 至 `TT-009` 的版本决定。
文件：新增 `component/tracer/protocol.go`、`protocol_test.go`。
动作：定义 tracing API version、event schema version 和能力名称常量。
测试：断言版本均为正整数，JSON fixture 期望值一致。
完成标准：生产代码不散落魔法数字。
验证：`go test ./component/tracer`。
提交：`feat: define TrafficTracer protocol versions`

### CORE-002 — 增加 capabilities 数据结构

依赖：CORE-001。
文件：`component/tracer/protocol.go`。
动作：定义 Capabilities，包含 TCP、UDP、normalized_flow、outer_conn_id、session_id、shared_outer_flow。
测试：JSON key 和零值测试。
完成标准：能力响应能被稳定序列化且字段命名与 contract 一致。
验证：`go test ./component/tracer`。
提交：`feat: expose TrafficTracer capability model`

### CORE-003 — 增加 capabilities 路由

依赖：CORE-002。
文件：`hub/route/experimental.go`、`experimental_test.go`。
动作：注册 `GET /experimental/tracing/capabilities`，返回版本和能力。
测试：200、content-type、完整字段、方法限制。
完成标准：标准 TrafficTracer 核心通过 Unix/TCP controller 返回同一内容。
验证：`go test ./hub/route`。
提交：`feat: add tracing capabilities endpoint`

### CORE-004 — 扩展 tracing ConfigPatch session_id

依赖：CORE-001。
文件：`component/tracer/tracer.go`、`tracer_test.go`。
动作：ConfigPatch 增加 `SessionID *string`；Tracer 状态受锁保护地保存 session ID。
测试：省略保持、空串清除、非空更新；失败 output patch 不改变 session。
完成标准：patch 保持原子性。
验证：`go test -race ./component/tracer`。
提交：`feat: track tracing capture session id`

### CORE-005 — 在 tracing API 接受和返回 session_id

依赖：CORE-004。
文件：`hub/route/experimental.go`、`experimental_test.go`。
动作：tracingPatch/tracingInfo 增加 session_id；GET 返回当前值；PATCH 转发指针语义。
测试：省略/设置/清除、旧 payload 回归。
完成标准：旧 `{enabled,output}` 客户端无行为变化。
验证：`go test ./hub/route`。
提交：`feat: control tracing session id through API`

### CORE-006 — 为事件增加 schema_version/session_id

依赖：CORE-001、CORE-004。
文件：`component/tracer/tracer.go`。
动作：event 增加 `schema_version` 和可选 `session_id`；在 write 时从锁内快照 session ID，并设置版本。
测试：未配置 session 时字段省略，配置后所有事件携带；race test。
完成标准：事件与 output 切换期间无数据竞争。
验证：`go test -race ./component/tracer`。
提交：`feat: version and tag tracing events`

### CORE-007 — 覆盖全部事件类型的版本字段

依赖：CORE-006。
文件：`component/tracer/tracer_test.go` 或新增 `event_contract_test.go`。
动作：触发 TCP/UDP connect、proxy dial、out/in、close 和错误事件，逐行验证版本/session。
测试：表驱动覆盖所有 EventType。
完成标准：新增事件类型若未进入表会触发维护检查。
验证：`go test ./component/tracer`。
提交：`test: enforce tracing event envelope contract`

### CORE-008 — 增加跨语言 golden fixtures

依赖：CORE-006、TrafficTracer `TT-008`。
文件：`component/tracer/testdata/complete/*.jsonl`、Go contract test。
动作：同步 TCP、UDP、IPv4、IPv6、shared、dial_error fixture；Go 解码并校验 FlowTuple key。
测试：fixture 每行合法且 event_seq 单调。
完成标准：fixture 可直接被 TrafficTracer Python 测试消费。
验证：`go test ./common/traffictrace ./component/tracer`。
提交：`test: add Complete tracing golden events`

### CORE-009 — 增加旧客户端兼容回归

依赖：CORE-005、CORE-006。
文件：`hub/route/experimental_test.go`、`component/tracer/tracer_test.go`。
动作：旧 PATCH、旧 parser 模拟、空 body、stdout output、无 session 模式回归。
测试：明确比较旧字段和值。
完成标准：Complete 扩展不要求所有调用方立即升级。
验证：`go test ./hub/route ./component/tracer`。
提交：`test: preserve legacy tracing API compatibility`

### CORE-010 — 构建并标识 Complete sidecar

依赖：CORE-003 至 CORE-009。
文件：Makefile 或 `scripts/build-complete-core.sh`（由总仓调用时可只在总仓实现）。
动作：构建 Linux amd64 v1 兼容核心，版本信息包含提交；产物供重命名为 `verge-mihomo-tt-<target>`。
测试：`-v`、配置 test、启动隔离 Unix Socket、GET capabilities。
完成标准：脚本不依赖已有 `bin/mihomo-traffictracer-v2`，避免 stale binary。
验证：

```bash
make linux-amd64-compatible
./bin/mihomo-linux-amd64-compatible -v
go test ./common/traffictrace ./component/tracer ./hub/route
```

提交：`build: add reproducible Complete core build`

## 3. API 目标响应

```json
{
  "api_version": 1,
  "event_schema_version": 1,
  "supports_tcp": true,
  "supports_udp": true,
  "supports_normalized_flow": true,
  "supports_outer_conn_id": true,
  "supports_session_id": true,
  "supports_shared_outer_flow": true
}
```

tracing 状态：

```json
{
  "enabled": true,
  "output": "/absolute/session/logs/mihomo_trace.jsonl",
  "session_id": "session-uuid",
  "write_errors": 0,
  "active_sessions": 1
}
```

事件 envelope：

```json
{
  "schema_version": 1,
  "session_id": "session-uuid",
  "event_seq": 42,
  "type": "tcp_proxy_dial",
  "conn_id": "...",
  "outer_conn_id": "...",
  "post_flow": {}
}
```

## 4. 不在本计划范围

- 多租户 tracing writer。
- 同时写多个 output。
- 远程上传日志。
- UI 或 Worker 的任务锁。
- 更改代理协议实现以强行制造独占 post_flow。
- 将 shared 连接伪装为一对一 NAT。

## 5. 核心完成门禁

```bash
gofmt -w component/tracer hub/route
go test -race ./common/traffictrace ./component/tracer ./hub/route
make linux-amd64-compatible
```

启动隔离核心后：

```bash
curl --unix-socket /tmp/test-mihomo.sock \
  http://localhost/experimental/tracing/capabilities
```

只有 capabilities、session patch、事件 envelope 和旧 API 回归全部通过，才更新 Complete 的核心子模块引用。
