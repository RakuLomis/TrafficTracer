# Bilibili 网络可达性修复实施方案

日期：2026-08-08
目标分支：TrafficTracer `Complete`
涉及组件：TrafficTracer、clash-verge-rev、mihomo-traffictracer
基线批次：`20260807-142927-915`

## 1. 结论与问题边界

最新批次已经证明 TrafficTracer 的捕获、规范化和关联链路正常：

- 五个目标均完成，所有 Session 一致性检查为 `passed`；
- Bilibili 的 54 条页面 transport connection 全部匹配到 Mihomo pre-flow；
- 48 条 Bilibili DIRECT 连接建立了完整 post-flow；
- 6 条连接在 Mihomo `dial` 阶段失败，因出口 socket 从未建立而没有 post-flow；
- 失败为 IPv4 TCP 超时和 IPv6 `network is unreachable`，不是 PCAP、Fake-IP 或关联算法丢失。

失败集中在：

- `i1.hdslb.com`：4 条；
- `upos-sz-staticcos-cmask.bilivideo.com`：2 条。

成功的 Bilibili DIRECT 流量包括 `www.bilibili.com`、`api.bilibili.com`、
`i0.hdslb.com`、`i2.hdslb.com` 和多个 `bilivideo.com` 视频 CDN。因此问题是特定
DNS 结果/CDN 路径不可达，而不是 Bilibili 整体不可达。当前代理快照还显示
`Bilibili -> DIRECT`，所以这些失败没有代理出口兜底。

## 2. 修复目标

1. 保留 Bilibili 可用的本地/校园网 DIRECT CDN，不把全部流量无条件改为代理。
2. 对不可达的精确域名提供显式、可撤销的代理恢复策略。
3. 在捕获前识别 IPv6 无默认路由、DNS 结果不可达和 TCP 拨号超时。
4. 在结果中区分“关联失败”和“出口拨号失败”，避免把不存在的 post-flow 计作关联缺陷。
5. 不硬编码 CDN IP，不静默改写用户导入的 YAML，不影响 YouTube 等现有规则。

非目标：

- 不为拨号失败伪造 post-flow；
- 不在 TrafficTracer 分析阶段重试业务请求；
- 不通过延长抓包时间掩盖固定的 5 秒拨号超时；
- 不自动关闭整个系统的 IPv6，除非确认主机没有可用 IPv6 默认路由并由用户确认。

## 3. 总体修复路径

```text
捕获前可达性检查
  ├─ 域名解析结果与解析器来源
  ├─ IPv4/IPv6 路由能力
  └─ TCP 443 探测
          │
          ├─ DIRECT 可达 ────────────────> 保持 Bilibili DIRECT
          │
          └─ 精确 CDN 域名不可达
                 ├─ DNS/IPv6 配置可修复 ─> 修正后复测 DIRECT
                 └─ 路径仍不可达 ────────> 精确域名走 Recovery 代理组

分析结果
  ├─ transport 未匹配             -> correlation_unmatched
  ├─ 已匹配但 dial_error          -> egress_not_established
  └─ socket 已建立且有 post-flow  -> pipeline_complete
```

## 4. P0：立即恢复与 A/B 定位

### BNET-001：保存可复现基线

从最新 Session 提取最小、脱敏的诊断 fixture，只保留：域名、A/AAAA 候选、规则策略、
terminal status、error class、pre-flow 是否完整和 post-flow 是否存在。不要提交完整 URL
查询串、Cookie、NetLog 或用户节点名称。

建议文件：

- `test/fixtures/reachability/bilibili-direct-timeout.json`
- `test/test_terminal_error_classification.py`
- `test/test_connection_artifacts.py`

验收：fixture 能稳定重现 `exact_pre_flow + dial_error + post_flow=null`，并证明它不是
`correlation_unmatched`。

### BNET-002：三组串行 A/B 实验

使用相同 `sites.yaml`、相同三个 Bilibili 页面和相同 15 秒窗口，串行执行：

1. `DIRECT-baseline`：保持当前配置；
2. `DIRECT-network-fix`：仅应用确认后的 DNS/IPv6 修正；
3. `targeted-proxy-recovery`：仅将两个失败域名切到现有上游代理组。

每个实验开始前确认上一轮 Chrome/CDP 进程已正常退出；不要并行捕获。记录 DNS 答案、
路由、探测耗时、页面请求数、dial error 数和完整 pre/post pipeline 数。

立即验证可先在 Clash Verge 中把现有 `Bilibili` 组从 `DIRECT` 临时切换到可用代理。
若 6 条失败消失，即可确认出口路径而非 TrafficTracer 是主因；该全组切换只用于诊断，
不作为最终默认配置。

## 5. P1：DNS、IPv6 与物理路由修复

### BNET-003：扩展只读可达性诊断

在现有 `environment.diagnose` 基础上增加可选的目标域名诊断，而不是在捕获流程中散落
shell 命令。建议实现位置：

- `traffictracer/diagnostics/environment.py`
- `traffictracer/worker/services.py`
- `test/test_diagnostics.py`
- `src-tauri/src/cmd/traffic_tracer.rs`
- `src/components/traffic-tracer/environment-card.tsx`

每个域名返回：

- 系统与 Mihomo 配置的解析器摘要；
- A/AAAA 候选地址，不记录无关 DNS 数据；
- IPv4/IPv6 默认路由是否存在；
- 目标地址 TCP 443 的成功、超时、拒绝或无路由分类；
- 推荐动作，但不自动更改配置。

探测必须具有 3～5 秒单目标超时、总时间上限和取消能力。UI 明确标注探测会产生少量
网络连接；只有用户点击“测试目标可达性”时执行。

### BNET-004：DNS 解析器定向修正

先比较系统/本地 ISP DNS 与当前 Mihomo nameserver 对以下域名的结果：

- `i1.hdslb.com`
- `i0.hdslb.com`（成功对照）
- `i2.hdslb.com`（成功对照）
- `upos-sz-staticcos-cmask.bilivideo.com`

如果系统或校园网 DNS 能返回可达的本地 CDN，而 Mihomo 当前解析器返回不可达的
`43.137/43.141/43.171` 地址，则在用户 YAML 中为 `+.hdslb.com`、
`+.bilivideo.com` 配置 `nameserver-policy`，指向已验证可用的本地解析器。规则只记录
解析器地址，绝不固定 CDN A/AAAA 地址。

如果不同解析器都返回相同不可达地址，则停止调整 DNS，进入 BNET-006。避免通过反复
切换公共 DNS 制造不可复现结果。

### BNET-005：IPv6 能力一致化

当前日志中的 AAAA 尝试明确返回 `network is unreachable`。处理顺序：

1. 检查物理接口是否有全局 IPv6 地址和默认路由；
2. 有完整 IPv6 路由时修复主机/网关，不禁用 IPv6；
3. 无 IPv6 默认路由时，在活动配置的顶层 `ipv6` 与 `dns.ipv6` 同步设为 `false`；
4. 通过 Clash Verge DNS/TUN 设置读取最终运行配置，不能只读取导入 YAML 的原始值；
5. 重载核心后重新运行环境检测，确认没有 AAAA 出口尝试。

该项只能消除无效 IPv6 尝试；由于本次 IPv4 同样超时，不能将其宣称为完整修复。

## 6. P2：精确域名代理恢复策略

### BNET-006：增加显式 Recovery 代理组

若 DNS/路由修复后两个域名仍不可达，在用户配置中增加独立选择组，并将精确规则放在
宽泛 Bilibili 规则之前：

```yaml
proxy-groups:
  - name: Bilibili-CDN-Recovery
    type: select
    proxies:
      - <现有可用上游代理组>
      - DIRECT

rules:
  - DOMAIN,i1.hdslb.com,Bilibili-CDN-Recovery
  - DOMAIN,upos-sz-staticcos-cmask.bilivideo.com,Bilibili-CDN-Recovery
  # 原有 Bilibili/GEOSITE 规则保持在后面
```

Recovery 组默认选择现有上游代理组，用户可随时切回 DIRECT。不要使用
`DOMAIN-SUFFIX,hdslb.com`，因为 `i0`、`i2` 当前可通过本地 DIRECT CDN 正常访问；也
不要把节点名称硬编码进产品代码。

Clash Verge 可以提供“复制修复片段”和“查看命中域名”，但不得无提示修改导入配置。
如将来提供会话级临时覆盖，必须展示 diff、要求确认，并在核心重启或用户撤销时恢复。

建议实现位置：

- `src/components/traffic-tracer/environment-card.tsx`
- `src/components/traffic-tracer/session-detail.tsx`
- `src-tauri/src/cmd/traffic_tracer.rs`
- 中英文 TrafficTracer 文案资源

## 7. P3：统计语义与 UI 修正

### BNET-007：拆分关联覆盖率和出口建立率

现有 connection index 已包含 `terminal.status=dial_error`、`stage=dial` 和稳定
`error_class`，无需修改 Mihomo trace 协议。TrafficTracer 汇总应派生三类指标：

- `correlation_matched`：NetLog transport 已匹配 Mihomo pre-flow；
- `egress_established`：存在完整 post-flow；
- `egress_failed_before_socket`：已匹配，但在 post socket 建立前 dial error。

修改位置：

- `traffictracer/analyze/artifacts.py`
- `traffictracer/analyze/connection_artifacts.py`
- `src/components/traffic-tracer/connection-results.tsx`
- `src/components/traffic-tracer/session-detail.tsx`

UI 对本次结果应显示“22/22 已关联，17/22 已建立出口，5 条 DIRECT 拨号失败”，不能只
显示“缺少 5 条 post-flow”。如果新字段写入持久化 schema，应同步更新 schema 版本、
fixture、Python/Rust/TypeScript 契约；如果仅从现有字段派生，则保持协议版本不变。

### BNET-008：将诊断快照纳入 Session

用户明确执行目标诊断后，把脱敏结果保存为 `raw/network-diagnostics.json`，登记新的
artifact role。内容必须带时间戳和活动配置摘要，禁止保存完整订阅、节点密钥、Cookie
或 URL 查询参数。未执行诊断时不创建空文件，也不能阻止正常捕获。

## 8. 测试矩阵

### 单元与契约测试

- IPv4 timeout、IPv6 unreachable、connection refused、DNS failure 分类；
- matched pre-flow + dial error 不计为 correlation unmatched；
- 无 post-flow 时不生成假的 post PCAP；
- 诊断取消、单目标超时和总超时；
- 脱敏输出不包含 URL query、代理密钥和节点详情；
- 新 artifact 的相对路径、大小和 manifest role 一致。

### 集成测试

- Bilibili DIRECT 成功连接仍保持 DIRECT；
- 两个精确域名命中 Recovery 组并产生 proxy post-flow；
- YouTube 规则、节点选择和 22/22 关联结果不受影响；
- TUN `Meta` 与物理接口 `wlp2s0` 两侧 PCAP 均非空；
- 三页面批次串行完成，前一 Chrome 实例退出后才开始下一目标。

### 现场验收门槛

连续三轮相同 Bilibili 批次满足：

- transport correlation：100%，ambiguous 为 0；
- 目标页面 `dial_error`：0；
- 页面归属 logical flow 的完整 post-flow：100%；
- manifest consistency：`passed`；
- 所有 pre/post PCAP artifact 存在且大小与 manifest 一致；
- 无 `.analysis-staging-*`、`.analysis-backup-*` 残留；
- YouTube 完整 pipeline 覆盖率不回退。

若 DIRECT-network-fix 仍失败而 targeted-proxy-recovery 连续三轮通过，则正式结论为
“当前物理网络到特定 Bilibili CDN 路径不可达”，Recovery 规则作为默认修复；若定向
DNS 后 DIRECT 连续三轮通过，则优先保留 DIRECT，并将 Recovery 组作为人工兜底。

## 9. 实施顺序与提交边界

1. BNET-001～002：固定证据并完成 A/B 诊断；
2. BNET-003～005：实现诊断，修复可验证的 DNS/IPv6 不一致；
3. BNET-006：只有物理路径仍不可达时启用精确域名 Recovery；
4. BNET-007～008：完善统计语义、UI 和可审计快照；
5. 三仓分别测试、提交、推送，最后更新 `components.lock.yaml` 与 gitlink；
6. 运行 Python 全量测试、Rust 单元测试、前端测试、组件锁检查和 Linux 包冒烟测试；
7. 构建新的 Deb/AppImage，再执行连续三轮现场验收。

Mihomo 已正确报告 dial error 和 post-flow 缺失，P0～P2 不需要修改核心。只有发现核心
错误选择地址族、未遵循最终 DNS 配置或未报告实际 dial 候选时，才在
`component/tracer/tracer.go` 及实际 dialer 路径增加经过脱敏的诊断字段，并相应更新
