# 产品定义

## 1. 产品定位

AgentVeil 是部署在用户本机的 **AI Agent 隐私控制层（Local Privacy Control Plane for AI Agents）**。

它不是单纯的正则替换器，也不是传统网络防火墙。它负责发现 AI Agent 的数据出口，理解模型协议中的业务内容，在数据离开设备前完成检测与策略决策，并为用户展示真实的保护覆盖率。

核心价值是：

> 用户保持原有 Agent、模型账号和网络环境，真实敏感信息尽可能不离开本机。

## 2. 目标用户与场景

首要用户是频繁使用 Codex、Claude Code、Hermes、OpenClaw 等工具的个人开发者和小团队。

典型风险包括：

- Agent 读取 `.env`、配置、日志或数据库结果后发送到模型；
- Prompt、Tool Call、Tool Result 中含手机号、身份证、邮箱或客户资料；
- 主模型已保护，但视觉、压缩、委派或 Fallback 模型绕过保护；
- Agent 经过本地模型中间件或网络代理时路由顺序错误；
- 流式响应中出现原始敏感值、新凭据或跨分片占位符。

## 3. 产品原则

### Local First

PII/Secret 检测、规则校验、策略、占位符、Vault 和审计默认在本机完成。敏感原文不得发送给 AgentVeil 自身的云服务。

### Protocol Aware

先识别 OpenAI Chat、OpenAI Responses、Anthropic Messages 等协议，再扫描承载用户内容的字段。不得对整个 JSON Body 做无差别替换。

### Fail Closed

无法证明请求完成安全检查时默认阻断。未知协议、解析失败、不支持的压缩、检测器异常、Vault 容量耗尽和保护配置被覆盖都属于阻断条件。

### No Credential Migration

尽量只识别认证类型并透传现有认证，不主动复制、托管或持久化用户长期凭据。

### Coverage Is Explicit

UI 和 CLI 必须按数据出口展示 `Protected / Local / Partial / Observed / Unprotected`，不得只显示笼统的“Agent 已保护”。

## 4. 核心用户流程

```text
发现 Agent 与配置
  -> 枚举数据出口
  -> 生成 Protection Plan
  -> 用户确认风险和覆盖率
  -> 创建本地 Session
  -> 启动受保护 Agent
  -> 请求检测与处置
  -> 响应泄漏检测和占位符恢复
  -> Session 结束并销毁敏感映射
```

CLI 命令体验建议：

```bash
veil inspect codex
veil run codex
veil run claude
veil status
```

## 5. 完整产品能力

### 本地控制面

- 后台 Privacy Core 统一承载协议解析、检测、策略、Vault、路由和审计；
- CLI 负责检查、运行、诊断和自动化；
- 桌面端负责 Agent 发现、保护计划、Routing Graph、实时告警、策略管理和历史审计；
- macOS、Windows、Linux 提供一致的核心安全语义。

### Agent 与出口覆盖

- 支持 Codex、Claude Code、Hermes、OpenClaw、OpenCode、Cursor、Zed、Cline 和自研 Agent；
- 同时支持 Launch、Attach、Managed、Native Integration；
- 将主模型、辅助模型、Fallback、Vision、Embedding、Image、Audio、MCP、Browser、Tool HTTP、ACP、SubAgent 分别建模；
- 父子 Agent 共享保护 Session，但保留独立路由、策略和审计关系；
- 对无法修改 Base URL 的闭源客户端提供 allowlist 限定的透明模式。

### 数据安全能力

- 支持 OpenAI Chat、OpenAI Responses、Anthropic Messages、Gemini、MCP 及可扩展协议适配；
- 组合 Feature、Prefix、Regex、Checksum、Entropy 和本地 Semantic Detector；
- 内置中国 PII、国际通用 PII、开发者 Secrets 与国内外云/模型 Provider 凭据规则；
- 支持 `ALLOW / REDACT / BLOCK / ASK` 及 Global、Agent、Workspace、Provider、Surface、Finding Type 多层策略；
- 支持长上下文切片、检测缓存、确定性占位符、请求级 Vault 和双向 Response DLP；
- 正确处理 SSE、流式 JSON、跨分片占位符和跨分片凭据。

### 路由与可观测性

- 自动发现模型中间件、网络代理、认证方式和真实 Upstream；
- 构建 Routing Graph 并识别 DLP 后内容修改、未知出口和旁路连接；
- 明确显示 Protected、Local、Partial、Observed、Unprotected；
- 观察 Agent 及子进程出口，对未保护外联告警；
- 本地审计记录元数据、动作、性能，以及将全部命中值替换为 `***` 的有界上下文摘要；不记录敏感原文。

## 6. 产品边界

AgentVeil 提供数据出口控制和风险可见性，但不宣称：

- 能识别所有未知或强语义敏感信息；
- 能抵御已取得当前用户权限并读取进程内存的本地恶意软件；
- 能在用户显式选择放行后继续保证数据不外传；
- 仅凭安装即可自动兼容未来所有 Agent 与协议版本；
- 等同于法律意义上的匿名化或合规认证。

## 7. 完整产品验收标准

1. 所有目标 Agent 均能生成包含全部已知 Surface 的 Manifest 和 Protection Plan。
2. Launch、Attach、Managed、Native 和 Transparent 模式分别具有自动化集成测试与真实应用验证。
3. OpenAI Chat、Responses、Anthropic、Gemini、MCP 的请求、非流式响应和流式响应均完成协议金样测试。
4. 未知 Endpoint、解析失败、检测失败、Vault full、不支持压缩和路由异常均不会静默旁路。
5. 相同 Session 的敏感值映射稳定，不同 Session 不可关联；Vault 不落盘且按请求销毁。
6. 占位符或凭据跨多个流事件时不会提前泄漏，响应恢复保持协议语义。
7. 日志、错误、诊断包和审计中不出现敏感原文、长期凭据及恢复映射。
8. Routing Graph 能识别内容中间件顺序错误、未保护出口和嵌套 Agent 链路。
9. 桌面端和 CLI 展示的覆盖状态与实际拦截能力一致，不把 Observed/Partial 标为 Protected。
10. Agent、Core 或桌面端异常退出后，临时配置、证书状态和内存映射均能安全恢复或清理。
11. macOS、Windows、Linux 的平台差异不改变 fail-closed、安全存储和策略语义。
12. 端到端测试能够证明受保护远端只收到策略允许或脱敏后的内容。

## 8. 成功指标

- 受支持链路的已知敏感信息旁路率为 0；
- 核心请求路径 P95 增量延迟目标：纯规则模式小于 15 ms（不含上游网络）；
- 各类 Integration 的受保护启动/接管成功率达到 99%（受支持版本与标准配置）；
- 崩溃恢复后无残留配置破坏；
- 用户能在一次命令内看到保护范围和阻断原因。
