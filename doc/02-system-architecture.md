# 系统架构

## 1. 总体结构

```text
Agent Integration
  -> Agent Manifest
  -> Protection Planner
  -> Session Manager
  -> Local Route / Proxy
  -> Protocol Router + Adapter
  -> Detection Pipeline
  -> Policy Engine
  -> Redactor + Request Vault
  -> Auth Strategy
  -> Network Route
  -> Provider

Provider Stream
  -> Protocol Stream Decoder
  -> Response DLP
  -> Placeholder Boundary Buffer
  -> Restore
  -> Stream Encoder
  -> Agent
```

建议以 Go 实现后台 Privacy Core 和 CLI。桌面 UI 作为独立控制面，通过版本化的本地管理 API 与 Core 通信；技术栈可以独立选择，但不得绕过 Core 执行安全逻辑。

## 2. 核心领域模型

### Egress Surface

保护的最小对象。推荐类型：

```text
model_primary, model_auxiliary, model_fallback,
vision, embedding, image_generation, audio,
mcp_http, mcp_stdio, tool_http, browser,
sub_agent, acp, unknown
```

每个 Surface 至少描述：标识、名称、类型、协议、Upstream、认证描述、配置来源、是否可改写、是否必需。

### Agent Manifest

Integration 对一个 Agent 实例的只读检查结果，包含所有已发现 Surface。Manifest 是事实描述，不包含 DLP 实现。

### Protection Plan

Planner 根据 Manifest 和本地能力计算：

- Protected Routes；
- Local Only Surfaces；
- Unprotected Surfaces；
- 风险与原因；
- 覆盖率摘要。

### Protected Route

将 `Surface + Protocol + Upstream + Auth + Network Route + Policy` 绑定成可执行路由。每条路由有独立标识，避免不同模型槽错误共享配置。

### Protection Session

一次受保护运行的生命周期边界，持有随机本地端口、Session Secret、路由集合、临时配置、子 Agent 上下文和清理函数。

## 3. 模块边界

| 模块 | 职责 | 禁止承担 |
|---|---|---|
| `integration` | 发现 Agent、读取配置、枚举 Surface、准备和清理运行环境 | PII/Secret 检测 |
| `planner` | 计算路由、覆盖率和风险 | 修改用户配置 |
| `session` | 生命周期、随机密钥、子进程与清理 | 协议字段解析 |
| `proxy` | 本地 HTTP 服务、路由鉴权、转发 | Provider 业务结构硬编码 |
| `protocol` | 请求抽取/重组、流事件编解码 | 策略决策 |
| `detector` | 输出 Finding，不决定处置 | 网络发送 |
| `policy` | 将 Finding 与上下文映射为 Action | 识别协议 |
| `redactor` | 生成占位符、替换和恢复 | 长期持久化原文 |
| `auth` | 在修改 Body 后正确应用/透传认证 | 保存长期凭据 |
| `network` | 使用直连、HTTP Proxy、SOCKS5 或系统代理 | 修改内容 |
| `audit` | 记录元数据、决策和性能 | 记录敏感原文 |

## 4. 请求处理顺序

顺序是安全约束，不可随意交换：

1. 只接受 loopback 和合法 Session/Route Token；
2. 限制 Body 大小并处理允许的 Content-Encoding；
3. 识别协议；
4. 抽取可扫描内容；
5. 执行检测并合并 Finding；
6. 执行策略；
7. 创建请求级 Vault 并脱敏；
8. 重组 Body；
9. 在 Body 最终确定后应用认证/签名；
10. 通过既定 Network Route 发送；
11. 对响应做泄漏检测、恢复和流式编码；
12. 销毁请求级 Vault。

## 5. 路由图

必须区分内容中间件和网络传输：

```text
Agent
  -> LiteLLM / OneAPI / Prompt Enhancer（可能修改内容）
  -> AgentVeil（最后一次内容检查）
  -> Clash / Surge / HTTP Proxy / SOCKS5（仅负责传输）
  -> Internet
```

若可修改 Prompt 的中间件出现在 AgentVeil 之后，产生 `CONTENT_MODIFIER_AFTER_DLP` 风险，默认阻断或要求用户显式处理。

## 6. Nested Agent

父子 Agent 共享 Protection Session，但拥有独立 Surface 和 Route。通过以下短生命周期上下文传播：

```text
VEIL_SESSION_ID
VEIL_PARENT_SESSION
VEIL_PROTECTION_TOKEN
VEIL_CORE_ENDPOINT
```

子 Agent 检测到父 Session 后加入现有会话，不重复启动代理。环境变量只包含短期能力令牌，不包含长期 Provider 凭据。

## 7. 当前代码布局

```text
cmd/veil/main.go          最小进程入口
cmd/veil/command.go       CLI 命令分派
cmd/veil/cli_commands.go  管理命令与输出
cmd/veil/management_client.go  版本化 Core 管理客户端
cmd/veil/launch.go        Protected/Nested Launch
cmd/veil/serve.go         Core 依赖装配与进程生命周期
internal/integration/     Codex、Claude、Hermes、OpenClaw
internal/domain/          Surface、Manifest 与共享领域契约
internal/planner/         Protection Plan 与 Routing Graph
internal/session/         会话生命周期
internal/core/            本地管理 API；按 lifecycle/auth/agents/sessions/policy/observability 拆分
internal/proxy/           Provider 数据面代理
internal/protocol/        OpenAI、Responses、Anthropic、MCP
internal/detector/        Rule、Secret、PII、Entropy、Semantic
internal/policy/          Policy Engine
internal/redactor/        Placeholder、Vault、流式恢复
internal/auth/            Passthrough、Bearer、SigV4 等
internal/network/         Direct、HTTP Proxy、SOCKS5
internal/audit/           隐私安全事件
internal/webui/           浏览器与 Tauri 共用的 Dashboard 源码和 Go embed 边界
sdk/                      Native、Attach 与 Tool Adapter 公共 SDK
desktop/src-tauri/        Rust 桌面壳；bridge/supervisor/tray 分离
```

`cmd/veil` 可以在未来替换为其他语言的 CLI；稳定边界是版本化 loopback 管理 API，
不是 Go 包。Tauri 只实现桌面平台能力和受限 API bridge，不承载 Core 业务逻辑。
