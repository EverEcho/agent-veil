# 集成设计

## 1. 统一 Integration 生命周期

每个 Agent Integration 只负责发现和接管出口：

```text
Detect -> Inspect -> PlanProtection -> Prepare -> Launch/Attach -> Cleanup
```

Integration 不实现检测、策略、Vault 或流式恢复。相同协议必须复用统一 Core。

## 2. 三种工作模式

| 模式 | 场景 | 完整产品要求 |
|---|---|---|
| Launch | CLI 或桌面 Agent，由 AgentVeil 启动子进程并注入临时配置 | 完整支持 |
| Attach | 已运行且支持动态配置的 Agent | 完整支持并可撤销接管 |
| Managed | 常驻 Gateway，通过插件、Provider Bridge 或配置 API 接入 | 完整支持健康检查与重连 |
| Native | 开源 Agent 通过 Provider/Plugin 直接注册 Surface | 优先集成方式 |
| Transparent | 无法修改 Base URL 的闭源客户端 | 高级模式，限定域名和进程范围 |

透明 MITM 仅用于不能修改 Base URL 的客户端，是高级集成方式，不是默认架构。

### Attach 通用生命周期

支持动态配置的 Agent 通过 `sdk/attach` 接入：控制器先注册 `ModeAttach` Manifest，再为完整 Protected Route 集合创建短期 Session，将 loopback Base URL、Session/Route Header 和兼容 API Key carrier 一次性交给 Agent 专用 `Target.Apply`。控制器在运行期间维持 generation-bound lease，并在 Session 半寿命处先应用新能力、再撤销旧能力。取消、心跳失败、轮换失败或 Apply 失败都会调用幂等 `Target.Restore`，随后撤销 Session 和当前 registration generation。管理 Token 不进入 Target 或 Agent 进程。

该 SDK 只负责安全生命周期，不代表具体 Agent 已实现动态配置。每个 Agent 的 Target 仍需证明原配置快照、原子替换、重连以及精确恢复能力后，才能在兼容矩阵中标为 Attach Protected。

## 3. Agent 优先级

### Codex

- 运行时用临时 Provider override 指向本地随机端口；
- 保留用户原认证方式，不永久修改原配置；
- 关闭可能绕过 HTTP 检查的 WebSocket 与请求压缩能力；
- 拒绝会覆盖 provider、base URL、WebSocket 或 compression 的冲突参数；
- 兼容 OpenAI API Key 与 ChatGPT/Codex 登录链路需分别做端到端验证。
- Codex Desktop 作为独立 Integration 识别其内置 `codex app-server` 版本；macOS 使用 AgentVeil 私有的会话级 `CODEX_HOME` 启动官方 App，退出后清理，不修改 `~/.codex`；
- 已运行的 Codex Desktop 不做伪 Attach。必须先退出，再从 AgentVeil 受保护启动；App Tools、MCP 与 Shell 子进程仍逐项展示其独立出口边界。

### Claude Code

- 保存原 `ANTHROPIC_BASE_URL` 和网络代理配置；
- 子进程的 Anthropic Base URL 指向 AgentVeil；
- AgentVeil 自身继承原 Upstream 与 HTTP/SOCKS 网络出口；
- 避免子进程通用代理将请求直接送往 Clash 而绕过内容检查；
- 不接管或保存长期 Claude 凭据。

### Hermes

必须枚举主模型、vision、compression、approval、delegation 和全部 fallback。每个模型槽独立生成 Surface 与 Protected Route，不能只修改 default model。

### OpenClaw

优先采用 Provider Bridge/插件集成，并枚举主模型、Fallback、Provider 插件、ACP、MCP 与 Browser/Tools。ACP 中的 Codex/Claude 作为 Nested Agent 加入父 Session。

### Cursor、Zed、OpenCode、Cline

先通过 Spike 验证是否存在稳定的显式 Base URL/Provider 配置。若只能依赖透明 MITM，必须在产品中标为高级模式并单独评估。

## 4. 协议优先级

### OpenAI Chat

扫描 `messages[].content`、tool/function call arguments 和 tool outputs。

### OpenAI Responses

扫描 `instructions`、`input`、function/custom tool call arguments 与 outputs；不得修改具有完整性语义或服务端生成的字段。

### Anthropic Messages

扫描 `system`、text block、`tool_use.input` 和 `tool_result.content`；不修改 thinking、redacted thinking 与服务端完整性字段。

### Gemini、MCP HTTP、MCP Streamable HTTP

每种协议均需完整的请求抽取/重组和流事件编解码器，不允许用“OpenAI 兼容”假设直接放行未知结构。Bedrock 与 Vertex 还必须在内容修改后完成对应的认证或请求重签名。

## 5. Tool JSON

Tool Arguments 既可能是对象，也可能是包含 JSON 的字符串。Adapter 应递归访问 object/array 的字符串值；若字符串本身是合法 JSON，则在有深度与大小上限的前提下继续解析。重组后必须保持协议类型和必要的转义。

## 6. MCP 与工具出口

- `MCP stdio` 是本地 IPC，可标记为 Local；其子进程的独立外联属于进程出口问题；
- Remote MCP 应通过专用 MCP Proxy 检查 tool arguments、results、resources 和 prompt payload；
- 已弃用的 HTTP+SSE 双端点传输独立标记为 `mcp_legacy_sse`，不得借用 `mcp_http` 或 Streamable HTTP 能力；Hermes 0.20.6 的该 Surface 由专用有状态适配器保护：Core 将 Provider 的 `endpoint` 事件改写为绑定 Session/Route 的不透明 loopback POST URL，以同一 Vault 检查双向 GET/POST 数据，精确保留 Provider query，拒绝跨源动态端点，并对通道数量、每通道 POST、正文、事件和 URL 设置硬上限；长连接 GET 与普通请求分别使用有界并发槽，关闭时排空已取得的 POST，过期或撤销则立即销毁通道；
- Browser、OAuth、文件上传和任意 WebSocket 语义复杂，首期只能准确展示为 Observed/Partial/Unprotected；
- 不应通过通用字符串替换伪装成完整 Browser DLP。

## 7. Auth 与 Network 解耦

同一协议可能使用 Passthrough、Bearer、Anthropic API Key、Google API Key、AWS SigV4、Vertex OAuth 或自定义认证。认证必须在内容修改后应用。

网络出口独立支持 Direct、HTTP Proxy、SOCKS5 和系统代理。最终路由是：

```text
Surface -> Protocol -> Policy -> Upstream -> Auth -> Network Route
```

## 8. 版本兼容策略

- 明确维护“已验证 Agent 版本 × 协议 × 认证方式”矩阵；
- 未验证的新版本先报告风险，不默认为兼容；
- 配置解析采用版本化 fixture 测试；
- 不为历史结构默认增加双字段或静默兼容层；确需兼容时单独评审并记录退出计划。
