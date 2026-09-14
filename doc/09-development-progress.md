# 开发进度

更新日期：2026-09-13  
代码基线：`e7607c4`（`feat: protect legacy mcp sse transport`）

本文按用户可感知功能追踪 AgentVeil 当前开发状态。这里的“已开发”只表示代码已经落地；“已验证”必须具有仓库自动化、模拟 Provider、目标 Agent 或目标平台证据。真实应用或平台证据不足的功能仍列入“待验证”，不能因为能够编译或存在接口就标为完整可用。

## 1. 状态定义

| 状态 | 含义 |
|---|---|
| 已开发 | 功能代码已经落地，并已接入实际运行路径 |
| 已验证 | 已有自动化测试、模拟 Provider、真实 Agent 或目标平台证据 |
| 待开发 | 关键运行能力尚未实现，或者当前只有领域模型和接口 |
| 待验证 | 功能已有实现，但缺真实应用、真实 Provider、目标平台或长期运行证据 |
| 外部阻塞 | 需要产品决策、签名身份、分发授权或仓库之外的运行环境 |

## 2. 总体进度

| 功能领域 | 已开发 | 已验证 | 待开发 | 待验证 | 当前结论 |
|---|---|---|---|---|---|
| Privacy Core 与本地管理面 | Core、Session、Route Capability、管理 API、健康检查、单实例、恢复与桌面 Supervisor | 自动化测试覆盖认证、生命周期、并发、撤销和崩溃状态 | 安装升级期间的 Core 迁移编排 | 系统重启、强制退出和桌面进程故障注入 | 运行生命周期已接入桌面，安装升级未闭环 |
| 协议感知数据面 | OpenAI Chat、Responses、Anthropic、Gemini、MCP HTTP、Streamable HTTP、legacy SSE | 协议金样、流分片、错误格式和模拟 Provider 边界 | Browser、OAuth、文件传输、WebSocket 专用适配器 | 真实 Provider 与真实 Agent 端到端 | 主要模型与远程 MCP 已完成 |
| 检测、策略与 Vault | 确定性规则、熵检测、分层策略、ASK、Placeholder、响应恢复 | Detector、Policy、Vault、响应 DLP 和隐私安全产物测试 | 正式本地语义模型运行时 | 中文模型基准、误报率、召回率和硬件档位 | 确定性链路完成，语义能力未产品化 |
| Agent 发现 | 八类目标 Agent 的配置发现与 Surface 枚举 | 配置 fixture 与未知版本降级测试 | 动态、IDE Host、Workspace 等缺失配置入口 | 各目标 Agent 精确版本实机核对 | 发现较广，完整性仍待实机确认 |
| Protected Launch | Linux Codex、Claude、Hermes 启动与临时配置注入 | 指定版本 launch smoke 和崩溃清理 | 其他 Agent 与其他平台 Protected Launch | 真实请求、复杂配置和长期运行 | 当前只覆盖三种 Linux Agent |
| Attach | 通用 Attach SDK、短期 Route 能力轮换、租约、失败恢复与撤销 | Core 集成自动化 | 各目标 Agent 动态配置适配器 | 所有目标 Agent Attach 实机 | 通用安全生命周期已完成，Agent 适配待接入 |
| Managed、Native、Nested | Managed Manifest Monitor、Native SDK、lease/heartbeat、父子 Session | 自动化集成与调用树测试 | OpenClaw Gateway、ACP、Provider Plugin 等产品集成 | 真实 Managed/Native Agent | 通用底座完成，产品集成不足 |
| MCP | HTTP、Streamable HTTP、legacy SSE 双端点保护、stdio Local 建模 | 请求/响应/流、能力绑定、Vault、撤销和 Provider 边界 | stdio 子进程跨平台连接前阻断 | 真实远程 MCP、重连和长连接运行 | 远程 MCP 核心数据面完成 |
| Browser、Web 与 Tool | Surface 枚举、Observed/Partial/Unprotected 分级、Tool Adapter SDK | 保守覆盖状态和 SDK 防夸大测试 | Browser 自动化、OAuth、上传下载、WebSocket 专用策略和数据面 | 真实浏览器及工具链 | 只能发现和分级，不能宣称内容保护 |
| Routing、Auth 与 Network | Routing Graph、SSRF 防护、Bearer/Key/SigV4/Vertex、Direct/HTTP Proxy/SOCKS5/System Proxy | 单模块和模拟网络测试 | VPN/TUN 信息发现、复杂透明路由集成 | Bedrock、Vertex、自定义 Gateway 和真实中间件链路 | 模块完成，组合验证不足 |
| 桌面控制面 | Tauri 2 桌面壳、Web/Desktop 共用 Dashboard、托盘、用户级自启动与 Core 生命周期 | Rust 轻量编译、既有 Core 生命周期测试 | 自动更新、回滚和迁移管理 | 三平台完整用户流程与签名安装包 | 统一 GUI 与桌面运行壳已开发，发行验收未完成 |
| Transparent Mode | 精确 Scope、CA、叶证书、Linux trust-store 与进程出口观察 | CA 生命周期、权限、恢复和 Linux `/proc` 测试 | HTTPS MITM、Protocol Adapter 接入和 pre-connect 阻断 | 证书固定、HTTP/3、QUIC、WebSocket、系统代理变化 | 安全底座完成，透明内容保护未实现 |
| 跨平台 | Linux/macOS/Windows、amd64/arm64 交叉构建 | 六目标编译 | macOS/Windows 原生安全存储、证书、出口观察和阻断 | 两个平台的安装、运行、升级、回滚和卸载 | 可构建不等于可交付 |
| 安装、升级与发布 | CI、SBOM、漏洞扫描、可复现构建和 provenance 工作流 | 仓库自动化门禁 | 正式安装器、自动更新、回滚、卸载和分发渠道 | 正式签名制品与发布演练 | 工程底座存在，正式发布未完成 |

## 3. Privacy Core 与本地管理面

### 已开发

- 独立后台 Core、随机 loopback 监听和版本化本地管理 API；
- Session Manager、Route Token、父子 Session 和撤销级联；
- 管理 Token 认证、Core 随机实例身份和无凭据身份预检；
- 单实例锁、原子状态持久化、旧实例状态和 Hermes 私有启动目录恢复；
- 请求大小、Header、Query、并发、TTL 和资源数量硬上限；
- 健康检查、隐私安全诊断、审计、规则包和模型包管理；
- 普通请求与长连接分别使用有界并发槽，避免 SSE GET 饿死动态 POST。

### 已验证

- 管理认证、API 版本、Session 生命周期、并发限制和管理面隔离；
- Core 崩溃释放实例锁、旧状态身份拒绝和启动残留安全清理；
- Session 删除、过期、子 Session 和 Route Capability 撤销；
- Core legacy MCP SSE 状态跨每请求 Handler 保持，并在关闭后销毁。

### 待开发

- 正式桌面进程对 Core 的安装、启动、保活、退出和升级编排；
- 三平台统一安全存储和系统服务集成。

### 待验证

- 系统重启、强制断电、桌面进程崩溃和升级中断等实机故障注入；
- 多用户桌面环境中的权限与隔离。

## 4. 协议、检测与数据保护

### 已开发

- OpenAI Chat Completions、OpenAI Responses、Anthropic Messages、Gemini；
- MCP HTTP、MCP Streamable HTTP 和 MCP legacy SSE；
- 请求业务字段抽取与原位重组、非流式响应和 Provider-specific SSE；
- Tool Arguments/Results 中对象、数组和 JSON 字符串的递归处理；
- 确定性 PII/Secret、结构化校验、前缀、正则和熵检测；
- Global、Agent、Workspace、Provider、Surface、Finding Type 分层策略；
- `ALLOW / REDACT / BLOCK / ASK`、确定性 Placeholder、有界内存 Vault；
- 响应泄漏检测、Placeholder 恢复、跨事件安全切点和 Credential look-behind。

### 已验证

- 协议请求、响应和流式金样；
- 未知 Endpoint、畸形 Envelope、未知压缩和检测器故障失败关闭；
- 任意 SSE 分片下的 Placeholder 恢复和跨事件 Secret 阻断；
- 模拟 Provider 只收到策略允许或脱敏后的内容；
- Vault 容量、隔离、稳定映射、销毁和请求级生命周期。

### 待开发

- Browser、OAuth、文件上传下载和 WebSocket 的专用协议适配器；
- 正式 ONNX 语义推理 Runtime 与可信模型下载流程。

### 待验证

- 真实 OpenAI、Anthropic、Gemini、Bedrock、Vertex 和 MCP Provider；
- 中文语义模型的准确率、性能、内存占用和硬件分档；
- 超长上下文、超大 Tool Result 和高并发 Session 压测。

## 5. Agent 与 Integration 进度

通用 Attach SDK 已接入 Core 的 leased registration 与 Session API，可将多 Surface Route 绑定原子交给 Agent 专用动态配置适配器，并负责心跳、短期能力轮换、失败恢复、Session 级联撤销和原配置恢复。当前尚无目标 Agent 的动态配置适配器，因此不能据此宣称任何具体 Agent 已支持 Attach。

| Agent | 已开发 | 已验证 | 待开发 | 待验证 |
|---|---|---|---|---|
| Codex | 按实际选中 Provider 解析 API Key、ChatGPT 登录上游和自定义 Base URL；未选中 Provider 不影响 Inspect；Linux/macOS 默认 OpenAI/ChatGPT Protected Launch | Linux 0.153.4 API Key/ChatGPT 与 macOS 0.153.4 ChatGPT `--help` launch smoke；自定义 Provider 保守降级测试 | 自定义 Header/Query/Signer 的完整接管 | 真实 Provider 请求、其他版本和 Windows |
| Claude Code | 配置发现、API Key Protected Launch | Linux 2.1.220 `--help` launch smoke | OAuth 能力注入与验证 | OAuth、真实 Anthropic 请求和其他平台 |
| Hermes | 主模型、辅助、Vision、Fallback、Delegation、远程 MCP 配置改写 | Linux 0.20.6 多 Surface 和 legacy SSE 自动化 | 更多 Provider 与特殊 transport | 真实复杂配置、远程 MCP 和长期运行 |
| OpenClaw | 模型、MCP、ACP、Browser、Web Tool Surface 发现 | 配置 fixture | Provider Bridge、Gateway、Plugin 和 Protected 接入 | 真实版本与嵌套运行 |
| OpenCode | 主模型、小模型、local/remote MCP 发现 | 配置 fixture | Protected Launch、项目级和托管覆盖 | 真实版本与运行 |
| Zed | 自定义模型、MCP、ACP 发现 | 配置 fixture | IDE Host、项目级配置和保护接入 | 真实 IDE |
| Cline | Provider、MCP、legacy SSE 发现 | 配置 fixture | IDE Host、Workspace 和保护接入 | 真实 VS Code/Cline |
| Cursor | MCP 配置发现 | Linux 3.19.19 discovery-only | 稳定模型和 MCP Protected 接入 | 闭源客户端真实链路 |

当前只有 Compatibility Matrix 中以下范围可以声明为指定条件下的 Protected：

- Linux/macOS Codex 0.153.4 的默认 OpenAI API Key/ChatGPT Responses 主模型 Surface；
- Linux Claude Code 2.1.220 的 Anthropic API Key 主模型 Surface；
- Linux Hermes 0.20.6 的主模型、辅助、Vision、Fallback、SubAgent、MCP Streamable HTTP 和 legacy SSE Surface。

其余 Agent 即使能够发现配置，也必须继续显示为 Observed、Partial 或 Unprotected。

## 6. MCP、Browser 与 Tool Surface

### 已开发

- MCP HTTP 和 Streamable HTTP 的请求、响应与流保护；
- legacy SSE 的 GET Stream、Provider `endpoint` 事件改写和动态 POST；
- legacy SSE Session/Route/Capability 精确绑定、GET/POST 共享 Vault；
- Provider query 精确保留、跨源动态 Endpoint 拒绝和能力 Header 剥离；
- 通道数量、每通道 POST、正文、事件和 URL 上限；
- MCP stdio 的 Local 状态以及 Browser、Tool HTTP 的保守 Surface 枚举；
- Tool Adapter SDK 防止 Native Integration 夸大特殊出口覆盖。

### 已验证

- MCP 协议 Envelope 和 Provider 边界；
- legacy SSE 关闭排空、过期、撤销、跨源拒绝和 Core 生命周期；
- Local stdio 不被标记为远程内容保护；
- Browser、OAuth、文件和 WebSocket 不能借用 MCP 能力宣称 Protected。

### 待开发

- stdio MCP 子进程的跨平台连接前阻断；
- Browser 自动化、OAuth、文件上传下载、WebSocket 和通用 Tool HTTP 专用数据面；
- 相应的用户阻断选项和细粒度策略。

### 待验证

- Hermes 与真实远程 MCP 服务的断线重连和长期连接；
- 真实浏览器、IDE Tool 与 OAuth 流程。

## 7. Routing、认证和网络

### 已开发

- Surface 到 Protocol、Policy、Upstream、Auth、Network Route 的独立绑定；
- Routing Graph 结构校验和 `CONTENT_MODIFIER_AFTER_DLP` 检测；
- 固定 Upstream、域名/IP/端口 allowlist、重定向复检和 SSRF 防护；
- Passthrough、Bearer、Anthropic Key、Google Key、Vertex OAuth、AWS SigV4；
- Direct、HTTP Proxy、SOCKS5 和 System Proxy；
- SigV4 在 DLP 修改完成后对最终 Body 签名。

### 已验证

- 模拟网络代理、SOCKS5 协商、SSRF 和开放代理拒绝；
- SigV4 最终 Body 签名与异常凭据失败关闭；
- DLP 后存在内容修改中间件时拒绝 Protected 规划。

### 待开发

- VPN/TUN 信息发现与平台网络栈集成；
- Transparent Route 与现有 Protocol Adapter 的单检查点接入。

### 待验证

- 真实 Bedrock、Vertex、自定义 Gateway、Clash 和企业网络代理组合；
- DNS、代理和系统网络配置动态变化。

## 8. 桌面控制面

### 已开发

- Tauri 2 独立桌面壳，系统 WebView 本地加载与 Core 内嵌页面同源的 Dashboard；
- 浏览器与桌面使用同一套前端源码；桌面通过受限 Rust bridge 自动使用本机管理凭据，凭据不进入 JavaScript；
- 浏览器入口由托盘或 `veil web` 签发 30 秒单次票据，并换取 `HttpOnly`、`SameSite=Strict` 的限时本机会话；页面不接受管理 Token；
- 系统托盘、单实例、用户级开机启动和关闭窗口隐藏；
- Tauri 官方插件提供的用户级开机启动；
- Rust 实际运行路径中的 Core instance identity 预检、启动、探活、保活、崩溃重启和 Session-aware 退出；
- Core 内嵌本地 Web Dashboard；
- Agent 发现、Inspection Preview、Protection Plan 和覆盖率展示；
- Routing Graph、父子调用树、Session 与 Agent 撤销；
- ASK 决策、脱敏预览、一次允许、一次脱敏和阻断；
- 策略编辑、规则测试、误报反馈、规则包与模型包管理；
- 当日统计、七日趋势、审计和隐私安全诊断导出；
- 中英文切换、键盘焦点和基础无障碍语义。

### 已验证

- 页面不包含受保护原文；
- Dashboard 管理请求使用认证和版本化 Core API；
- 覆盖状态保留 Protected、Local、Partial、Observed、Unprotected 的真实语义。

### 待开发

- 安装、升级、回滚、迁移和卸载入口；
- 三平台签名、原生打包与平台安全存储适配。

### 待验证

- Linux、macOS、Windows 的完整普通用户流程；
- 关闭窗口、退出桌面进程和系统休眠时不影响已有保护。

## 9. Transparent Mode 与进程出口

### 已开发

- Session、PID、进程启动时间和精确 DNS 名称绑定的透明 Scope；
- 私有 CA 创建、安全文件权限、短期叶证书、轮换与撤销；
- Linux trust-store 原子安装、回滚、恢复和卸载；
- Linux Process Tree、TCP 和 connected UDP 出口采集；
- Expected Route、Local loopback 和 Unexpected Egress 分类；
- Protected Launch 中观察失败或意外出口后的进程组清理。

### 已验证

- CA 材料替换、路径穿越、权限放宽和容量上限失败关闭；
- CA 安装中断、轮换中断、卸载失败和重启 reconcile；
- PID 复用、进程树变化、连接表边界和异常出口不会被标为 Protected。

### 待开发

- 生产 HTTPS MITM 数据面；
- MITM 与 Protocol Adapter 的单检查点集成；
- Linux、macOS、Windows 的 pre-connect 进程级阻断；
- macOS Keychain 和 Windows Certificate Store 控制器。

### 待验证

- 证书固定、HTTP/3、QUIC、WebSocket 和系统代理变化；
- 非 allowlist 目标永不被解密；
- 显式 Protected Route 与 Transparent Mode 不发生双重代理。

## 10. 跨平台与发布

### 已开发

- Linux、macOS、Windows 的 amd64/arm64 交叉构建；
- `go test`、race、fuzz、性能门禁和 acceptance evidence；
- SBOM、依赖漏洞扫描、可复现构建和构建 provenance；
- 规则包与模型包的独立 Ed25519 trust root、签名安装、激活和回滚。

### 已验证

- 六目标交叉编译；
- 仓库全量测试、静态检查、相关包 race 和自动化验收证据；
- 模拟 Provider 与隐私安全制品扫描。

### 待开发

- macOS、Windows 原生安全存储、进程观察、证书和阻断实现；
- 正式安装器、自动更新、回滚、完整卸载和迁移；
- 规则、模型和应用的正式分发及紧急更新流程。

### 待验证

- 三平台真实安装、权限、运行、升级、回滚和卸载；
- 正式签名制品、发布演练和供应链事件响应。

### 外部阻塞

- 桌面安装、升级、签名和分发决策；
- 本地语义模型选型、许可证、中文基准和可信下载源；
- Apple 与 Windows 签名身份；
- 正式发布授权和分发渠道。

## 11. 当前可交付边界

当前适合作为开发者预览范围：

- Linux；
- Codex 0.153.4、Claude Code 2.1.220、Hermes 0.20.6 的指定 Protected Launch 链路；
- OpenAI Responses、Anthropic、Hermes 多模型和远程 MCP；
- 本地规则、策略、脱敏、响应恢复、审计和 Dashboard；
- Native SDK、Managed Manifest 与通用 Attach SDK 实验性接入。

当前不能宣称：

- 所有目标 Agent 均已受保护；
- macOS 和 Windows 已达到生产可用；
- 已支持具体目标 Agent 的运行中 Attach（通用安全生命周期已开发，Agent 动态配置适配器仍待实现）；
- Browser、OAuth、WebSocket 和文件传输已获得内容保护；
- Transparent Mode 已提供完整 HTTPS 内容保护；
- 已具备正式桌面客户端和安装升级体验；
- 已完成所有真实 Provider、认证模式和目标版本验证。

## 12. 建议开发顺序

1. 为首个支持动态配置的目标 Agent 接入 Attach Target；
2. 选择 OpenClaw 或 OpenCode，完成首个三大 CLI Agent 之外的 Protected 集成；
3. 完成 Transparent pre-connect 阻断，再接入受限 HTTPS MITM；
4. 补齐 macOS、Windows 原生平台生命周期；
5. 落地正式 ONNX 语义模型运行时与中文基准；
6. 完成安装、升级、回滚、卸载和正式发布链路。

## 13. 更新规则

- 功能合入实际运行路径后更新“已开发”；
- 自动化证据进入 `make acceptance-evidence` 后更新“已验证（自动化）”；
- 真实 Agent、Provider 或操作系统验证必须记录精确版本、平台和验证方式；
- Compatibility Matrix 是 Protected 声明的唯一事实源；
- 未验证版本和特殊 Surface 必须继续显示为 Partial、Observed 或 Unprotected；
- 本文只追踪进度，产品验收结论以[产品验收证据](./08-acceptance-evidence.md)为准，目标能力以[产品定义](./01-product-definition.md)为准。
