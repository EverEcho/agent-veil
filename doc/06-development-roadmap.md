# 开发路线图

## 1. 路线图原则

本路线图描述完整目标产品的合理建设顺序，不按开发周期、发布日期或阶段性发布范围裁剪能力。

各阶段是依赖关系，不是对外产品版本。允许并行建设，但只有前置层的接口和安全不变量稳定后，依赖它的功能才能进入集成状态。最终产品应完成全部阶段，而不是停留在某个“可演示版本”。

## 2. 路线总览

```text
领域契约与安全基线
  -> Privacy Core 与本地管理平面
  -> 协议感知数据面
  -> 完整检测、策略、脱敏与响应 DLP
  -> Routing Graph、认证与网络路由
  -> Agent 发现及 Launch/Attach
  -> Native/Managed/Nested Agent
  -> MCP、Browser 与 Tool Surface
  -> 桌面控制面与完整用户体验
  -> Transparent Mode 与进程出口防绕过
  -> 跨平台加固、供应链和正式发布
```

## 3. 阶段一：领域契约与安全基线

### 建设内容

- 定义 AgentInstance、EgressSurface、AgentManifest、ProtectionPlan、ProtectedRoute、ProtectionSession；
- 定义 Protocol、AuthStrategy、NetworkRoute、Finding、Policy、Action、AuditEvent；
- 固化 fail-closed、安全日志、内存 Vault、Upstream allowlist、配置恢复等安全不变量；
- 建立统一错误模型、风险代码、覆盖状态和兼容矩阵；
- 建立威胁模型、数据生命周期和产品表述边界；
- 准备协议金样、Agent 配置 fixture、模拟 Provider 和随机流分片测试工具。

### 完成标准

- 领域对象能表达多模型槽、Fallback、MCP、Browser、子 Agent 和未知出口；
- 安全不变量可映射为自动化测试；
- Integration、Protocol、Detector、Policy、Auth、Network 之间不存在职责重叠；
- 未知能力只能落入 Partial、Observed 或 Unprotected，不能被表示为 Protected。

## 4. 阶段二：Privacy Core 与本地管理平面

### 建设内容

- 实现独立后台 Core、CLI 客户端和版本化本地管理 API；
- 实现 Session Manager、随机端口、Session/Route Token、子进程管理与崩溃恢复；Core 状态绑定随机实例身份，CLI 在发送管理 Token 前执行无凭据身份握手，重启取得实例锁后先清除崩溃残留状态；
- 实现只监听 loopback 的路由服务、请求大小限制、超时和并发控制；
- 实现本地配置、策略存储、规则包存储和隐私安全审计；
- 实现 Core 健康检查、单实例协调、升级兼容和安全停机；
- 为桌面端、CLI 和 Native Plugin 提供同一组能力接口。

### 完成标准

- UI 或 CLI 退出不破坏正在保护的 Session；
- Core 异常时受保护请求安全失败，不自动直连 Provider；
- 本地 API 不能被其他进程未授权调用；
- 所有临时配置和能力令牌均有明确生命周期与清理机制。

## 5. 阶段三：协议感知数据面

### 建设内容

- 实现 Protocol Router 与统一 ProtocolAdapter 接口；
- 实现 OpenAI Chat、OpenAI Responses、Anthropic Messages、Gemini；
- 实现 MCP HTTP、SSE、Streamable HTTP 的消息解析；
- 递归抽取对象、数组和 JSON 字符串中的 Tool Arguments/Results；
- 实现请求抽取、原位重组、非流式响应和 Provider-specific 流式编解码；
- 识别并保护具有完整性语义的 thinking、签名字段和服务端生成字段；
- 未知 Endpoint、Body、Content-Type、Content-Encoding 统一失败关闭。

### 完成标准

- 每种协议均具有脱敏后的 round-trip 金样；
- 任意流分片方式不改变协议语义；
- 协议升级造成的不兼容可被识别并阻断；
- 不依赖对整个 JSON Body 的无差别字符串替换。

## 6. 阶段四：检测、策略、脱敏与 Response DLP

### 建设内容

- Feature Scanner、Exact/Prefix Scanner、Regex Detector、Structured Validator；
- Secret 规则库、中国 PII、国际通用 PII、国内外云和模型 Provider 凭据；
- Entropy Detector 与上下文置信度；
- 本地 Semantic Detector、Tokenizer、分块、overlap、BIES/Viterbi 解码；
- Finding Merge、严重级别、置信度和解释信息；
- Global、Agent、Workspace、Provider、Surface、Finding Type 多层 Policy；
- `ALLOW / REDACT / BLOCK / ASK` 的一致执行语义；
- Session 稳定 Placeholder、请求级有界内存 Vault；
- Response Leak Scanner、Placeholder Restore、跨流事件 Safe Cutpoint 和 credential look-behind；
- 长上下文检测缓存、批处理和性能优化。

### 完成标准

- 规则、校验器、语义模型和策略均可独立测试与替换；
- 相同 Session 映射稳定，不同 Session 不可关联；
- Vault full、Detector failure 和 Semantic Model required-but-unavailable 均阻断；
- 流式响应不会泄漏占位符片段、原文片段或跨分片 Secret；
- 日志、审计、错误和诊断产物通过敏感原文扫描。

## 7. 阶段五：Routing Graph、认证与网络路由

### 建设内容

- 发现 Direct、HTTP Proxy、SOCKS5、System Proxy、VPN/TUN 信息；
- 区分可修改内容的 Model Middleware 与只负责联网的 Network Transport；
- 构建真实 Routing Graph，检测 `CONTENT_MODIFIER_AFTER_DLP`；
- 实现固定 Upstream、域名/IP/端口 allowlist、重定向复检和 SSRF 防护；
- 实现 Passthrough、Bearer、Anthropic Key、Google Key、AWS SigV4、Vertex OAuth 和 Custom Auth；
- 保证 Body 修改完成后再执行 SigV4 等依赖内容的签名；
- 为每个 Surface 绑定独立的 Protocol、Upstream、Auth、NetworkRoute 和 Policy；
- 计算并解释 CoverageSummary 与 ProtectionRisk。

### 完成标准

- 客户端无法通过路径、Header 或 Body 把代理变成开放代理；
- 中间件和网络代理顺序错误可自动修正或明确阻断；
- Bedrock、Vertex 和自定义 Gateway 不因重写 Body 破坏认证；
- 每条出站连接都能追溯到 Manifest 中的 Surface 和 Protection Plan。

## 8. 阶段六：Agent 发现与 Launch/Attach Integration

### 建设内容

- 自动发现 Codex、Claude Code、Hermes、OpenClaw、OpenCode、Cursor、Zed、Cline；
- 读取并解释模型、Provider、Base URL、Fallback、代理和认证类型；
- 为 CLI Agent 实现 Protected Launch 和临时配置注入；
- 为支持动态配置的 Agent 实现 Attach、撤销接管和重连；
- Codex 同时处理 API Key 与 ChatGPT/Codex 登录链路；
- Claude Code 正确保存 Anthropic Upstream 与网络代理顺序；
- 对冲突启动参数、压缩和 WebSocket 绕过做显式阻断；
- 保证不永久修改用户原配置，异常退出后可恢复。

### 完成标准

- 每个 Agent 均有版本化配置 fixture 和真实应用端到端测试；
- Inspect 输出完整 Manifest，运行前展示 Protection Plan；
- 配置或版本未知时不假设兼容；
- Agent 崩溃、Core 崩溃、系统重启后均不存在静默旁路或配置损坏。

## 9. 阶段七：Native、Managed 与 Nested Agent

### 建设内容

- 为 Hermes 实现全部主模型、vision、compression、approval、delegation、fallback 的独立 Surface；
- 为 OpenClaw 实现 Provider Bridge、Gateway 管理、Provider Plugin、ACP 和工具出口发现；
- 提供通用 Native Integration SDK，允许自研 Agent 注册 Surface；
- 提供 Managed Integration 的健康检查、配置变更监听和自动重连；
- 实现父 Session、Child Surface、Protection Token 的上下文传播；
- 子 Agent 加入父 Session，不重复创建 Privacy Proxy；
- 在 Dashboard 中展示完整父子调用树、路由、策略和审计。

### 完成标准

- 主模型之外的辅助、Fallback 和委派链路不会遗漏；
- OpenClaw -> ACP -> Codex/Claude 等嵌套链路只经过一次正确的数据检查点；
- Native Plugin 只报告 Surface 和路由，不自行复制 DLP 逻辑；
- Managed Agent 配置变化会触发重新规划，保护缺口期间默认阻断。

## 10. 阶段八：MCP、Browser 与 Tool Surface

### 建设内容

- 将 MCP stdio、MCP HTTP、MCP SSE/Streamable HTTP 作为正式 Surface；
- 保护 Remote MCP 的 tool arguments、results、resources 和 prompt payload；
- 观察 stdio MCP 子进程自身的网络出口；
- 建立 Browser、Web、Tool HTTP 的协议识别和覆盖分级；
- 为 OAuth、文件上传、下载、WebSocket 和浏览器自动化定义专用策略；
- 对不能安全改写的交互显示 Partial/Observed 并提供阻断选项；
- 形成可扩展 Tool Surface Adapter SDK。

### 完成标准

- Remote MCP 与模型请求使用一致的检测、策略、Vault 和审计核心；
- Local stdio 不被错误宣传为其子进程网络安全；
- Browser 和 Tool HTTP 不采用破坏语义的全局字符串替换；
- 每类特殊传输都有清晰的保护、观察或阻断状态。

## 11. 阶段九：桌面控制面与完整产品体验

### 建设内容

- Agent 自动发现、保护开关和运行状态；
- AgentManifest、Routing Graph、ProtectionPlan 与覆盖率可视化；
- 按 Agent、Surface 和 Session 展示 Protected/Local/Partial/Observed/Unprotected；
- 高危 Finding 的 `ASK` 对话、脱敏预览、一次允许和取消；
- 策略编辑、规则说明、误报反馈和规则测试台；
- 当日统计、历史审计、风险趋势和本地诊断；
- Semantic Model 下载、校验、启停、资源占用和版本管理；
- 系统托盘/菜单栏、开机启动、后台 Core 状态和升级管理；
- 无障碍、国际化和面向普通用户的安全说明。

### 完成标准

- 用户无需重新填写 API Key、Base URL、OAuth 或网络代理即可建立保护；
- UI 状态和 Core 的实时事实一致；
- 每个风险都能解释来源、影响和可选动作；
- 关闭桌面窗口不会意外中断或旁路保护；
- 所有诊断导出默认完成二次脱敏。

## 12. 阶段十：Transparent Mode 与进程出口防绕过

### 建设内容

- 为无法显式接管的闭源客户端提供 allowlist HTTPS MITM；
- 实现本地 CA 的生成、安全存储、安装、轮换、吊销与完整卸载；
- 限制可拦截域名、进程、协议和 Session，禁止成为通用 MITM；
- 观察 Agent Process Tree 与 Descendants 的实际网络连接；
- 将 Expected Route 与 Unexpected Egress 对比并告警；
- 在平台能力允许时提供进程级阻断规则；
- 明确区分 Observed、Blocked 与 Content Protected；
- 验证证书固定、HTTP/3、QUIC、WebSocket 和系统代理变化时的行为。

### 完成标准

- CA 和透明代理可完整、可验证地卸载；
- 非 allowlist 目标永不被解密；
- 无法检查的流量默认阻断或明确报告，不静默直连；
- 进程出口观察不会被描述为内容级保护；
- 显式 Protected Route 始终是优先方案，透明模式不会导致双重代理。

## 13. 阶段十一：跨平台、性能、安全与供应链加固

### 建设内容

- macOS、Windows、Linux 的安装、签名、升级、回滚和卸载；
- 多架构构建、ONNX Runtime/模型分发和硬件能力适配；
- 长上下文、并发 Session、超大 Tool Result 和慢速流压测；
- fuzz、property test、race test、故障注入和崩溃恢复；
- SSRF、开放代理、Token 猜测、CA 滥用、路径穿越和本地权限安全评审；
- 规则包、模型和更新包的签名、校验、回滚与离线验证；
- SBOM、依赖漏洞扫描、可复现构建和发布物证明；
- 安全响应、规则紧急更新、兼容矩阵和用户迁移流程。

### 完成标准

- 完整产品验收标准在三个目标平台通过；
- 所有 fail-closed 场景均有自动化证据；
- P0/P1 安全问题清零，性能达到产品指标；
- 安装、升级、回滚、卸载不会破坏用户 Agent 或系统代理配置；
- 发布文档准确列出每个 Agent、版本、Surface、协议和平台的覆盖状态。

## 14. 工程工作流划分

为便于多人并行，建议长期维护以下工作流：

1. Core/Session：后台服务、本地 API、生命周期和恢复；
2. Protocol/Data Plane：协议 Adapter、Proxy 和流编解码；
3. Detection/Policy：规则、语义模型、策略、Placeholder 和 Vault；
4. Routing/Security：Routing Graph、Auth、Network、SSRF 和透明模式；
5. Agent Integrations：各 Agent 的发现、接管、Native/Managed Plugin；
6. MCP/Tools：MCP、Browser、Tool HTTP 与 Process Egress；
7. Desktop UX：控制面、策略、告警、覆盖率和审计；
8. Quality/Release：跨平台、测试基础设施、供应链和发布。

每个工作流都应以同一套领域契约、安全不变量和验收测试为准，禁止为了单个 Agent 在 Integration 内复制一套检测或策略实现。
