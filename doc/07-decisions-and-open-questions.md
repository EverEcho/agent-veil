# 决策与待确认事项

## 1. 已收敛决策

| 决策 | 状态 | 原因 |
|---|---|---|
| 项目名使用 AgentVeil，CLI 使用 `veil` | 暂定 | 表达 Agent + 隐私遮蔽，命令简短 |
| 本地优先，不上传敏感原文 | 已定 | 产品信任基础 |
| 保护单位是 Egress Surface | 已定 | 覆盖主模型之外的辅助、Fallback、MCP 与子 Agent |
| Protocol Adapter 与 Agent Integration 分离 | 已定 | 避免重复 DLP，便于测试和扩展 |
| 默认 fail closed | 已定 | 防止未知协议或故障静默泄漏 |
| 显式 Protected Route 优先 | 已定 | 无需根证书，边界更清晰 |
| 确定性规则优先，语义模型补充 | 已定 | 性能、解释性和中文结构化数据准确性更好 |
| Request-scoped 内存 Vault | 已定 | 降低长期敏感数据驻留风险 |
| Core 与桌面控制面进程解耦 | 建议锁定 | 安全核心可独立运行，UI 不承载 DLP 逻辑 |
| Go 实现 Core/CLI | 建议锁定 | 适合本地代理、并发流处理和单文件分发 |

## 2. 架构决策进度

| 事项 | 状态 | 当前答案与退出条件 |
|---|---|---|
| macOS/Linux/Windows 的平台能力差异和统一安全语义 | 部分落地 | 数据面与管理面保持统一 fail-closed 语义，六个 OS/架构目标可交叉构建；只有 Linux 具备受测的进程出口观察与 CA trust-store adapter。macOS/Windows 安装、权限、出口阻断和卸载证据完成前不得宣称平台能力等价。 |
| 目标 Agent 版本与配置入口 | 部分落地 | 编译进二进制并可离线导出的 Compatibility Matrix 是唯一验证事实源。当前 Protected launch 仅覆盖矩阵中标记为 `launch_smoke` 的 Linux Codex 0.153.4、Claude Code 2.1.220 与 Hermes 0.20.6 Surface；其他发现结果不能提升覆盖级别。新增版本必须先增加 fixture、启动证据和精确矩阵记录。 |
| Codex API Key 与 ChatGPT 登录链路的凭据边界 | 已落地（当前范围） | API Key 仅通过 Agent 自身环境读取并由受保护路由引用；无 API Key 时使用 Codex 现有登录能力，Core 不迁移、不存储长期凭据。两条路径都只向子进程下发短期 Session/Route capability。新的登录传输出现时重新进入未验证状态。 |
| `ASK/本次允许` 的一致行为 | 已落地 | 交互 Session 在 Core 内暂停并创建一次性审批，只接受 `allow/redact/block`；Dashboard 与 `veil approvals` 使用同一版本化 API。取消等同阻断，超时阻断，非交互 Session 将 `ASK` 直接按 `BLOCK` 执行。Finding 只暴露位置和分类元数据，不暴露原文。 |
| 默认 PII 策略与 Action | 已落地（可配置） | 默认 Action 为 `REDACT`，`secret.private_key` 显式为 `BLOCK`。用户可通过同一 Policy Document 在 Dashboard 或 `veil policy` 覆盖；重复 Scope、无效 Action、原始工作区路径和未知字段均拒绝。误报反馈只保留本地有界元数据，不自动弱化策略。 |
| 审计保留期与工作区路径 | 已落地 | 默认保留 30 天，可用正时长配置覆盖；文件最大 64 MiB 并优先压缩最旧事件。工作区使用 `sha256:` 截断哈希引用，不持久化原始路径。CLI、Dashboard 和诊断导出均只读取元数据。 |
| 本地 HTTP Upstream | 已落地 | 远端默认只允许 HTTPS；HTTP 仅允许明确识别的 loopback 主机（`localhost` 或数字 loopback 地址），且必须来自 Protection Plan 的固定 Upstream。UI 将 Local 与 Protected 分开表达，不把明文或本地跳转宣传为内容保护。 |
| 本地语义模型的体积、许可证、中文基准和下载方式 | 未完成 | Core 只接受不超过 512 MiB 的签名模型并支持流式安装、校验、启停和回滚；具体模型、许可证、中文基准、硬件分档和可信下载源仍需产品与发布决策，在此之前不内置或自动下载模型。 |

## 3. ADR 状态

- 桌面技术栈、托盘/自启动/升级机制和 Core 安装生命周期：**待决策**；
- Policy v1 JSON、Scope 优先级、显式 BLOCK 不降级与原子持久化：**实现已锁定，仍需迁移 ADR**；
- HMAC-SHA256 Session 稳定占位符、截取长度、碰撞阻断和请求级 Vault：**实现已锁定，仍需 prompt cache 影响 ADR**；
- `SHA-256(chunk)` 有界缓存只保存 Finding 相对位置、不保存原文，策略逐请求重算：**实现已锁定**；
- Bedrock SigV4、Vertex OAuth 与 Custom Auth 的运行时凭据边界：**接口已锁定，新增 Provider 前需逐项安全 ADR**；
- 透明 MITM CA 的生成、安装、轮换、吊销和卸载：**Linux 原语与回滚已实现，完整产品 ADR 和 macOS/Windows 方案未完成**；
- 规则包与模型包使用独立 Ed25519 trust root、规范签名载荷、原子激活和回滚：**实现已锁定，分发与紧急更新流程未完成**；
- 进程出口观察与阻断权限模型：**Linux 观察和启动进程组 fail-closed 已实现，跨平台与 pre-connect 阻断 ADR 未完成**。

## 4. 产品表述边界

可以承诺：

- “受支持的 Protected Route 会在本机完成检查”；
- “检测或解析失败时请求不会静默发送”；
- “敏感映射不持久化到磁盘”；
- “清楚展示发现但未保护的出口”。

现阶段不能承诺：

- “100% 识别所有敏感信息”；
- “保护电脑上的所有 AI 应用”；
- “任何插件、浏览器和子进程都无法绕过”；
- “等同于合规认证或完整匿名化”；
- “安装后无需验证即可兼容未来所有 Agent 版本”。

## 5. 文档维护约定

- 架构、安全边界或阶段范围变化时，同步更新对应文档和本页决策状态；
- 新增兼容逻辑前先明确记录需要兼容的版本、退出条件和测试 fixture；
- 路线图完成项以自动化验收证据为准，不以代码合并为准；
- 外部项目只作为设计参考，不直接把其宣传口径当作 AgentVeil 的安全保证。
