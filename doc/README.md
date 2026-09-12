# AgentVeil 文档中心

AgentVeil 是一个本地优先的 AI Agent 数据安全控制层。它在模型请求离开设备前识别敏感内容，依据策略执行放行、脱敏、询问或阻断，并在模型响应中安全恢复占位符。

> 产品标语：**Keep sensitive data local while your agents work.**

## 文档导航

| 文档 | 内容 | 适合读者 |
|---|---|---|
| [01-product-definition.md](./01-product-definition.md) | 产品定位、完整能力边界与产品验收标准 | 产品、研发、测试 |
| [02-system-architecture.md](./02-system-architecture.md) | 核心架构、数据流、模块边界和领域模型 | 架构、研发 |
| [03-security-and-privacy.md](./03-security-and-privacy.md) | 威胁模型、安全不变量、日志与凭据原则 | 安全、研发、测试 |
| [04-integrations.md](./04-integrations.md) | Agent、协议、网络和认证集成策略 | 研发、测试 |
| [05-detection-and-policy.md](./05-detection-and-policy.md) | 检测管线、占位符、Vault、策略模型 | 算法、研发、测试 |
| [06-development-roadmap.md](./06-development-roadmap.md) | 分阶段路线图、里程碑、质量门禁 | 全体成员 |
| [07-decisions-and-open-questions.md](./07-decisions-and-open-questions.md) | 已收敛决策、待验证事项和非目标 | 产品、架构 |

## 一句话架构

```text
Agent
  -> Content Middleware（如有）
  -> AgentVeil 本地保护路由
  -> Network Transport（Clash / HTTP Proxy / SOCKS5）
  -> Remote Provider
```

AgentVeil 保护的基本单位不是“某个 Agent”，而是 Agent 的每一个 **Egress Surface（数据出口）**，例如主模型、视觉模型、Fallback、远程 MCP、子 Agent 和工具 HTTP。

## 目标产品

AgentVeil 的目标不是一个只支持单一 CLI 或少数协议的脱敏代理，而是一套完整的本地 AI Agent 隐私控制产品：

- 后台 Privacy Core、CLI 与桌面控制面；
- Launch、Attach、Managed、Native 与高级 Transparent Integration；
- Codex、Claude Code、Hermes、OpenClaw、OpenCode、Cursor、Zed、Cline 和自研 Agent；
- 主模型、辅助模型、Fallback、Vision、Embedding、MCP、Browser、Tool HTTP、ACP 与 SubAgent 出口；
- OpenAI Chat、OpenAI Responses、Anthropic Messages、Gemini、MCP 等协议；
- 确定性 PII/Secret、熵检测与本地语义检测；
- 完整 Routing Graph、Protection Plan、覆盖率、策略、审计和进程出口观察；
- 对无法显式接管的客户端提供受限、可审计的透明 HTTPS 模式。

开发路线不以删减完整能力为前提，而是按照依赖关系逐层完成并集成，详见[开发路线图](./06-development-roadmap.md)。
