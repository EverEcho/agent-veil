# AgentVeil

> Keep sensitive data local while your agents work.

AgentVeil 是一个本地优先的 AI Agent 隐私控制层。它位于 Agent 与模型、远程 MCP 等数据出口之间，在请求离开设备前识别敏感内容，并按策略执行放行、脱敏、询问或阻断；对于被替换的内容，则在响应返回时于本机安全恢复。

## 这个项目是什么

AgentVeil 保护的不是一个笼统的“AI 应用”，而是 Agent 的每一个数据出口，例如主模型、辅助模型、Fallback、远程 MCP、子 Agent 和工具请求。

它由三个部分组成：

- **Privacy Core**：负责协议解析、敏感信息检测、策略决策、占位符与本地审计；
- **CLI**：负责发现 Agent、检查保护范围和启动受保护会话；
- **Desktop**：提供发现、路由、审批、策略和审计的可视化控制面。

当前支持范围和真实验证状态会持续变化，请以[开发进度](doc/09-development-progress.md)和[兼容性说明](doc/04-integrations.md)为准。能够发现某个 Agent 或数据出口，并不代表它已经受到完整保护。

## 为什么需要 AgentVeil

AI Agent 会主动读取代码、配置、日志、工具结果和本地文件，这些上下文中可能包含 API Key、客户资料、账号信息或其他不应离开设备的数据。普通网络代理只能转发流量，简单的文本替换也不了解模型协议、流式响应和工具调用结构。

AgentVeil 的意义是：

- 尽可能让敏感原文留在本机，同时保留原有 Agent、模型账号和网络环境；
- 按协议理解真正承载业务内容的字段，避免对整个请求做无差别替换；
- 明确展示每个数据出口是 `Protected`、`Local`、`Partial`、`Observed` 还是 `Unprotected`；
- 在无法确认安全处理时默认阻断，避免静默旁路；
- 只保留隐私安全的本地审计信息，不把 AgentVeil 变成新的敏感数据汇聚点。

AgentVeil 不能保证识别所有语义敏感信息，也不等同于匿名化工具或合规认证。完整的能力边界见[产品定义](doc/01-product-definition.md)和[安全与隐私](doc/03-security-and-privacy.md)。

## 怎么用

优先使用对应平台的 Desktop 安装包。启动 AgentVeil 后：

1. 在 Dashboard 中发现本机已有的 Agent 和数据出口；
2. 查看 Protection Plan，确认哪些出口已保护、哪些仍存在风险；
3. 从 AgentVeil 启动受保护的 Agent；
4. 在 Dashboard 中处理 `ASK` 请求，并查看会话、路由和隐私安全审计。

如果使用 CLI，可先查看 Core 状态和本机 Agent，再启动受支持的保护会话：

```bash
veil status
veil discover
veil inspect codex
veil run codex
```

Codex Desktop 可通过以下命令由 AgentVeil 创建隔离的受保护会话：

```bash
veil run codex-desktop
```

具体 Agent、版本、平台和数据出口是否支持 Protected Launch，以 Dashboard 展示及[开发进度](doc/09-development-progress.md)为准。不要将“已发现”或“可启动”理解为所有 Agent 流量都已受到保护。

## 文档

- [文档中心](doc/README.md)：产品、架构、安全、集成、策略、进度与决策；
- [开发指南](doc/11-development-guide.md)：环境准备、项目结构、启动、构建和测试；
- [发布渠道](doc/10-release-channels.md)：`dev`、`beta`、`main` 的质量定义与发布规则。

项目仍在持续开发中。正式使用前，请先确认当前版本的兼容范围和未完成边界。
