# AgentVeil 架构决策记录

本目录记录已经影响安全边界或跨模块契约的决策。状态为“已接受”的 ADR
描述当前实现必须保持的不变量；状态为“部分接受”的 ADR 只锁定已实现范围，
其开放项不能据此宣传为已完成能力。

| ADR | 状态 | 主题 |
|---|---|---|
| [0001](./0001-policy-document-and-precedence.md) | 已接受 | Policy v1、层级优先级和显式 BLOCK |
| [0002](./0002-placeholder-vault-and-detection-cache.md) | 已接受 | Session 稳定占位符、请求级 Vault 和检测缓存 |
| [0003](./0003-runtime-credential-boundary.md) | 已接受 | 运行时凭据解析与内容签名顺序 |
| [0004](./0004-signed-rule-and-model-artifacts.md) | 已接受 | 规则包与模型包签名、安装和回滚 |
| [0005](./0005-transparent-mode-boundary.md) | 部分接受 | 透明模式作用域、CA 生命周期和平台边界 |
| [0006](./0006-desktop-shell-and-core-lifecycle.md) | 部分接受 | Tauri 统一 GUI、托盘、自启动与 Core 生命周期 |

尚未形成可执行决策的系统安装/升级、模型分发来源，以及
macOS/Windows 的透明阻断方案继续保留在
[决策与待确认事项](../07-decisions-and-open-questions.md)中。
