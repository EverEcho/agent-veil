# ADR-0007：Codex Desktop 受保护启动

- 状态：部分接受
- 范围：macOS Codex Desktop、Go Launch Integration、Tauri 控制入口

## 决策

Codex Desktop 与终端 Codex 分开发现和维护兼容矩阵。AgentVeil 不重做 Codex
界面，也不永久修改 `~/.codex`。用户从 AgentVeil 点击启动后，Go Launch
Integration 创建私有会话、Protected Route 和会话级 `CODEX_HOME`，复制现有
认证状态并写入临时 Provider 配置，再启动官方 App 主程序。

Tauri 只负责调用 Go 启动器和显示结果，不持有 Route capability，也不实现 DLP。
如果官方 App 已经运行，启动器拒绝宣称 Attach 成功；用户需要先退出再重新启动。

## 当前声明边界

当前兼容记录只覆盖内置 Codex 0.154.0 的 OpenAI Responses 主模型配置解析和
launch smoke。App Tools、本机 MCP、Shell 及其子进程出口单独展示，不能借用主
模型 Route 声明为内容已保护。真实 Provider 往返、macOS 进程级 pre-connect
阻断和版本升级回归完成前，不扩大兼容声明。

## 透明模式关系

透明 MITM 是无法显式注入 Provider 时的用户可选备选方案，默认关闭。它必须复用
相同 Protocol Adapter，并满足精确 Session、进程身份和域名 Scope；安装 CA、
系统代理或阻断规则均需独立授权与可验证卸载。透明数据面未完成前，UI 只展示
开发状态，不提供会造成虚假保护预期的启用开关。
