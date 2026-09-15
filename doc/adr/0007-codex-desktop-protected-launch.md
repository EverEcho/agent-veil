# ADR-0007：Codex Desktop 受保护启动

- 状态：部分接受
- 范围：macOS Codex Desktop、Go Launch Integration、Tauri 控制入口

## 决策

Codex Desktop 与终端 Codex 分开发现和维护兼容矩阵。AgentVeil 不重做 Codex
界面，也不永久修改 `~/.codex`。用户从 AgentVeil 点击启动后，Go Launch
Integration 创建私有会话、Protected Route 和稳定的 AgentVeil 专用 `CODEX_HOME`，复制现有
认证状态并写入临时内置 `openai` Provider Base URL，再启动官方 App 主程序。原
`sessions`、归档会话和历史数据库以受控符号链接接入专用 Home，使旧对话可见且
新对话继续持久化；用户配置、认证文件和运行时 IPC 不共享。可能成为沙箱可写根的
`visualizations`、`generated_images`、`attachments`、缓存及工具运行目录必须在
专用 Home 中实体化，不得链接到 `~/.codex`；其中用户可见产物跨受保护启动保留，
缓存与临时状态在退出时清理。SQLite 数据库及其
WAL/SHM 不得使用硬链接接入：同一数据库经不同路径打开会形成分离的 WAL/锁域并
可能损坏历史投影库。退出后清除认证、Provider 配置和运行时状态，但保留分别指向
原 `sessions` 与 `archived_sessions` 的路径转发。Codex 会把 `rollout_path` 记录为
`CODEX_HOME` 下的绝对路径，因此这些稳定路径不能随会话删除，否则对话将无法恢复
或删除。

启动器不设置 `allow_symlinked_codex_home`。该兼容开关会把专用 Home 下所有可写
符号链接目标纳入信任，超出 AgentVeil 对单一持久状态路径的最小授权边界。

终端 Codex 不需要隔离 Home：启动器采用一次性的 `-c` Provider 覆盖，保留用户原
Home。官方桌面 App 没有同等可靠的参数注入入口；直接使用 `~/.codex` 将要求永久
改写用户 `config.toml`，所以桌面版仍使用专用 Home，但不再为每次启动生成随机路径。

主模型 HTTP 元数据保持透明：Provider 账户、功能、版本、追踪请求头和查询参数
不做 DLP 改写；隐私规则只处理协议正文中的语义内容及 SSE 事件内容。AgentVeil
自己的能力头、Cookie、Provider `Set-Cookie` 和 hop-by-hop 头仍按安全边界剥离。

Tauri 只负责调用 Go 启动器和显示结果，不持有 Route capability，也不实现 DLP。
它通过精确匹配官方 GUI 主进程显示运行状态，同时以自己持有的 Go 启动器子进程
判断该运行实例是否由当前 AgentVeil 启动。已有受保护实例时不重复启动；只有普通
GUI 进程存在时，先发送 `SIGTERM`，最多等待 5 秒并确认退出，再调用 Go 启动器。
无法读取进程状态或旧进程未按时退出时安全失败，不使用 `SIGKILL`，也不把正在
运行的普通实例宣称为已 Attach 或已保护。Go 启动器仍保留启动前的独立进程检查，
防止竞态窗口内出现第二个实例。

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
