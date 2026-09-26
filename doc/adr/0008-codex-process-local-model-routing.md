# ADR-0008：Codex 进程级模型路由

- 状态：实施中
- 范围：Codex CLI、macOS Codex Desktop

## 决策

受保护的 Codex 继续使用原 `CODEX_HOME` 和内置 `openai` provider。CLI 使用当前进程的
`-c model_provider="openai"`、`-c openai_base_url=...`；桌面版使用已核对的
`CODEX_APP_SERVER_OPENAI_BASE_URL` 映射，并强制启动当前 App 自带的 app server，避免
连接已有 daemon。Veil 不再为新启动创建私有 Codex Home，不链接原 `sessions` 或 SQLite，
也不把临时 `agentveil` provider 写入会话元数据。旧版专用 Home 只由已有残留清理代码处理。

模型 URL 使用 Veil Route 已有的路径能力令牌。代理先验证令牌，剥离能力路径，再把
`/responses` 映射到原上游路径；能力令牌不会发往模型服务。CLI 的进程参数包含该
临时令牌，启动器不能将参数或完整模型 URL 写入日志。令牌随受保护会话结束失效。

当前 Codex 内置 provider 会先尝试 WebSocket。Veil 对经授权的模型 WebSocket 升级
返回 `426`，使 Codex 立即改用可检查的 HTTP Responses；其他不支持的协议升级仍拒绝。
应用连接、浏览器、MCP、Shell 及其子进程的网络流量不由模型 Route 保护，客户端
必须明确显示这个范围。

桌面启动前检查安装包中是否具有进程级模型 URL 映射，并校验自带 app server；
不支持时直接失败，不能先关闭原 Codex。确认可启动后，才以精确 GUI 进程匹配发送
`SIGTERM` 并等待退出；绝不 `SIGKILL`。受保护 Codex 仍运行时，Veil 留在托盘并保持
代理；完全退出保护需要先正常关闭 Codex。之后普通 Codex 使用同一会话目录，无需
历史迁移。旧版已被临时 provider 写入的损坏会话需要单独修复。

## 验证边界

已在临时 Home、假凭据与本地假代理上验证 CLI、桌面内置 app server 的模型请求路由
和 `openai` 会话元数据，且路径令牌及 `426` 回退已有 Mock 测试。真实账号、官方 GUI
完整对话、应用升级和异常退出仍需端到端验证；在此之前不扩大保护范围声明。
