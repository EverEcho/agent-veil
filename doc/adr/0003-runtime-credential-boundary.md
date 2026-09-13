# ADR-0003：运行时凭据边界与签名顺序

- 状态：已接受
- 范围：`internal/auth`、Protected Route、Agent launch

## 决策

Manifest 只保存凭据的间接 Source，例如 `environment:NAME`，不保存凭据值。
Core 在请求发送前按 Route 的 AuthStrategy 从运行环境解析 Bearer、Anthropic、
Google、Vertex 或 AWS 凭据；Passthrough 仅用于已经由受保护 Agent 请求携带的
认证。Custom Auth 没有显式注册 signer 时拒绝运行。

所有协议解析、检测、Policy 和 Body 重写完成后才应用认证。AWS SigV4 只允许
识别出的 HTTPS Bedrock Endpoint，并对最终方法、路径、查询、Header 和 Body
签名。Upstream 固定在 Protection Plan 中，客户端输入不能选择认证目标。

Protected child 只接收短期 Session/Route capability。Core 管理 Token 不进入
子进程；长期 Provider 凭据不写入 Manifest、Session、审计或诊断。

## 理由

将身份解析放在 Core 的最后发送阶段可以避免重写后签名失效，也避免 Integration
各自复制认证逻辑。间接引用允许继续使用 Agent/OS 已有凭据，而无需建立新的长期
Secret Store。

## 后果与验证

- 环境变量名、Credential Source 和 Bedrock Endpoint 使用严格 allowlist；
- Upstream 重定向必须重新通过精确 origin allowlist，Provider CookieJar 状态不
  持久化或重放；
- 测试覆盖 Bearer/Anthropic/Google/Vertex、SigV4 重签名、错误 Source、目标混淆
  和管理 Token 隔离；
- 新增 OAuth 刷新、Keychain、Custom signer 或 Provider 前，必须记录其最小权限、
  生命周期、刷新失败和日志边界。
