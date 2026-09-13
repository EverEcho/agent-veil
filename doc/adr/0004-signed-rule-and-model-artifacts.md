# ADR-0004：签名规则包与语义模型制品

- 状态：已接受
- 范围：`internal/rulestore`、`internal/modelstore`、Core、Dashboard、CLI

## 决策

规则包与模型包使用相互独立的 Ed25519 trust root。Manifest v1 的规范签名载荷
绑定 schema、version、size 和 SHA-256；base64、摘要和签名必须采用规范编码。
安装仅接受有界输入，在私有 staging 目录完成签名、大小、摘要及格式校验后原子
发布版本目录。

Active pointer 单独原子切换。激活前重新打开并验证完整制品；规则编译或语义模型
加载失败时保留旧数据面。Active 版本不能删除，停用后可删除；启动时任何损坏、
宽权限、符号链接、歧义 JSON 或不一致 pointer 都失败关闭。

Core 是唯一验证与切换主体。Dashboard 和 CLI 只通过认证、版本化的 loopback
管理 API 提交制品；模型上传流式传输且 Content-Length 必须与签名 Manifest 一致。

## 理由

独立 trust root 限制规则发布与大型模型供应链的相互影响。不可变版本目录与小型
Active pointer 使更新可回滚，且不会向并发请求暴露部分写入或半加载状态。

## 后果与验证

- 规则包最大 1 MiB，模型制品最大 512 MiB，已安装版本数均有上限；
- CLI 拒绝符号链接、非普通文件、未知字段、重复键和大小不一致，且不跟随重定向；
- Store 与 Core 测试覆盖签名、摘要、并发安装、激活、停用、删除、权限和崩溃残留；
- 可信下载源、模型许可证、中文基准、紧急签名轮换和离线分发仍是发布流程开放项。
