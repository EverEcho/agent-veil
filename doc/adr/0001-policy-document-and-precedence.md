# ADR-0001：Policy Document 与优先级

- 状态：已接受
- 范围：`internal/policy`、Core 管理 API、Dashboard、CLI

## 决策

Policy 使用严格的 v1 JSON Document，包含一个默认 Action 和有界 Rule 列表。
Scope 可组合 Agent、工作区哈希、Provider、Surface 和 Finding Type。匹配时按
Scope 字段的确定性权重选择最具体规则；任意匹配的显式 `BLOCK` 不会被另一个
非阻断规则降级。重复 Scope 属于歧义配置并拒绝加载。

`ALLOW / REDACT / BLOCK / ASK` 由 Core 统一执行。`ASK` 只在交互 Session 中
创建一次性审批，最终只接受 `allow/redact/block`；非交互、取消或超时均阻断。
策略更新先完整验证并原子持久化，再替换内存 Engine。

## 理由

确定性优先级让 Dashboard、CLI、Native/Managed Integration 和数据面得到同一
结果。显式 BLOCK 不降级避免更具体但低风险的规则意外覆盖安全禁令。严格 JSON
与原子替换避免重复键、未知字段或部分写入改变运行中语义。

## 后果与验证

- 默认策略为 `REDACT`，`secret.private_key` 显式 `BLOCK`；
- 工作区 Scope 只能使用 `sha256:` 引用，不能保存原始路径；
- Dashboard 与 `veil policy` 使用同一 `/v1/policy` API；
- Policy 单测覆盖优先级、重复 Scope、非法标识和持久化权限；Core/CLI 测试覆盖
  原子更新、预览和无歧义解码。

未来 schema 或迁移必须提升版本并在替换旧 Engine 前完成离线校验，不能静默
改变既有规则含义。
