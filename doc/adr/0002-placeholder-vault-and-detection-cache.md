# ADR-0002：占位符 Vault 与检测缓存

- 状态：已接受
- 范围：`internal/redactor`、`internal/detector`、请求/响应数据面

## 决策

占位符 ID 使用 `HMAC-SHA256(SessionSecret, Type || NUL || Original)` 的前 64 bit，
格式为 `[[VEIL_<TYPE>_<ID>]]`。同一 Session 的相同类型与原文保持稳定，不同
Session 不可关联；发生 ID 碰撞且原文不同时立即阻断。

映射只保存在每个请求独立、容量有界的内存 Vault。请求完成、失败或取消后销毁
Vault 并清零保存的原文字节。容量耗尽、未知占位符、畸形占位符和跨请求恢复都
失败关闭。

长文本按 UTF-8 安全边界和 overlap 分块。检测缓存键为
`SHA-256(path || NUL || chunk)`，值只保存去掉 Path 的 Finding 相对位置，不保存
原文或 Match Value；缓存条目有固定上限并淘汰最旧项。Policy 不进入缓存，每个
请求都根据当前策略重新求值。

## 理由

Session 稳定 ID 保留对话缓存价值，同时请求级映射限制敏感原文驻留时间。将 Path
纳入缓存键避免同一文本在具有协议语义差异的位置间错误复用；仅缓存 Finding
元数据避免为了性能复制敏感内容。

## 后果与验证

- 流式恢复允许占位符跨逻辑事件分片，但未闭合或未知值不能提前输出；
- 只有完整、未变形且属于本次请求的占位符可以恢复；逐字符拆分、插入分隔符或其他变形作为不透明文本透传，不得据此变换或恢复原文；
- 缓存命中仍从本次输入切取 Match Value，并重新执行合并与 Policy；
- 单测覆盖 Session 内稳定性、跨 Session 不可关联、碰撞、Vault full、销毁、
  缓存上限、路径隔离、UTF-8 与 overlap 边界；
- 若未来需要跨进程缓存或改变 ID 长度，必须新建 ADR 并重新评估可关联性、碰撞率
  与 prompt cache 影响。
