# 检测与策略

## 1. 检测管线

```text
Extracted Content
  -> Feature Scanner
  -> Exact / Prefix Scanner
  -> Regex Detector
  -> Structured Validator
  -> Entropy Detector
  -> Semantic Detector（可选）
  -> Finding Merge
  -> Policy Engine
```

确定性规则是基础，语义模型作为完整管线中的补充。即使语义模型不可用，高确定性的 PII 和 Secrets 仍必须被可靠保护；若策略要求语义检测，则模型不可用时必须失败关闭。

## 2. Finding 模型

Finding 至少包含：规则 ID、类别、严重级别、内容位置、置信度、来源 Detector 和建议动作。Finding 仅描述“检测到了什么”，最终动作由 Policy 决定。

重叠 Finding 合并规则：

1. 已通过校验器的高确定性结果优先；
2. Secret 优先于一般高熵文本；
3. 更具体的规则优先于宽泛规则；
4. 无法安全拆分的重叠区间按最高严重级别整体处理；
5. 合并过程不得把原文写入日志。

## 3. 性能预筛

每条规则声明 Required Features，例如数字、`@`、`_`、`-`、`.`、`/`、`=`。一次线性扫描后跳过不可能命中的 Regex。

对 `sk-`、`ghp_`、`github_pat_`、`AKIA`、`xoxb-`、`glpat-`、`AIza` 等使用 Trie、Aho-Corasick 或前缀匹配先定位候选，再做格式和上下文校验。

## 4. 结构化 PII

完整规则库应内置：

- 中国大陆手机号、固定电话；
- 居民身份证：格式、日期、行政区基础校验、MOD 11-2；
- 银行卡：格式与 Luhn；
- 统一社会信用代码：格式与校验码；
- Email、IPv4/IPv6、MAC；
- 可可靠校验的护照/车牌规则。

姓名、详细地址、联系人描述属于语义能力，不能用高误报正则强行覆盖。

## 5. Secret 检测

完整规则库覆盖：

- OpenAI、Anthropic、Google、GitHub、GitLab、AWS；
- Slack、Stripe、JWT、Bearer；
- 完整 PEM Private Key 块（必须包含可解码的头、密钥载荷和对应结尾；源码中的单独示例标记不判为私钥）；
- 敏感环境变量赋值，包括 `PASSWORD`、`TOKEN`、`SECRET`、`API_KEY`、`ACCESS_KEY`、`AES_KEY/AES_IV`、`SALT` 等后缀；兼容 Markdown 转义的下划线，并跳过变量引用、占位符、布尔/空值哨兵、常见示例值和不足 6 个字符的非可信字面量；
- 数据库连接串；
- 国内主要云厂商与模型 Provider 的可稳定识别格式。

未知 Token 使用长度、字符集、熵、附近关键词和已知占位符排除共同判断，不能只按熵值阻断所有随机字符串。

IPv6 只有在包含足够地址信息时才作为网络标识处理；`::`、`::1` 和 `a::b` 等非识别性地址或常见源码片段不进入脱敏流程。

## 6. Capture Group

规则只替换真正的 Secret，保留上下文。例如：

```text
Authorization: Bearer eyJ...
```

处理后应为：

```text
Authorization: Bearer [[VEIL_JWT_...]]
```

不得把整个 Header 语义抹掉。

## 7. 长上下文与缓存

长文本按稳定边界切片，优先换行、空格和 UTF-8 rune boundary；硬切片时保留 overlap，避免实体跨边界漏检。

重复 Conversation History 可按 `SHA-256(chunk)` 缓存 Finding。缓存中保存相对位置和类型，不保存额外原文副本；策略变更后仍需重新执行 Policy。

## 8. Policy

动作模型：

```text
ALLOW   明确放行
REDACT  替换后发送
BLOCK   不发送
ASK     暂停并请求一次性决定（非交互环境按 BLOCK）
```

覆盖层级建议：

```text
Global -> Agent -> Workspace -> Provider -> Surface -> Finding Type
```

更具体的规则覆盖更宽泛规则；任何层级的显式 BLOCK 不应被低可信来源自动降级。

面向普通用户的设置开关必须落到同一份 Policy，而不是绕过 Detector：联系方式、身份与财务信息、敏感环境变量、数据库连接凭据、常见服务密钥、疑似未知密钥和网络标识可以分别开启或关闭。开启生成对应 `finding_type: REDACT` 规则，关闭生成 `finding_type: ALLOW` 规则；Agent、Workspace、Provider、Surface 的高级规则继续保留。私钥默认显式阻断，但 Dashboard 提供 `BLOCK`、`REDACT`、`ASK` 和高风险 `ALLOW` 选择；选择默认 Action 时删除冗余的全局私钥规则。协议解析与未知协议失败关闭、响应检查、Placeholder/Vault 边界不作为普通设置开关。

示例：

```yaml
rules:
  secret.private_key: { action: block }
  secret.openai_key:  { action: redact }
  secret.github_pat:  { action: redact }
  pii.cn.phone:       { action: redact }
  pii.cn.id_card:     { action: redact }
  pii.email:          { action: redact }
```

## 9. Placeholder 与 Vault

推荐格式：

```text
[[VEIL_PHONE_4E13FA917EB2621A]]
```

ID 使用 `HMAC-SHA256(SessionSecret, Type || Original)` 截取至少 64 bit。相同 Session 内同一类型和原文保持稳定，不同 Session 不可关联。

稳定占位符不等于长期保存映射。每个请求建立有界内存 Vault，保存 `Placeholder -> Original`，响应完成或失败后立即销毁；Vault full 必须阻断。

## 10. Response DLP

Provider 响应先检查：

- 是否包含请求原文；
- 是否包含新的 credential-shaped secret；
- 是否包含 Private Key；
- 是否有畸形或伪造的 AgentVeil 占位符。

随后才恢复当前请求 Vault 中已知占位符。未知占位符不得猜测或跨 Session 恢复。
响应发现继续遵循同一 Policy：`redact` 只替换命中的响应内容并保持协议正常结束，显式 `block` 才终止响应。只有完整、未变形且属于当前请求 Vault 的占位符可以恢复；逐字符拆分、插入分隔符或其他变形可以作为不透明文本正常透传，但绝不能据此变换或恢复原文。

## 11. 开发模式与误脱敏排查

Dashboard 可显式开启开发模式。每条请求诊断记录包含协议、端点、正文处理前后字节数，以及每个 Finding 的规则、类型、Detector、Policy Action、字段路径、字节偏移、命中长度与置信度。默认仍不保存原文；高风险“记录原始请求正文”是独立二次开关，启用后保存有界的脱敏前和上游请求正文，用于对照是否误脱敏。安全审计、诊断导出与开发日志保持独立，关闭开发模式不会继续写入新记录。
