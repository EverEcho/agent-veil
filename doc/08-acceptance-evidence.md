# 产品验收证据

本文逐条追踪[完整产品验收标准](./01-product-definition.md#7-完整产品验收标准)。状态只表示当前仓库已有的可复现证据，不以代码存在、编译成功或界面展示作为完成依据。

状态定义：

- **自动化通过**：仓库测试可以直接证明该条标准在所列范围内成立；
- **部分通过**：已有自动化证据，但仍缺真实应用、目标平台或尚未实现的子能力；
- **外部阻塞**：需要产品/发布决策、签名身份、真实应用版本或目标操作系统环境，不能由当前 Linux 仓库单独闭环。

## 证据矩阵

| # | 当前状态 | 自动化证据 | 尚未闭环的退出条件 |
|---|---|---|---|
| 1 | 部分通过 | `internal/integration` 的各 Agent 配置解析、未知版本阻断和 Hermes 全 Surface 测试；`internal/planner` 的覆盖率测试；`internal/compatibility` 的平台/版本矩阵测试 | Codex、Claude、Hermes 以外目标 Agent 的真实版本 fixture 与完整 Surface 实机核对 |
| 2 | 部分通过 | `cmd/veil` 的 Protected Launch、进程组清理、Managed Monitor 与 Native lease 测试；`sdk/native`；`internal/transparent` 的 CA 生命周期测试 | 通用 Attach 尚未实现；Transparent 数据面尚未完成；五种模式仍需真实应用验证 |
| 3 | 部分通过 | `TestProtocolFixturesExtractOnlyBusinessContentAndRoundTrip`、`TestNonStreamingResponseProtocolMatrixRestoresPlaceholders`、`TestSSEProtocolMatrixRestoresFragmentedPlaceholders`、`TestEndToEndProtocolMatrixOnlySendsRedactedContentToProvider` 覆盖 OpenAI Chat/Responses、Anthropic、Gemini、MCP Streamable HTTP | MCP legacy SSE 当前明确为 Observed，完成适配前不能把整个 MCP 范围标为完成 |
| 4 | 自动化通过（显式 Route） | `TestUnknownProtocolAndCompressionFailClosed`、`TestMalformedProtocolEnvelopesFailClosed`、`TestProxyRejectsUnboundedRoutesAndBodies`、`TestExternalOriginIsRejectedBeforeForward`、Pipeline 的 Vault/Detector/Semantic failure 测试 | Transparent 数据面加入后需复用同一套失败关闭证据 |
| 5 | 自动化通过 | `internal/redactor` 的 Session 隔离、确定性映射、容量和清理测试；Pipeline 请求/响应 round-trip；Session 删除与过期擦除测试 | 真实应用长时运行仍属于验收 2 的实机验证范围 |
| 6 | 自动化通过 | `TestSSEPlaceholderCrossesEventsWithoutTouchingSignature`、`TestSSEProcessorBlocksCredentialSplitAcrossEvents`、随机 SSE 分片 fuzz、各 Provider 流式矩阵 | 新协议或新事件字段加入时必须扩展同一矩阵 |
| 7 | 自动化通过 | `internal/audit`、`internal/diagnostic` 的二次扫描与敏感字段拒绝测试；CI 使用 canary 扫描完整测试输出 | 正式安装器和更新器产生的日志尚不存在，加入后需纳入扫描 |
| 8 | 部分通过 | `internal/routing` 的 DLP 后内容修改阻断；Registry call tree；Linux Process Tree/Unexpected Egress 测试 | 非 Linux 出口观察、真实中间件链路和 Transparent pre-connect 阻断未完成 |
| 9 | 部分通过 | Planner 禁止将不完整能力标成 Protected；Compatibility Matrix 是唯一验证事实源；Dashboard/CLI 从同一 Core API 读取 Agent、Session、Call Tree 与覆盖率 | 当前 Dashboard 是 Core 内嵌本地页面，不是具备托盘/生命周期的正式桌面应用 |
| 10 | 部分通过 | 临时 Launch 配置清理、Session/lease 级联撤销、能力内存擦除、CA 中断恢复与可验证卸载测试 | Core/桌面进程崩溃、系统重启和三平台安装生命周期的实机故障注入 |
| 11 | 部分通过 | CI 对 Linux/macOS/Windows 的 amd64/arm64 交叉构建；统一 Core 数据面测试；Linux CA trust-store 与出口观察测试 | macOS/Windows 安装、权限、安全存储、出口阻断、升级/回滚/卸载实机证据 |
| 12 | 自动化通过（模拟 Provider） | `TestEndToEndProviderOnlyReceivesRedactedContent` 和六协议 `TestEndToEndProtocolMatrixOnlySendsRedactedContentToProvider` 证明 Provider 只收到允许或脱敏内容 | 各 Compatibility Matrix 中版本的真实 Provider/Agent 端到端验证仍归验收 1、2 |

## 可复现命令

所有自动化证据由 CI 的 `verify`、`fuzz`、`cross-build`、`reproducible-build`、`vulnerability-scan`、`sbom` 和 tag-only `release-evidence` 作业执行。开发机使用与 CI 相同的核心入口：

```bash
go vet ./...
go test -race ./...
VEIL_PERFORMANCE_GATE=1 go test ./internal/pipeline -run '^TestPureRulePipelineP95Budget$' -count=1 -v
```

协议到模拟 Provider 的关键验收可以单独复跑：

```bash
go test ./internal/proxy -run '^TestEndToEndProtocolMatrixOnlySendsRedactedContentToProvider$' -count=1 -v
go test ./internal/pipeline -run '^(TestNonStreamingResponseProtocolMatrixRestoresPlaceholders|TestSSEProtocolMatrixRestoresFragmentedPlaceholders|TestSSEProtocolMatrixBlocksNewCredentials)$' -count=1 -v
```

## 不可由仓库自行关闭的事项

以下事项必须保留为显式阻塞，不能用单元测试、交叉编译或模拟 Provider 替代：

1. 桌面技术栈、托盘、自启动、升级机制和 Core 安装生命周期决策；
2. 语义模型选型、许可证、中文基准、硬件分档和可信下载源；
3. macOS、Windows 的签名身份、权限和真实安装/卸载环境；
4. 每个受支持 Agent 精确版本的真实应用启动、接管和崩溃恢复证据；
5. Transparent MITM 完整数据面、平台级 pre-connect 阻断和证书固定/QUIC/WebSocket 验证；
6. 正式制品发布授权、分发渠道和紧急更新流程。

这些退出条件完成前，README 和 Compatibility Matrix 必须继续使用 Partial、Observed、Unprotected 或“未验证”的准确表述。
