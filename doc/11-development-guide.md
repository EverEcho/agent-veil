# 开发指南

本文集中说明 AgentVeil 的本地开发入口。产品定位、系统设计和当前完成度分别见[产品定义](./01-product-definition.md)、[系统架构](./02-system-architecture.md)和[开发进度](./09-development-progress.md)。

## 1. 环境要求

- Go 1.23 或更高版本；
- Rust 1.88 或更高版本；
- Tauri 2 CLI；
- 当前平台所需的 [Tauri 系统依赖](https://v2.tauri.app/start/prerequisites/)。

根目录的 `run.sh` 会检查 Go、Cargo 和 Tauri CLI。缺少 Tauri CLI 时，它会通过 Cargo 安装兼容的 2.x 版本，因此首次运行需要网络连接。

## 2. 项目结构

| 路径 | 作用 |
|---|---|
| `cmd/veil/` | Core 与 CLI 入口 |
| `internal/` | 协议、检测、策略、代理、集成和本地管理面 |
| `sdk/` | Native、Attach 和 Tool Surface Adapter SDK |
| `desktop/` | Tauri 2 桌面壳 |
| `doc/` | 产品、架构、安全、开发进度、验收与 ADR |

Desktop 与浏览器模式共用 Core 提供的 Dashboard。Tauri 只负责桌面生命周期、托盘、单实例和受限的本地 API 桥接，不在桌面层复制隐私处理逻辑。

## 3. 启动桌面开发环境

从仓库根目录运行：

```bash
./run.sh
```

脚本会构建 Go Core，将其路径通过 `VEIL_CORE_EXECUTABLE` 传给 Desktop，然后启动 `cargo tauri dev`。如果当前仓库已有开发版 Desktop 或 Core，脚本只会在确认没有活动保护会话后替换旧进程。

也可以手动运行：

```bash
go build -trimpath -o veil ./cmd/veil
cd desktop
VEIL_CORE_EXECUTABLE="$(pwd)/../veil" cargo tauri dev
```

## 4. 只启动 Core 与浏览器 Dashboard

`serve` 需要至少 32 个可打印字符的随机管理令牌：

```bash
export VEIL_ADMIN_TOKEN='replace-with-a-random-32-character-token'
go run ./cmd/veil serve
```

另一个终端使用同一令牌打开 Dashboard：

```bash
export VEIL_ADMIN_TOKEN='replace-with-the-same-token'
go run ./cmd/veil web
```

`veil web` 会创建短期、一次性的本地访问地址；管理令牌不会被放入浏览器 URL。

## 5. 常用 CLI 调试入口

Core 运行后，可以使用以下命令检查运行状态和保护计划：

```bash
go run ./cmd/veil status
go run ./cmd/veil discover
go run ./cmd/veil inspect codex
go run ./cmd/veil compatibility
go run ./cmd/veil sessions list
go run ./cmd/veil calls
go run ./cmd/veil audit
go run ./cmd/veil diagnostics
```

启动受保护 Agent 的常见入口：

```bash
go run ./cmd/veil run codex -- --help
go run ./cmd/veil run codex --interactive -- exec "review this change"
go run ./cmd/veil run codex-desktop
go run ./cmd/veil run hermes -- --help
```

`--interactive` 允许会话通过 Dashboard 处理一次性 `ASK` 决策；非交互会话遇到 `ASK` 时默认阻断。支持的 Agent、版本、平台和出口范围必须以[开发进度](./09-development-progress.md)中的当前证据为准。

## 6. 构建与验证

常用 Make 入口：

```bash
make build
make test
make verify
make desktop-test
make desktop-build-ci
```

- `make test` 运行全部 Go 测试；
- `make verify` 运行 `go vet` 和 Go race 测试；
- `make desktop-test` 运行 Desktop Rust 测试；
- `make desktop-build-ci` 对 Desktop 执行锁定依赖的 `cargo check`；
- `make acceptance-evidence` 重放仓库记录的自动化验收证据。

完整证据范围、真实性边界和需要实机验证的项目见[验收证据](./08-acceptance-evidence.md)。本地测试或编译通过不能替代真实 Agent、Provider、目标平台、签名安装包或发布验证。

## 7. 开发约束

- 新能力必须按 Egress Surface 报告实际覆盖，不得因为 Agent 可发现就宣称全部流量受保护；
- 未知协议、无法安全解析的内容和检测故障必须保持 fail-closed；
- 敏感原文默认不得进入日志、审计或诊断包；
- Desktop、CLI 和 Core 对外展示的能力必须与兼容矩阵和验证证据一致；
- 架构或安全边界发生变化时，在 `doc/adr/` 中补充或更新 ADR。

更详细的约束见[安全与隐私](./03-security-and-privacy.md)、[集成策略](./04-integrations.md)、[检测与策略](./05-detection-and-policy.md)以及 [ADR 索引](./adr/README.md)。
