# ADR-0005：透明模式安全边界

- 状态：部分接受
- 范围：`internal/transparent`、`internal/egress`、Linux protected launch

## 已锁定决策

显式 Protected Route 始终优先。透明能力必须同时绑定 Session、精确进程身份
（PID 与启动时间）和精确 DNS 名称；不允许通配域名、IP 证书或通用 MITM。
每个叶证书短期有效，且只有处于激活状态、权限安全、身份未变化的 CA 才能签发。

CA material 与 OS trust installation 分离。Linux controller 使用独立 staging、
Active pointer、安装 receipt、刷新命令超时和失败回滚；启动时 reconcile 清理未
激活或已退休 CA。撤销必须同时移除 trust entry 与私钥，任何身份替换都停止删除
而不是误删未知材料。

进程出口观察与内容保护是不同状态。Linux protected launch 发现计划外连接或
观察失败时终止隔离进程组并写入目标无关的元数据审计，但该机制是 post-connect
观察，不宣称 pre-connect 阻断或 HTTPS 内容检查。

## 理由

透明代理拥有高权限和广泛可见性，必须比普通本地代理采用更窄的能力范围。将
CA 生命周期、进程身份、域名范围和 Coverage 表述分别约束，可避免把“安装了一张
根证书”误当成完整保护产品。

## 尚未接受

- 生产 HTTPS MITM 数据面和与 Protocol Adapter 的单检查点集成；
- macOS Keychain 与 Windows Certificate Store 的原子安装、回滚和卸载；
- Linux/macOS/Windows 的 pre-connect 进程级阻断规则与最小权限模型；
- 证书固定、HTTP/3、QUIC、WebSocket 和系统代理变化的产品级验收。

以上各项完成 ADR、实现和目标平台自动化证据前，Compatibility Matrix 不得将其
标记为 Content Protected。
