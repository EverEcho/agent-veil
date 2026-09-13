# ADR-0006：桌面壳与 Core 生命周期

- 状态：部分接受
- 范围：`desktop`、`internal/desktopapp`、Core 桌面托管

## 已锁定决策

桌面壳采用 Fyne v2，并作为独立 Go module 构建。Fyne 同时提供 Linux、macOS、
Windows 的原生窗口、系统托盘、通知与打包入口，能够继续使用 Go 实现而不把检测、
策略或 Vault 复制进 UI 进程。Core 继续是独立 `veil serve` 进程；桌面应用只承担
生命周期编排和打开现有 loopback Dashboard。

桌面进程使用独立的随机管理 Token，或显式使用 `VEIL_ADMIN_TOKEN`。随机 Token 保存
在权限收紧的 AgentVeil 用户配置目录中，以便桌面崩溃后重新接管仍在运行的 Core；
它只通过环境传给 Core，不写入自启动文件、Core state 或命令行。桌面进程还持有独立
单实例锁。桌面必须先验证 state 中的随机 instance identity，再发送管理 Token。
检测到由其他 Token 管理的活动 Core 时不得争抢 Core 实例锁或启动第二个 Core。

关闭窗口只隐藏到托盘。退出桌面应用时，仅当 Core 是当前桌面进程启动且活动 Session
数为零时才请求停止；存在 Session 或 Core 属于其他控制器时保持 Core 运行。Core
异常退出由桌面监控循环重新拉起，重启仍沿用 Core 自身的单实例、残留 state 清理和
Hermes 临时目录恢复语义。

开机启动采用用户级、无提权机制：Linux freedesktop autostart `.desktop`、macOS
LaunchAgent、Windows 用户 Startup command。写入使用同目录临时文件、同步和原子
替换；内容只包含桌面可执行文件绝对路径，不包含任何 Token 或 Agent 凭据。

## 尚未接受

- Fyne 原生制品在三平台的图形、托盘、通知和辅助功能实机验收；
- macOS app bundle/notarization、Windows 签名安装器和 Linux 桌面包；
- Core 二进制升级、版本迁移、回滚和安装服务权限；
- macOS Keychain 与 Windows Credential Manager 的 Token 存储替换；
- 系统休眠、快速用户切换、桌面会话重启和强制断电故障注入。

完成这些平台证据前，只能声明桌面技术栈和通用生命周期代码已开发，不能声明正式
桌面发行版已交付。
