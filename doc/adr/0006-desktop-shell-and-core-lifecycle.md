# ADR-0006：桌面壳与 Core 生命周期

- 状态：部分接受
- 范围：`desktop`、Core 桌面托管

## 已锁定决策

桌面壳采用 Tauri 2，并作为独立 Rust crate 构建。Linux、macOS、Windows 使用各自
系统 WebView 渲染本地打包的 Dashboard；Core 同时内嵌并提供同一份前端源码给浏览器，
因此 CLI 浏览器模式与桌面模式不维护两套 GUI。Core 继续是独立 `veil serve` 进程；
桌面应用只承担生命周期编排、凭据自动装载、系统托盘、单实例与用户级自启动。

桌面 Dashboard 通过 Tauri Rust command bridge 调用 Core，而不是导航到 Core 的
localhost 页面。bridge 只开放显式的管理 API method/path 白名单，拒绝任意 URL、Header
和重定向；管理 Token 只留在 Rust 进程，不注入 JavaScript。浏览器 Dashboard 由托盘或
`veil web` 使用管理凭据向 Core 换取 30 秒内有效、仅可使用一次的票据；页面从 URL
fragment 读取并立即清除票据，再以同源请求换取 `HttpOnly`、`SameSite=Strict`、仅限
`/v1/` 的 8 小时本机会话 Cookie。管理 Token 不进入浏览器，直接打开 Core 页面也不提供
手工输入 Token 的后门。

桌面进程使用独立的随机管理 Token，或显式使用 `VEIL_ADMIN_TOKEN`。随机 Token 保存
在权限收紧的 AgentVeil 用户配置目录中，以便桌面崩溃后重新接管仍在运行的 Core；
它只通过环境传给 Core，不写入自启动文件、Core state 或命令行。桌面进程通过
Tauri single-instance 插件避免重复运行。桌面必须先验证 state 中的随机 instance identity，再发送管理 Token。
检测到由其他 Token 管理的活动 Core 时不得争抢 Core 实例锁或启动第二个 Core。

关闭窗口只隐藏到托盘。退出桌面应用时，仅当 Core 是当前桌面进程启动且活动 Session
数为零时才请求停止；存在 Session 或 Core 属于其他控制器时保持 Core 运行。Core
异常退出由桌面监控循环重新拉起，重启仍沿用 Core 自身的单实例、残留 state 清理和
Hermes 临时目录恢复语义。

开机启动采用 Tauri 官方 autostart 插件提供的用户级、无提权机制；内容不包含任何
Token 或 Agent 凭据。此前未接入真实桌面路径的 Go `internal/desktopapp` 实现已移除，
避免 Go 测试替代实际 Rust 生命周期证据。

## 尚未接受

- Tauri 原生制品在三平台的 WebView、托盘和辅助功能实机验收；
- macOS app bundle/notarization、Windows 签名安装器和 Linux 桌面包；
- Core 二进制升级、版本迁移、回滚和安装服务权限；
- macOS Keychain 与 Windows Credential Manager 的 Token 存储替换；
- 系统休眠、快速用户切换、桌面会话重启和强制断电故障注入。

完成这些平台证据前，只能声明桌面技术栈和通用生命周期代码已开发，不能声明正式
桌面发行版已交付。
