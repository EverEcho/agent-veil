use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::Deserialize;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use tauri::{AppHandle, Manager, WebviewWindow};
use url::Url;

use crate::bridge::{client, get_json, API_VERSION};

const CORE_READY_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const RELEASE_CHANNEL: &str = match option_env!("AGENTVEIL_CHANNEL") {
    Some(value) => value,
    None => "dev",
};

#[derive(Default)]
pub(crate) struct CoreRuntime {
    child: Option<Child>,
    launches: Vec<Child>,
    endpoint: String,
    token: String,
    sessions: usize,
}

pub(crate) type SharedRuntime = Arc<Mutex<CoreRuntime>>;

pub(crate) fn new_runtime() -> SharedRuntime {
    Arc::new(Mutex::new(CoreRuntime::default()))
}

pub(crate) fn ready(runtime: &SharedRuntime) -> bool {
    runtime
        .lock()
        .is_ok_and(|value| !value.endpoint.is_empty() && !value.token.is_empty())
}

pub(crate) fn credentials(runtime: &SharedRuntime) -> Result<(String, String), String> {
    runtime
        .lock()
        .map(|value| (value.endpoint.clone(), value.token.clone()))
        .map_err(|_| "Core 运行状态不可用".into())
}

pub(crate) fn protected_codex_running(runtime: &SharedRuntime) -> Result<bool, String> {
    let mut value = runtime.lock().map_err(|_| "Core 运行状态不可用")?;
    let mut running = Vec::with_capacity(value.launches.len());
    for mut launch in value.launches.drain(..) {
        match launch.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => running.push(launch),
        }
    }
    value.launches = running;
    Ok(!value.launches.is_empty())
}

pub(crate) fn stop_owned(runtime: &SharedRuntime) {
    if let Ok(mut value) = runtime.lock() {
        for mut launch in value.launches.drain(..) {
            let _ = launch.kill();
            let _ = launch.wait();
        }
        if let Some(mut child) = value.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Deserialize)]
struct CoreState {
    schema_version: String,
    api_endpoint: String,
    instance_id: String,
    process_id: u32,
}

pub(crate) fn config_dir() -> Result<PathBuf, String> {
    let base = if cfg!(target_os = "windows") {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|v| PathBuf::from(v).join("Library/Application Support"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|v| PathBuf::from(v).join(".config")))
    };
    base.map(|p| p.join("agentveil"))
        .ok_or_else(|| "无法确定用户配置目录".into())
}

fn load_or_create_token(dir: &Path) -> Result<String, String> {
    fs::create_dir_all(dir).map_err(|e| format!("创建配置目录失败: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("收紧配置目录权限失败: {e}"))?;
    }
    let path = dir.join("desktop.token");
    match fs::read_to_string(&path) {
        Ok(value) => {
            let value = value.trim_end_matches(['\r', '\n']);
            if (32..=4096).contains(&value.len())
                && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
            {
                return Ok(value.to_owned());
            }
            return Err("桌面管理凭据无效".into());
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.to_string()),
        Err(_) => {}
    }
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|e| format!("保存管理凭据失败: {e}"))?;
    writeln!(file, "{token}").map_err(|e| format!("保存管理凭据失败: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("同步管理凭据失败: {e}"))?;
    Ok(token)
}

fn open_private_log(dir: &Path) -> Result<File, String> {
    let path = dir.join("desktop-core.log");
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    Ok(file)
}

fn open_private_launch_log(dir: &Path) -> Result<(PathBuf, File), String> {
    let path = dir.join("codex-desktop-launch.log");
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    Ok((path, file))
}

fn launch_failure_detail(path: &Path) -> Option<String> {
    let metadata = fs::metadata(path).ok()?;
    if metadata.len() == 0 || metadata.len() > 64 * 1024 {
        return None;
    }
    fs::read_to_string(path)
        .ok()?
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| line.strip_prefix("veil: ").unwrap_or(line).to_owned())
}

pub(crate) fn core_executable(app: &AppHandle) -> Result<PathBuf, String> {
    if let Some(value) = std::env::var_os("VEIL_CORE_EXECUTABLE") {
        let path = PathBuf::from(value);
        return path
            .is_absolute()
            .then_some(path)
            .ok_or_else(|| "VEIL_CORE_EXECUTABLE 必须是绝对路径".into());
    }
    let name = if cfg!(windows) { "veil.exe" } else { "veil" };
    let current = std::env::current_exe().map_err(|e| e.to_string())?;
    let adjacent = current.parent().unwrap_or(Path::new(".")).join(name);
    if adjacent.is_file() {
        return Ok(adjacent);
    }
    app.path()
        .resource_dir()
        .map_err(|e| e.to_string())
        .map(|p| p.join("resources").join(name))
}

pub(crate) fn launch_protected_codex(
    app: &AppHandle,
    runtime: &SharedRuntime,
) -> Result<(), String> {
    let (endpoint, token) = credentials(runtime)?;
    if endpoint.is_empty() || token.is_empty() {
        return Err("Privacy Core 尚未就绪".into());
    }
    if protected_codex_running(runtime)? {
        return Err("已有一个由 AgentVeil 启动的 Codex 桌面会话".into());
    }
    let executable = core_executable(app)?;
    if !executable.is_file() {
        return Err(format!("未找到 Privacy Core：{}", executable.display()));
    }
    let dir = config_dir()?;
    let (launch_log_path, log) = open_private_launch_log(&dir)?;
    let stderr = log.try_clone().map_err(|e| e.to_string())?;
    let mut child = Command::new(executable)
        .args(["run", "codex-desktop"])
        .env("VEIL_CORE_ENDPOINT", endpoint)
        .env("VEIL_ADMIN_TOKEN", token)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|e| format!("启动 Codex 桌面保护器失败：{e}"))?;
    thread::sleep(Duration::from_millis(350));
    if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
        let detail = launch_failure_detail(&launch_log_path)
            .unwrap_or_else(|| format!("启动器已退出（{status}）"));
        return Err(format!("Codex 桌面版启动失败：{detail}"));
    }
    runtime
        .lock()
        .map_err(|_| "Core 运行状态不可用")?
        .launches
        .push(child);
    Ok(())
}

fn probe(
    http: &reqwest::blocking::Client,
    dir: &Path,
    token: &str,
) -> Result<(String, usize), String> {
    let bytes = fs::read(dir.join("core.json")).map_err(|e| e.to_string())?;
    let state: CoreState = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if state.schema_version != API_VERSION || state.process_id == 0 || state.instance_id.len() < 32
    {
        return Err("Core 状态无效".into());
    }
    let url = Url::parse(&state.api_endpoint).map_err(|e| e.to_string())?;
    let loopback = url
        .host_str()
        .and_then(|h| h.parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    if url.scheme() != "http" || url.path() != "/" || url.query().is_some() || !loopback {
        return Err("Core 端点不是本机回环地址".into());
    }
    let identity = get_json(http, &state.api_endpoint, None, "/v1/identity")?;
    if identity.get("instance_id").and_then(|v| v.as_str()) != Some(&state.instance_id) {
        return Err("Core 身份不匹配".into());
    }
    get_json(http, &state.api_endpoint, Some(token), "/v1/health")?;
    let sessions = get_json(http, &state.api_endpoint, Some(token), "/v1/sessions")?
        .as_array()
        .map_or(0, Vec::len);
    Ok((state.api_endpoint, sessions))
}

fn show_error(window: &WebviewWindow, message: &str) {
    let message = serde_json::to_string(message).unwrap_or_else(|_| "\"启动失败\"".into());
    let _ = window.eval(format!(
        "(()=>{{const main=document.querySelector('main'),title=document.createElement('h1'),detail=document.createElement('p');title.textContent='AgentVeil 无法启动';detail.textContent={};main.replaceChildren(title,detail)}})()",
        message
    ));
}

fn core_command(executable: &Path, token: &str) -> Command {
    let mut command = Command::new(executable);
    command.arg("serve").env("VEIL_ADMIN_TOKEN", token);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command
}

fn start_core(app: AppHandle, runtime: SharedRuntime) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let result = (|| -> Result<(), String> {
        let dir = config_dir()?;
        let token = match std::env::var("VEIL_ADMIN_TOKEN") {
            Ok(value) => value,
            Err(_) => load_or_create_token(&dir)?,
        };
        let http = client()?;
        let (endpoint, sessions, child) = match probe(&http, &dir, &token) {
            Ok((endpoint, sessions)) => (endpoint, sessions, None),
            Err(_) => {
                if let Ok(bytes) = fs::read(dir.join("core.json")) {
                    if let Ok(state) = serde_json::from_slice::<CoreState>(&bytes) {
                        if get_json(&http, &state.api_endpoint, None, "/v1/identity").is_ok() {
                            return Err("已有 Core 正在运行，但桌面端没有其管理权限".into());
                        }
                    }
                }
                if let Ok(mut value) = runtime.lock() {
                    if let Some(mut previous) = value.child.take() {
                        let _ = previous.kill();
                        let _ = previous.wait();
                    }
                }
                let executable = core_executable(&app)?;
                if !executable.is_file() {
                    return Err(format!("未找到 Privacy Core：{}", executable.display()));
                }
                let log = open_private_log(&dir)?;
                let stderr = log.try_clone().map_err(|e| e.to_string())?;
                let mut child = core_command(&executable, &token)
                    .stdout(Stdio::from(log))
                    .stderr(Stdio::from(stderr))
                    .spawn()
                    .map_err(|e| e.to_string())?;
                let deadline = Instant::now() + CORE_READY_TIMEOUT;
                let (endpoint, sessions) = loop {
                    let probe_error = match probe(&http, &dir, &token) {
                        Ok(status) => break status,
                        Err(error) => error,
                    };
                    if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                        return Err(format!(
                            "Privacy Core 启动后提前退出（{status}）。诊断日志：{}",
                            dir.join("desktop-core.log").display()
                        ));
                    }
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(format!(
                            "Privacy Core 未能在 30 秒内就绪：{probe_error}。诊断日志：{}",
                            dir.join("desktop-core.log").display()
                        ));
                    }
                    thread::sleep(Duration::from_millis(80));
                };
                (endpoint, sessions, Some(child))
            }
        };
        if let Ok(mut value) = runtime.lock() {
            value.endpoint = endpoint.clone();
            value.token = token.clone();
            value.sessions = sessions;
            value.child = child;
        }
        Ok(())
    })();
    if let Err(error) = result {
        show_error(&window, &error);
    }
}

pub(crate) fn monitor_core(app: AppHandle, runtime: SharedRuntime) {
    start_core(app.clone(), runtime.clone());
    loop {
        thread::sleep(Duration::from_secs(3));
        let Ok(dir) = config_dir() else { continue };
        let token = runtime.lock().map(|v| v.token.clone()).unwrap_or_default();
        if token.is_empty() {
            start_core(app.clone(), runtime.clone());
            continue;
        }
        match client().and_then(|http| probe(&http, &dir, &token)) {
            Ok((endpoint, sessions)) => {
                if let Ok(mut value) = runtime.lock() {
                    value.endpoint = endpoint;
                    value.sessions = sessions;
                }
            }
            Err(_) => start_core(app.clone(), runtime.clone()),
        }
    }
}

pub(crate) fn refresh_sessions(runtime: &SharedRuntime) -> usize {
    let (endpoint, token) = runtime
        .lock()
        .map(|v| (v.endpoint.clone(), v.token.clone()))
        .unwrap_or_default();
    if endpoint.is_empty() {
        return 0;
    }
    let sessions = client()
        .and_then(|c| get_json(&c, &endpoint, Some(&token), "/v1/sessions"))
        .ok()
        .and_then(|v| v.as_array().map(Vec::len))
        .unwrap_or(0);
    if let Ok(mut value) = runtime.lock() {
        value.sessions = sessions;
    }
    sessions
}
