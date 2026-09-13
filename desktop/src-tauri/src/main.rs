#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use reqwest::blocking::Client;
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
use tauri::{
    menu::{CheckMenuItem, Menu, MenuItem},
    tray::TrayIconBuilder,
    AppHandle, Manager, RunEvent, WebviewWindow,
};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};
use url::Url;

const API_VERSION: &str = "v1";
const RELEASE_CHANNEL: &str = match option_env!("AGENTVEIL_CHANNEL") {
    Some(value) => value,
    None => "dev",
};

#[derive(Default)]
struct CoreRuntime {
    child: Option<Child>,
    endpoint: String,
    token: String,
    sessions: usize,
}

type SharedRuntime = Arc<Mutex<CoreRuntime>>;

#[derive(Deserialize)]
struct CoreState {
    schema_version: String,
    api_endpoint: String,
    instance_id: String,
    process_id: u32,
}

fn config_dir() -> Result<PathBuf, String> {
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

fn core_executable(app: &AppHandle) -> Result<PathBuf, String> {
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

fn client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())
}

fn request(
    client: &Client,
    endpoint: &str,
    token: Option<&str>,
    path: &str,
) -> Result<serde_json::Value, String> {
    let mut request = client
        .get(format!("{endpoint}{path}"))
        .header("X-AgentVeil-API-Version", API_VERSION);
    if let Some(value) = token {
        request = request.bearer_auth(value);
    }
    let response = request.send().map_err(|e| e.to_string())?;
    if !response.status().is_success()
        || response
            .headers()
            .get("X-AgentVeil-API-Version")
            .and_then(|v| v.to_str().ok())
            != Some(API_VERSION)
    {
        return Err(format!("Core 返回状态 {}", response.status()));
    }
    response.json().map_err(|e| e.to_string())
}

fn probe(http: &Client, dir: &Path, token: &str) -> Result<(String, usize), String> {
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
    let identity = request(http, &state.api_endpoint, None, "/v1/identity")?;
    if identity.get("instance_id").and_then(|v| v.as_str()) != Some(&state.instance_id) {
        return Err("Core 身份不匹配".into());
    }
    request(http, &state.api_endpoint, Some(token), "/v1/health")?;
    let sessions = request(http, &state.api_endpoint, Some(token), "/v1/sessions")?
        .as_array()
        .map_or(0, Vec::len);
    Ok((state.api_endpoint, sessions))
}

fn inject_desktop(window: &WebviewWindow, token: &str) {
    let encoded = serde_json::to_string(token).unwrap_or_else(|_| "\"\"".into());
    let channel = serde_json::to_string(RELEASE_CHANNEL).unwrap_or_else(|_| "\"dev\"".into());
    let script = format!(
        r#"(()=>{{let n=0;const ready=()=>{{const input=document.querySelector('#token'),load=document.querySelector('#load');if(input&&load){{input.value={encoded};input.parentElement.style.display='none';document.documentElement.dataset.agentveilDesktop='true';const badge=document.createElement('span');badge.textContent={channel}.toUpperCase();badge.style.cssText='position:fixed;right:22px;bottom:18px;z-index:9999;padding:6px 10px;border:1px solid #485575;border-radius:999px;background:#111827e8;color:#aebcff;font:700 11px system-ui;letter-spacing:.12em;box-shadow:0 8px 24px #0006';document.body.appendChild(badge);load.click();return}}if(n++<100)setTimeout(ready,50)}};ready()}})()"#
    );
    let _ = window.eval(&script);
}

fn show_error(window: &WebviewWindow, message: &str) {
    let message = serde_json::to_string(message).unwrap_or_else(|_| "\"启动失败\"".into());
    let _ = window.eval(&format!(
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
                        if request(&http, &state.api_endpoint, None, "/v1/identity").is_ok() {
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
                let child = core_command(&executable, &token)
                    .stdout(Stdio::from(log))
                    .stderr(Stdio::from(stderr))
                    .spawn()
                    .map_err(|e| e.to_string())?;
                let deadline = Instant::now() + Duration::from_secs(10);
                let (endpoint, sessions) = loop {
                    if let Ok(status) = probe(&http, &dir, &token) {
                        break status;
                    }
                    if Instant::now() >= deadline {
                        return Err("Privacy Core 未能在 10 秒内就绪".into());
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
        window
            .navigate(Url::parse(&format!("{endpoint}/")).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        thread::sleep(Duration::from_millis(350));
        inject_desktop(&window, &token);
        Ok(())
    })();
    if let Err(error) = result {
        show_error(&window, &error);
    }
}

fn monitor_core(app: AppHandle, runtime: SharedRuntime) {
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

fn refresh_sessions(runtime: &SharedRuntime) -> usize {
    let (endpoint, token) = runtime
        .lock()
        .map(|v| (v.endpoint.clone(), v.token.clone()))
        .unwrap_or_default();
    if endpoint.is_empty() {
        return 0;
    }
    let sessions = client()
        .and_then(|c| request(&c, &endpoint, Some(&token), "/v1/sessions"))
        .ok()
        .and_then(|v| v.as_array().map(Vec::len))
        .unwrap_or(0);
    if let Ok(mut value) = runtime.lock() {
        value.sessions = sessions;
    }
    sessions
}

fn main() {
    let runtime: SharedRuntime = Arc::new(Mutex::new(CoreRuntime::default()));
    let app_runtime = runtime.clone();
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec![]),
        ))
        .setup(move |app| {
            let show = MenuItem::with_id(app, "show", "显示 AgentVeil", true, None::<&str>)?;
            let browser =
                MenuItem::with_id(app, "browser", "在浏览器打开面板", true, None::<&str>)?;
            let auto = CheckMenuItem::with_id(
                app,
                "autostart",
                "登录时启动",
                true,
                app.autolaunch().is_enabled().unwrap_or(false),
                None::<&str>,
            )?;
            let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &browser, &auto, &quit])?;
            let tray_runtime = app_runtime.clone();
            let mut tray = TrayIconBuilder::new();
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.tooltip("AgentVeil 隐私保护")
                .menu(&menu)
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "browser" => {
                        let endpoint = tray_runtime
                            .lock()
                            .map(|v| v.endpoint.clone())
                            .unwrap_or_default();
                        if !endpoint.is_empty() {
                            let _ = open_url(&endpoint);
                        }
                    }
                    "autostart" => {
                        let enabled = app.autolaunch().is_enabled().unwrap_or(false);
                        let _ = if enabled {
                            app.autolaunch().disable()
                        } else {
                            app.autolaunch().enable()
                        };
                    }
                    "quit" => {
                        if refresh_sessions(&tray_runtime) > 0 {
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.set_focus();
                                let _ = w.eval(
                                    "alert('仍有受保护会话运行，AgentVeil 将继续留在托盘中。')",
                                );
                            }
                        } else {
                            if let Ok(mut value) = tray_runtime.lock() {
                                if let Some(mut child) = value.child.take() {
                                    let _ = child.kill();
                                    let _ = child.wait();
                                }
                            }
                            app.exit(0);
                        }
                    }
                    _ => {}
                })
                .build(app)?;
            if let Some(window) = app.get_webview_window("main") {
                let close_window = window.clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = close_window.hide();
                    }
                });
            }
            let handle = app.handle().clone();
            let background = app_runtime.clone();
            thread::spawn(move || monitor_core(handle, background));
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build AgentVeil desktop application");
    app.run(move |_handle, event| {
        if let RunEvent::ExitRequested { api, .. } = event {
            if refresh_sessions(&runtime) > 0 {
                api.prevent_exit();
            } else if let Ok(mut value) = runtime.lock() {
                if let Some(mut child) = value.child.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
    });
}

fn open_url(url: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let status = Command::new("cmd").args(["/C", "start", "", url]).status();
    #[cfg(target_os = "macos")]
    let status = Command::new("open").arg(url).status();
    #[cfg(all(unix, not(target_os = "macos")))]
    let status = Command::new("xdg-open").arg(url).status();
    status.map_err(|e| e.to_string()).and_then(|s| {
        s.success()
            .then_some(())
            .ok_or_else(|| "无法打开浏览器".into())
    })
}
