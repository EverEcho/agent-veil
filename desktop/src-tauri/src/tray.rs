use std::{process::Command, thread};
use tauri::{
    menu::{CheckMenuItem, Menu, MenuItem},
    tray::TrayIconBuilder,
    App, Manager,
};
use tauri_plugin_autostart::ManagerExt;

use crate::{
    bridge::browser_url,
    core_supervisor::{monitor_core, refresh_sessions, stop_owned, SharedRuntime},
};

pub(crate) fn setup(
    app: &mut App,
    runtime: SharedRuntime,
) -> Result<(), Box<dyn std::error::Error>> {
    let show = MenuItem::with_id(app, "show", "显示 AgentVeil", true, None::<&str>)?;
    let browser = MenuItem::with_id(app, "browser", "在浏览器打开面板", true, None::<&str>)?;
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
    let tray_runtime = runtime.clone();
    let mut tray = TrayIconBuilder::new();
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.tooltip("AgentVeil 隐私保护")
        .menu(&menu)
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "show" => show_main_window(app),
            "browser" => {
                if let Ok(target) = browser_url(&tray_runtime) {
                    let _ = open_url(&target);
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
                    show_main_window(app);
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window
                            .eval("alert('仍有受保护会话运行，AgentVeil 将继续留在托盘中。')");
                    }
                } else {
                    stop_owned(&tray_runtime);
                    app.exit(0);
                }
            }
            _ => {}
        })
        .build(app)?;
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
        let close_window = window.clone();
        window.on_window_event(move |event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = close_window.hide();
            }
        });
    }
    let handle = app.handle().clone();
    thread::spawn(move || monitor_core(handle, runtime));
    Ok(())
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn open_url(url: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let status = Command::new("cmd").args(["/C", "start", "", url]).status();
    #[cfg(target_os = "macos")]
    let status = Command::new("open").arg(url).status();
    #[cfg(all(unix, not(target_os = "macos")))]
    let status = Command::new("xdg-open").arg(url).status();
    status.map_err(|error| error.to_string()).and_then(|value| {
        value
            .success()
            .then_some(())
            .ok_or_else(|| "无法打开浏览器".into())
    })
}
