#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{Manager, RunEvent};
use tauri_plugin_autostart::MacosLauncher;

mod bridge;
mod core_supervisor;
mod tray;

use core_supervisor::{new_runtime, refresh_sessions, stop_owned};

fn main() {
    let runtime = new_runtime();
    let app_runtime = runtime.clone();
    let app = tauri::Builder::default()
        .manage(runtime.clone())
        .invoke_handler(tauri::generate_handler![
            bridge::desktop_info,
            bridge::core_request
        ])
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
        .setup(move |app| tray::setup(app, app_runtime.clone()))
        .build(tauri::generate_context!())
        .expect("failed to build AgentVeil desktop application");
    app.run(move |_handle, event| {
        if let RunEvent::ExitRequested { api, .. } = event {
            if refresh_sessions(&runtime) > 0 {
                api.prevent_exit();
            } else {
                stop_owned(&runtime);
            }
        }
    });
}
