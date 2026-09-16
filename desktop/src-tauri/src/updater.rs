use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
};
use tauri::{AppHandle, State};
use tauri_plugin_updater::{Update, UpdaterExt};
use url::Url;

use crate::core_supervisor::{config_dir, RELEASE_CHANNEL};

const SETTINGS_FILE: &str = "update-settings.json";
const SETTINGS_SCHEMA: u8 = 1;
const UPDATE_BASE_URL: &str = "https://github.com/EverEcho/agent-veil/releases/download";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum UpdateChannel {
    Dev,
    Beta,
    Release,
}

impl UpdateChannel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Beta => "beta",
            Self::Release => "release",
        }
    }

    fn build_default() -> Self {
        match RELEASE_CHANNEL {
            "beta" => Self::Beta,
            "release" | "main" => Self::Release,
            _ => Self::Dev,
        }
    }

    fn endpoint(self) -> Result<Url, String> {
        Url::parse(&format!(
            "{UPDATE_BASE_URL}/agentveil-updates-{}/latest.json",
            self.as_str()
        ))
        .map_err(|error| format!("更新地址无效: {error}"))
    }
}

#[derive(Deserialize, Serialize)]
struct UpdateSettings {
    schema_version: u8,
    channel: UpdateChannel,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum UpdateStatus {
    Unsupported,
    Idle,
    Checking,
    Available,
    UpToDate,
    Downloading,
    Downloaded,
    Installing,
    Error,
}

pub(crate) struct UpdateRuntime {
    channel: UpdateChannel,
    status: UpdateStatus,
    available: Option<Update>,
    downloaded: Option<Vec<u8>>,
    downloaded_bytes: u64,
    total_bytes: Option<u64>,
    error: Option<String>,
}

pub(crate) type SharedUpdateRuntime = Arc<Mutex<UpdateRuntime>>;

#[derive(Serialize)]
pub(crate) struct UpdateSnapshot {
    current_version: String,
    build_channel: &'static str,
    selected_channel: UpdateChannel,
    status: UpdateStatus,
    available_version: Option<String>,
    notes: Option<String>,
    downloaded_bytes: u64,
    total_bytes: Option<u64>,
    error: Option<String>,
    supported: bool,
}

pub(crate) fn new_runtime() -> SharedUpdateRuntime {
    Arc::new(Mutex::new(UpdateRuntime {
        channel: load_channel().unwrap_or_else(UpdateChannel::build_default),
        status: if supported() {
            UpdateStatus::Idle
        } else {
            UpdateStatus::Unsupported
        },
        available: None,
        downloaded: None,
        downloaded_bytes: 0,
        total_bytes: None,
        error: None,
    }))
}

fn supported() -> bool {
    if cfg!(target_os = "linux") {
        std::env::var_os("APPIMAGE").is_some()
    } else {
        cfg!(target_os = "macos") || cfg!(target_os = "windows")
    }
}

fn snapshot(app: &AppHandle, runtime: &UpdateRuntime) -> UpdateSnapshot {
    UpdateSnapshot {
        current_version: app.package_info().version.to_string(),
        build_channel: UpdateChannel::build_default().as_str(),
        selected_channel: runtime.channel,
        status: runtime.status,
        available_version: runtime
            .available
            .as_ref()
            .map(|value| value.version.clone()),
        notes: runtime
            .available
            .as_ref()
            .and_then(|value| value.body.clone()),
        downloaded_bytes: runtime.downloaded_bytes,
        total_bytes: runtime.total_bytes,
        error: runtime.error.clone(),
        supported: supported(),
    }
}

fn lock(runtime: &SharedUpdateRuntime) -> Result<std::sync::MutexGuard<'_, UpdateRuntime>, String> {
    runtime.lock().map_err(|_| "更新状态不可用".to_owned())
}

fn load_channel() -> Option<UpdateChannel> {
    let bytes = fs::read(config_dir().ok()?.join(SETTINGS_FILE)).ok()?;
    let settings: UpdateSettings = serde_json::from_slice(&bytes).ok()?;
    (settings.schema_version == SETTINGS_SCHEMA).then_some(settings.channel)
}

fn save_channel(channel: UpdateChannel) -> Result<(), String> {
    let directory = config_dir()?;
    fs::create_dir_all(&directory).map_err(|error| format!("创建配置目录失败: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("收紧配置目录权限失败: {error}"))?;
    }
    let path = directory.join(SETTINGS_FILE);
    let payload = serde_json::to_vec_pretty(&UpdateSettings {
        schema_version: SETTINGS_SCHEMA,
        channel,
    })
    .map_err(|error| format!("序列化更新设置失败: {error}"))?;
    write_private(&path, &payload).map_err(|error| format!("保存更新设置失败: {error}"))
}

fn write_private(path: &Path, payload: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    file.write_all(payload).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

#[tauri::command]
pub(crate) fn update_info(
    app: AppHandle,
    runtime: State<'_, SharedUpdateRuntime>,
) -> Result<UpdateSnapshot, String> {
    let value = lock(&runtime)?;
    Ok(snapshot(&app, &value))
}

#[tauri::command]
pub(crate) fn set_update_channel(
    app: AppHandle,
    runtime: State<'_, SharedUpdateRuntime>,
    channel: UpdateChannel,
) -> Result<UpdateSnapshot, String> {
    save_channel(channel)?;
    let mut value = lock(&runtime)?;
    value.channel = channel;
    value.status = if supported() {
        UpdateStatus::Idle
    } else {
        UpdateStatus::Unsupported
    };
    value.available = None;
    value.downloaded = None;
    value.downloaded_bytes = 0;
    value.total_bytes = None;
    value.error = None;
    Ok(snapshot(&app, &value))
}

#[tauri::command]
pub(crate) async fn check_for_update(
    app: AppHandle,
    runtime: State<'_, SharedUpdateRuntime>,
) -> Result<UpdateSnapshot, String> {
    if !supported() {
        return Err("此安装类型需要通过系统包管理器手动更新".into());
    }
    let shared = runtime.inner().clone();
    let channel = {
        let mut value = lock(&shared)?;
        if matches!(
            value.status,
            UpdateStatus::Checking | UpdateStatus::Downloading | UpdateStatus::Installing
        ) {
            return Err("已有更新操作正在进行".into());
        }
        value.status = UpdateStatus::Checking;
        value.error = None;
        value.channel
    };
    let result = async {
        let updater = app
            .updater_builder()
            .endpoints(vec![channel.endpoint()?])
            .map_err(|error| error.to_string())?
            .build()
            .map_err(|error| error.to_string())?;
        updater.check().await.map_err(|error| error.to_string())
    }
    .await;
    let mut value = lock(&shared)?;
    match result {
        Ok(update) => {
            value.available = update;
            value.downloaded = None;
            value.downloaded_bytes = 0;
            value.total_bytes = None;
            value.status = if value.available.is_some() {
                UpdateStatus::Available
            } else {
                UpdateStatus::UpToDate
            };
            value.error = None;
        }
        Err(error) => {
            value.status = UpdateStatus::Error;
            value.error = Some(error.clone());
            return Err(error);
        }
    }
    Ok(snapshot(&app, &value))
}

#[tauri::command]
pub(crate) async fn download_update(
    app: AppHandle,
    runtime: State<'_, SharedUpdateRuntime>,
) -> Result<UpdateSnapshot, String> {
    let shared = runtime.inner().clone();
    let update = {
        let mut value = lock(&shared)?;
        let update = value
            .available
            .clone()
            .ok_or_else(|| "没有可下载的更新".to_owned())?;
        value.status = UpdateStatus::Downloading;
        value.downloaded_bytes = 0;
        value.total_bytes = None;
        value.error = None;
        update
    };
    let progress = shared.clone();
    let result = update
        .download(
            move |chunk, total| {
                if let Ok(mut value) = progress.lock() {
                    value.downloaded_bytes = value.downloaded_bytes.saturating_add(chunk as u64);
                    value.total_bytes = total;
                }
            },
            || {},
        )
        .await;
    let mut value = lock(&shared)?;
    match result {
        Ok(bytes) => {
            value.downloaded = Some(bytes);
            value.status = UpdateStatus::Downloaded;
        }
        Err(error) => {
            let message = error.to_string();
            value.status = UpdateStatus::Error;
            value.error = Some(message.clone());
            return Err(message);
        }
    }
    Ok(snapshot(&app, &value))
}

#[tauri::command]
pub(crate) fn install_update(
    app: AppHandle,
    runtime: State<'_, SharedUpdateRuntime>,
) -> Result<UpdateSnapshot, String> {
    let (update, bytes) = {
        let mut value = lock(&runtime)?;
        let update = value
            .available
            .clone()
            .ok_or_else(|| "没有可安装的更新".to_owned())?;
        let bytes = value
            .downloaded
            .take()
            .ok_or_else(|| "更新尚未下载".to_owned())?;
        value.status = UpdateStatus::Installing;
        (update, bytes)
    };
    if let Err(error) = update.install(&bytes) {
        let mut value = lock(&runtime)?;
        let message = error.to_string();
        value.downloaded = Some(bytes);
        value.status = UpdateStatus::Error;
        value.error = Some(message.clone());
        return Err(message);
    }
    #[cfg(not(target_os = "windows"))]
    app.restart();
    #[allow(unreachable_code)]
    {
        let value = lock(&runtime)?;
        Ok(snapshot(&app, &value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_channels_have_stable_endpoints() {
        assert_eq!(UpdateChannel::Dev.as_str(), "dev");
        assert_eq!(UpdateChannel::Beta.as_str(), "beta");
        assert_eq!(UpdateChannel::Release.as_str(), "release");
        assert_eq!(
            UpdateChannel::Release.endpoint().unwrap().as_str(),
            "https://github.com/EverEcho/agent-veil/releases/download/agentveil-updates-release/latest.json"
        );
    }

    #[test]
    fn settings_reject_unknown_schema() {
        let value: UpdateSettings =
            serde_json::from_str(r#"{"schema_version":2,"channel":"dev"}"#).unwrap();
        assert_ne!(value.schema_version, SETTINGS_SCHEMA);
    }
}
