use reqwest::{
    blocking::{Client, Response},
    Method,
};
use serde::Serialize;
use serde_json::Value;
use std::io::Read;
use std::time::Duration;
use tauri::State;

use crate::core_supervisor::{credentials, ready, SharedRuntime, RELEASE_CHANNEL};

pub(crate) const API_VERSION: &str = "v1";
const MAX_REQUEST_BYTES: usize = 1 << 20;
const MAX_RESPONSE_BYTES: u64 = 4 << 20;

#[derive(Serialize)]
pub(crate) struct DesktopInfo {
    desktop: bool,
    ready: bool,
    channel: &'static str,
}

pub(crate) fn client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| error.to_string())
}

pub(crate) fn get_json(
    client: &Client,
    endpoint: &str,
    token: Option<&str>,
    path: &str,
) -> Result<Value, String> {
    send(client, endpoint, token, Method::GET, path, None)
}

pub(crate) fn browser_url(runtime: &SharedRuntime) -> Result<String, String> {
    let (endpoint, token) = credentials(runtime)?;
    if endpoint.is_empty() || token.is_empty() {
        return Err("Privacy Core 尚未就绪".into());
    }
    let response = send(
        &client()?,
        &endpoint,
        Some(&token),
        Method::POST,
        "/v1/browser-sessions",
        None,
    )?;
    let ticket = response
        .get("ticket")
        .and_then(Value::as_str)
        .filter(|value| {
            value.len() == 43
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
        .ok_or_else(|| "Core 返回了无效的浏览器会话票据".to_owned())?;
    Ok(format!(
        "{}/#ticket={ticket}",
        endpoint.trim_end_matches('/')
    ))
}

#[tauri::command]
pub(crate) fn desktop_info(runtime: State<'_, SharedRuntime>) -> DesktopInfo {
    DesktopInfo {
        desktop: true,
        ready: ready(&runtime),
        channel: RELEASE_CHANNEL,
    }
}

#[tauri::command]
pub(crate) async fn core_request(
    runtime: State<'_, SharedRuntime>,
    path: String,
    method: String,
    body: Option<String>,
) -> Result<Value, String> {
    let method = Method::from_bytes(method.as_bytes()).map_err(|_| "Core 请求方法无效")?;
    if !allowed_request(&method, &path) {
        return Err("桌面页面无权访问该 Core API".into());
    }
    if body
        .as_ref()
        .is_some_and(|value| value.len() > MAX_REQUEST_BYTES)
    {
        return Err("Core 请求正文超过桌面端上限".into());
    }
    let (endpoint, token) = credentials(&runtime)?;
    if endpoint.is_empty() || token.is_empty() {
        return Err("Privacy Core 尚未就绪".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        send(
            &client()?,
            &endpoint,
            Some(&token),
            method,
            &path,
            body.as_deref(),
        )
    })
    .await
    .map_err(|_| "Core 请求任务异常退出".to_owned())?
}

fn send(
    client: &Client,
    endpoint: &str,
    token: Option<&str>,
    method: Method,
    path: &str,
    body: Option<&str>,
) -> Result<Value, String> {
    let mut request = client
        .request(
            method,
            format!("{}{}", endpoint.trim_end_matches('/'), path),
        )
        .header("X-AgentVeil-API-Version", API_VERSION)
        .header("Accept-Encoding", "identity");
    if let Some(value) = token {
        request = request.bearer_auth(value);
    }
    if let Some(value) = body {
        request = request
            .header("Content-Type", "application/json")
            .body(value.to_owned());
    }
    let response = request.send().map_err(|error| error.to_string())?;
    decode_response(response)
}

fn decode_response(mut response: Response) -> Result<Value, String> {
    let status = response.status();
    if response
        .headers()
        .get("X-AgentVeil-API-Version")
        .and_then(|value| value.to_str().ok())
        != Some(API_VERSION)
    {
        return Err("Core 管理 API 版本不兼容".into());
    }
    if !status.is_success() {
        return Err(format!("Core 返回状态 {status}"));
    }
    if status.as_u16() == 204 {
        return Ok(Value::Null);
    }
    let mut payload = Vec::new();
    response
        .by_ref()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut payload)
        .map_err(|error| error.to_string())?;
    if payload.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("Core 响应超过桌面端上限".into());
    }
    serde_json::from_slice(&payload).map_err(|_| "Core 返回了无效 JSON".into())
}

fn allowed_request(method: &Method, path: &str) -> bool {
    if path.contains(['?', '#', '\r', '\n']) || path.contains("..") {
        return false;
    }
    match (method, path) {
        (&Method::GET, "/v1/health" | "/v1/discovery" | "/v1/agents")
        | (&Method::GET, "/v1/approvals" | "/v1/audit" | "/v1/call-tree")
        | (&Method::GET, "/v1/policy" | "/v1/rules" | "/v1/models")
        | (&Method::GET, "/v1/diagnostics")
        | (&Method::PUT, "/v1/policy") => true,
        (&Method::GET, value) => single_safe_segment(value, "/v1/discovery/"),
        (&Method::POST, value) => single_safe_segment(value, "/v1/approvals/"),
        _ => false,
    }
}

fn single_safe_segment(path: &str, prefix: &str) -> bool {
    let Some(segment) = path.strip_prefix(prefix) else {
        return false;
    };
    !segment.is_empty()
        && segment.len() <= 128
        && segment
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_allows_only_dashboard_contract() {
        for (method, path) in [
            (&Method::GET, "/v1/health"),
            (&Method::GET, "/v1/discovery/codex"),
            (&Method::POST, "/v1/approvals/approval-123"),
            (&Method::PUT, "/v1/policy"),
        ] {
            assert!(allowed_request(method, path), "{method} {path}");
        }
        for (method, path) in [
            (&Method::DELETE, "/v1/sessions/root"),
            (&Method::GET, "/v1/identity"),
            (&Method::GET, "/v1/discovery/a/b"),
            (&Method::GET, "/v1/discovery/../policy"),
            (&Method::POST, "/v1/approvals/x?admin=true"),
            (&Method::PUT, "https://example.com/v1/policy"),
        ] {
            assert!(!allowed_request(method, path), "{method} {path}");
        }
    }
}
