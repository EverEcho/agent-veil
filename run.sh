#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

require_command() {
  local command_name="$1"
  local install_hint="$2"

  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "错误：未找到 ${command_name}。" >&2
    echo "请先执行：${install_hint}" >&2
    exit 1
  fi
}

require_command go "brew install go"
require_command cargo "安装 Rust：https://rustup.rs"

if ! cargo tauri --version >/dev/null 2>&1; then
  echo "未检测到 Tauri CLI，正在安装 Tauri 2 CLI..."
  cargo install tauri-cli --version "^2.0.0" --locked
fi

echo "正在构建 AgentVeil Core..."
(
  cd "$ROOT_DIR"
  go build -trimpath -o veil ./cmd/veil
)

if [[ "$(uname -s)" == "Darwin" ]]; then
  config_dir="${HOME}/Library/Application Support/agentveil"
else
  config_dir="${XDG_CONFIG_HOME:-${HOME}/.config}/agentveil"
fi

# `cargo tauri dev` is single-instance. Without replacing the previous debug
# shell, a rebuilt process exits immediately and merely focuses the stale UI.
existing_desktop_pids=""
while IFS= read -r desktop_pid; do
  [[ "$desktop_pid" =~ ^[0-9]+$ ]] || continue
  if [[ "$(uname -s)" == "Darwin" ]]; then
    desktop_cwd="$(lsof -a -p "$desktop_pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p')"
  else
    desktop_cwd="$(readlink "/proc/${desktop_pid}/cwd" 2>/dev/null || true)"
  fi
  if [[ "$desktop_cwd" == "${ROOT_DIR}/desktop/src-tauri" ]]; then
    existing_desktop_pids+="${desktop_pid}"$'\n'
  fi
done < <(pgrep -f '(^|/)target/debug/agentveil-desktop$' || true)

if [[ -n "${existing_desktop_pids//[[:space:]]/}" ]]; then
  if [[ -f "${config_dir}/core.json" ]]; then
    token_file="${config_dir}/desktop.token"
    if [[ ! -f "$token_file" ]]; then
      echo "错误：旧桌面端可能仍有 Core，但缺少管理凭据，无法安全替换。" >&2
      exit 1
    fi
    if ! sessions="$(VEIL_ADMIN_TOKEN="$(tr -d '\r\n' < "$token_file")" "$ROOT_DIR/veil" sessions list)"; then
      echo "错误：无法确认旧桌面端是否仍有活动保护会话，本次开发启动不会中断它。" >&2
      exit 1
    fi
    if [[ "${sessions//[[:space:]]/}" != "[]" ]]; then
      echo "错误：旧桌面端仍有活动保护会话，本次开发启动不会中断它。" >&2
      exit 1
    fi
  fi
  echo "正在替换当前项目的旧 AgentVeil Desktop..."
  while IFS= read -r desktop_pid; do
    [[ "$desktop_pid" =~ ^[0-9]+$ ]] || continue
    kill -TERM "$desktop_pid"
  done <<< "$existing_desktop_pids"
  for _ in {1..50}; do
    desktop_alive=false
    while IFS= read -r desktop_pid; do
      [[ "$desktop_pid" =~ ^[0-9]+$ ]] || continue
      if kill -0 "$desktop_pid" 2>/dev/null; then desktop_alive=true; fi
    done <<< "$existing_desktop_pids"
    if [[ "$desktop_alive" == false ]]; then break; fi
    sleep 0.1
  done
  while IFS= read -r desktop_pid; do
    [[ "$desktop_pid" =~ ^[0-9]+$ ]] || continue
    if kill -0 "$desktop_pid" 2>/dev/null; then
      echo "错误：旧 AgentVeil Desktop 未能安全退出。" >&2
      exit 1
    fi
  done <<< "$existing_desktop_pids"
fi

# Development builds must not silently adopt an older in-memory Core after the
# executable has been rebuilt. Replacing it is safe only when the authenticated
# Core reports no active protection sessions.
existing_core_pids="$(pgrep -f "^${ROOT_DIR}/veil serve$" || true)"
if [[ -n "$existing_core_pids" ]]; then
  token_file="${config_dir}/desktop.token"
  if [[ ! -f "$token_file" ]]; then
    echo "错误：发现旧 Core，但缺少桌面管理凭据，无法安全替换。" >&2
    exit 1
  fi
  sessions="$(VEIL_ADMIN_TOKEN="$(tr -d '\r\n' < "$token_file")" "$ROOT_DIR/veil" sessions list)"
  if [[ "${sessions//[[:space:]]/}" != "[]" ]]; then
    echo "错误：旧 Core 仍有活动保护会话，本次开发启动不会中断它。" >&2
    exit 1
  fi
  echo "正在替换无活动会话的旧 AgentVeil Core..."
  while IFS= read -r core_pid; do
    [[ "$core_pid" =~ ^[0-9]+$ ]] || continue
    kill -TERM "$core_pid"
  done <<< "$existing_core_pids"
  for _ in {1..50}; do
    if ! pgrep -f "^${ROOT_DIR}/veil serve$" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
  if pgrep -f "^${ROOT_DIR}/veil serve$" >/dev/null 2>&1; then
    echo "错误：旧 Core 未能安全退出。" >&2
    exit 1
  fi
fi

echo "正在启动 AgentVeil Desktop..."
cd "$ROOT_DIR/desktop"
export VEIL_CORE_EXECUTABLE="$ROOT_DIR/veil"
exec cargo tauri dev
