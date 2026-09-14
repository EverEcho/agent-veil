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

# Development builds must not silently adopt an older in-memory Core after the
# executable has been rebuilt. Replacing it is safe only when the authenticated
# Core reports no active protection sessions.
existing_core_pids="$(pgrep -f "^${ROOT_DIR}/veil serve$" || true)"
if [[ -n "$existing_core_pids" ]]; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    config_dir="${HOME}/Library/Application Support/agentveil"
  else
    config_dir="${XDG_CONFIG_HOME:-${HOME}/.config}/agentveil"
  fi
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
