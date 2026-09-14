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

echo "正在启动 AgentVeil Desktop..."
cd "$ROOT_DIR/desktop"
export VEIL_CORE_EXECUTABLE="$ROOT_DIR/veil"
exec cargo tauri dev
