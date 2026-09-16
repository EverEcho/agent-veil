#!/usr/bin/env python3
"""Build a Tauri static updater manifest from renamed workflow artifacts."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote


TARGETS = {
    "darwin-aarch64": ("macos-arm64", ".app.tar.gz"),
    "darwin-x86_64": ("macos-amd64", ".app.tar.gz"),
    "linux-x86_64": ("linux-amd64", ".AppImage"),
    "windows-x86_64": ("windows-amd64", "-setup.exe"),
}


def single(directory: Path, marker: str, suffix: str) -> Path:
    matches = sorted(
        path for path in directory.iterdir()
        if marker in path.name and path.name.endswith(suffix) and not path.name.endswith(".sig")
    )
    if len(matches) != 1:
        raise SystemExit(f"expected one {marker} {suffix} updater artifact, found {len(matches)}")
    return matches[0]


def build(args: argparse.Namespace) -> dict:
    directory = Path(args.artifacts)
    platforms = {}
    for target, (marker, suffix) in TARGETS.items():
        artifact = single(directory, marker, suffix)
        signature_path = Path(f"{artifact}.sig")
        if not signature_path.is_file():
            raise SystemExit(f"missing signature: {signature_path}")
        url = (
            f"https://github.com/{args.repository}/releases/download/"
            f"{quote(args.tag, safe='')}/{quote(artifact.name, safe='')}"
        )
        platforms[target] = {
            "url": url,
            "signature": signature_path.read_text(encoding="utf-8").strip(),
        }
    return {
        "version": args.version,
        "notes": f"AgentVeil {args.version} ({args.channel})",
        "pub_date": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "platforms": platforms,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--channel", choices=("dev", "beta", "release"), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    Path(args.output).write_text(json.dumps(build(args), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
