#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

channel="dev"
branch="main"
version=""
publish=false
repository="EverEcho/agent-veil"

usage() {
  echo "Usage: ./release.sh [--channel dev|beta|release] [--version X.Y.Z] [--publish]"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --channel) channel="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --publish) publish=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "${channel}" in
  dev) statement="dev-no-fatal" ;;
  beta) statement="beta-self-tested-no-known" ;;
  release) statement="release-fully-verified-no-known" ;;
  *) echo "Channel must be dev, beta, or release." >&2; exit 2 ;;
esac

if [ "${publish}" = true ]; then
  if [ -n "$(git status --porcelain)" ]; then
    echo "Working tree must be clean before publishing." >&2
    exit 1
  fi
  current_branch="$(git branch --show-current)"
  if [ "${current_branch}" != "${branch}" ]; then
    echo "Channel ${channel} must be published from branch ${branch}, not ${current_branch}." >&2
    exit 1
  fi
  git fetch origin "${branch}" --tags
fi

if [ -z "${version}" ]; then
  latest="$(git tag --list 'v[0-9]*' | sed -E 's/^v//; s/-(dev|beta)$//' | awk -F. '/^[0-9]+\.[0-9]+\.[0-9]+$/ {printf "%09d.%09d.%09d %s\n",$1,$2,$3,$0}' | sort | tail -1 | awk '{print $2}')"
  if [ -z "${latest}" ]; then version="0.1.0"; else
    IFS=. read -r major minor patch <<<"${latest}"
    version="${major}.${minor}.$((patch + 1))"
  fi
fi
if ! [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Version must be numeric SemVer, for example 0.2.0." >&2
  exit 2
fi

sha="$(git rev-parse HEAD)"
echo "Channel: ${channel}"
echo "Branch:  ${branch}"
echo "Version: ${version}"
echo "Commit:  ${sha}"

if [ "${publish}" != true ]; then
  echo "Preview only. Re-run with --publish to trigger the workflow for this exact commit."
  exit 0
fi

if [ "$(git rev-parse HEAD)" != "$(git rev-parse "origin/${branch}")" ]; then
  echo "Local ${branch} must exactly match origin/${branch}." >&2
  exit 1
fi
if git rev-parse -q --verify "refs/tags/v${version}" >/dev/null || git rev-parse -q --verify "refs/tags/v${version}-dev" >/dev/null || git rev-parse -q --verify "refs/tags/v${version}-beta" >/dev/null; then
  echo "Version ${version} already exists in a release channel." >&2
  exit 1
fi
gh auth status >/dev/null
gh workflow run package-channel.yml --repo "${repository}" --ref "${branch}" \
  -f "channel=${channel}" \
  -f "version=${version}" \
  -f "quality_statement=${statement}" \
  -f "publish_release=true" \
  -f "source_sha=${sha}"
echo "Triggered package-channel.yml for ${sha}."
