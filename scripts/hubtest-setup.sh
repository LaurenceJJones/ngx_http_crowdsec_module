#!/usr/bin/env bash
# Clone or update the CrowdSec hub repository (AppSec rule tests live in .appsec-tests/).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HUB_DIR="${HUB_DIR:-${ROOT}/.hub}"
HUB_REPO="${HUB_REPO:-https://github.com/crowdsecurity/hub.git}"
HUB_REF="${HUB_REF:-master}"

if ! command -v git >/dev/null 2>&1; then
  echo "git is required" >&2
  exit 1
fi

if [[ -d "${HUB_DIR}/.git" ]]; then
  echo "Updating hub checkout in ${HUB_DIR} (ref ${HUB_REF})..."
  git -C "${HUB_DIR}" fetch --depth 1 origin "${HUB_REF}"
  git -C "${HUB_DIR}" checkout -q FETCH_HEAD
else
  echo "Cloning ${HUB_REPO} into ${HUB_DIR} (ref ${HUB_REF})..."
  git clone --depth 1 --branch "${HUB_REF}" "${HUB_REPO}" "${HUB_DIR}"
fi

test_count="$(find "${HUB_DIR}/.appsec-tests" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')"
echo "Hub ready: ${test_count} AppSec hubtests under ${HUB_DIR}/.appsec-tests"
