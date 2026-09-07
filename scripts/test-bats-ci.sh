#!/usr/bin/env bash
# Full CI BATS suite: real CrowdSec integration + bot challenge.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export NGINX_CROWDSEC_IMAGE="${NGINX_CROWDSEC_IMAGE:-nginx-crowdsec:test}"

echo "=== BATS integration (real CrowdSec LAPI + AppSec) ==="
"${ROOT}/scripts/test-bats-integration.sh"

echo "=== BATS challenge (CrowdSec 1.8 bot challenge) ==="
"${ROOT}/scripts/test-bats-challenge.sh"
