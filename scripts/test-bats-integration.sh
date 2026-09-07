#!/usr/bin/env bash
# Run real CrowdSec integration BATS tests (docker/compose.integration.yml).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export TEST_DIR="${ROOT}/tests"
export TEST_STACK=integration
export NGINX_CROWDSEC_IMAGE="${NGINX_CROWDSEC_IMAGE:-nginx-crowdsec:test}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-csint}"
export STREAM_SYNC_WAIT="${STREAM_SYNC_WAIT:-25}"

cleanup() {
  local code=$?
  # shellcheck source=tests/lib/common.bash
  source "${TEST_DIR}/lib/common.bash"
  # shellcheck source=tests/lib/integration_stack.bash
  source "${TEST_DIR}/lib/integration_stack.bash"
  if [[ "$code" -ne 0 ]]; then
    integration_stack_logs
  fi
  integration_stack_down
  exit "$code"
}

trap cleanup EXIT

if ! docker image inspect "$NGINX_CROWDSEC_IMAGE" >/dev/null 2>&1; then
  echo "Building ${NGINX_CROWDSEC_IMAGE}..." >&2
  docker build --pull -t "$NGINX_CROWDSEC_IMAGE" -f "${ROOT}/docker/Dockerfile" "$ROOT"
fi

chmod +x "${TEST_DIR}/run-tests" "${TEST_DIR}/bin/"*
"${TEST_DIR}/run-tests" "${TEST_DIR}/bats/integration" "$@"
