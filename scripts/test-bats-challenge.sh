#!/usr/bin/env bash
# Run CrowdSec 1.8 bot-challenge BATS tests (docker/compose.challenge.yml).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export TEST_DIR="${ROOT}/tests"
export TEST_STACK=challenge
export NGINX_CROWDSEC_IMAGE="${NGINX_CROWDSEC_IMAGE:-nginx-crowdsec:test}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-cschallenge}"

cleanup() {
  local code=$?
  # shellcheck source=tests/lib/common.bash
  source "${TEST_DIR}/lib/common.bash"
  # shellcheck source=tests/lib/challenge_stack.bash
  source "${TEST_DIR}/lib/challenge_stack.bash"
  if [[ "$code" -ne 0 ]]; then
    challenge_stack_logs
  fi
  challenge_stack_down
  exit "$code"
}

trap cleanup EXIT

if ! docker image inspect "$NGINX_CROWDSEC_IMAGE" >/dev/null 2>&1; then
  echo "Building ${NGINX_CROWDSEC_IMAGE}..." >&2
  docker build --pull -t "$NGINX_CROWDSEC_IMAGE" -f "${ROOT}/docker/Dockerfile" "$ROOT"
fi

chmod +x "${TEST_DIR}/run-tests" "${TEST_DIR}/bin/"*
"${TEST_DIR}/run-tests" "${TEST_DIR}/bats/challenge" "$@"
