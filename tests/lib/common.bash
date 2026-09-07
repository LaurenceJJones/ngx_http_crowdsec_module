# Shared constants for BATS docker stacks (integration or challenge).

if [[ -n "${BATS_TEST_DIRNAME:-}" ]]; then
  REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../../.." && pwd)"
elif [[ -n "${TEST_DIR:-}" ]]; then
  REPO_ROOT="$(cd "${TEST_DIR}/.." && pwd)"
else
  REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fi

export TEST_STACK="${TEST_STACK:-integration}"
export NGINX_CROWDSEC_IMAGE="${NGINX_CROWDSEC_IMAGE:-nginx-crowdsec:test}"

case "$TEST_STACK" in
  integration)
    export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-csint}"
    COMPOSE_FILE="${REPO_ROOT}/docker/compose.integration.yml"
    NGINX_CONTAINER=cs-int-nginx
    CLIENT_CONTAINER=cs-int-client
    LAPI_CONTAINER=cs-int-crowdsec
    UPSTREAM_CONTAINER=cs-int-upstream
    ;;
  challenge)
    export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-cschallenge}"
    COMPOSE_FILE="${REPO_ROOT}/docker/compose.challenge.yml"
    NGINX_CONTAINER=cs-challenge-nginx
    CLIENT_CONTAINER=cs-challenge-client
    LAPI_CONTAINER=cs-challenge-crowdsec
    ;;
  *)
    echo "unknown TEST_STACK: ${TEST_STACK}" >&2
    return 1 2>/dev/null || exit 1
    ;;
esac

export STREAM_SYNC_WAIT="${STREAM_SYNC_WAIT:-25}"
