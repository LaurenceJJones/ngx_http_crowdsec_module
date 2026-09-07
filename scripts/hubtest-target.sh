#!/usr/bin/env bash
# Start/stop the NGINX hubtest target (port 7822, host networking).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT}/docker/compose.hubtest.yml"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-cshubtest}"
NGINX_CROWDSEC_IMAGE="${NGINX_CROWDSEC_IMAGE:-nginx-crowdsec:test}"

usage() {
  cat <<EOF
Usage: $(basename "$0") up|down|status|logs

  up      Build image if missing, start NGINX on 127.0.0.1:7822 (host network)
  down    Stop the target
  status  Show compose status and probe :7822
  logs    Tail NGINX logs

Environment:
  NGINX_CROWDSEC_IMAGE   Docker image (default: nginx-crowdsec:test)
  HUBTEST_TARGET         Probe URL (default: http://127.0.0.1:7822/)
EOF
}

cmd="${1:-up}"
shift || true

case "${cmd}" in
  up)
    if ! docker image inspect "${NGINX_CROWDSEC_IMAGE}" >/dev/null 2>&1; then
      echo "Building ${NGINX_CROWDSEC_IMAGE}..."
      docker build -f "${ROOT}/docker/Dockerfile" -t "${NGINX_CROWDSEC_IMAGE}" "${ROOT}"
    fi
    NGINX_CROWDSEC_IMAGE="${NGINX_CROWDSEC_IMAGE}" \
      docker compose -f "${COMPOSE_FILE}" -p "${COMPOSE_PROJECT_NAME}" up -d --force-recreate
    ;;
  down)
    docker compose -f "${COMPOSE_FILE}" -p "${COMPOSE_PROJECT_NAME}" down --remove-orphans
    ;;
  status)
    docker compose -f "${COMPOSE_FILE}" -p "${COMPOSE_PROJECT_NAME}" ps
    target="${HUBTEST_TARGET:-http://127.0.0.1:7822/}"
    code="$(curl -s -o /dev/null -w '%{http_code}' "${target}" || true)"
    if [[ "${code}" =~ ^[0-9]+$ ]]; then
      echo "target ${target}: up (HTTP ${code})"
    else
      echo "target ${target}: down" >&2
      exit 1
    fi
    ;;
  logs)
    docker logs -f cs-hubtest-nginx
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
