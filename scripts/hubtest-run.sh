#!/usr/bin/env bash
# Run CrowdSec hub AppSec tests against this module's NGINX target (local only).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HUB_DIR="${HUB_DIR:-${ROOT}/.hub}"
HUBTEST_TARGET="${HUBTEST_TARGET:-http://127.0.0.1:7822/}"
HUBTEST_APPSEC_HOST="${HUBTEST_APPSEC_HOST:-127.0.0.1:4241}"
CSCLI="${CSCLI:-cscli}"
CROWDSEC="${CROWDSEC:-crowdsec}"
NUCLEI="${NUCLEI:-nuclei}"
RUNNER_IMAGE="${HUBTEST_RUNNER_IMAGE:-crowdsec-hubtest-runner:v1.8.1}"
CSCLI_CONFIG="${CSCLI_CONFIG:-${ROOT}/docker/hubtest-cscli/config.yaml}"
USE_DOCKER="${HUBTEST_USE_DOCKER:-auto}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [hubtest run flags] [--all | TEST ...]

Examples:
  $(basename "$0") --all
  $(basename "$0") CVE-2017-9841
  $(basename "$0") --report-success CVE-2017-9841

Prerequisites:
  ./scripts/hubtest-setup.sh
  ./scripts/hubtest-target.sh up

Environment:
  HUB_DIR                 Hub checkout (default: ${ROOT}/.hub)
  HUBTEST_TARGET          Nuclei target (default: http://127.0.0.1:7822/)
  HUBTEST_APPSEC_HOST     Ephemeral AppSec bind (default: 127.0.0.1:4241)
  HUBTEST_USE_DOCKER      auto|1|0 — run via Docker runner (default: auto)
  HUBTEST_RUNNER_IMAGE    Docker image with cscli+crowdsec+nuclei
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

"${ROOT}/scripts/hubtest-setup.sh"
"${ROOT}/scripts/hubtest-target.sh" status

if [[ ! -d "${HUB_DIR}/.appsec-tests" ]]; then
  echo "missing ${HUB_DIR}/.appsec-tests — run ./scripts/hubtest-setup.sh" >&2
  exit 1
fi

if (($# == 0)); then
  echo "Pass --all or one or more test names (see: cscli hubtest list --appsec --hub ${HUB_DIR})" >&2
  exit 2
fi

host_ready() {
  command -v "${CSCLI}" >/dev/null 2>&1 \
    && command -v "${CROWDSEC}" >/dev/null 2>&1 \
    && command -v "${NUCLEI}" >/dev/null 2>&1
}

run_host() {
  (cd "${HUB_DIR}" && exec "${CSCLI}" -c "${CSCLI_CONFIG}" hubtest run \
    --appsec \
    --hub "${HUB_DIR}" \
    --crowdsec "${CROWDSEC}" \
    --cscli "${CSCLI}" \
    --target "${HUBTEST_TARGET}" \
    --host "${HUBTEST_APPSEC_HOST}" \
    "$@")
}

run_docker() {
  if ! docker image inspect "${RUNNER_IMAGE}" >/dev/null 2>&1; then
    echo "Building ${RUNNER_IMAGE}..."
    docker build -t "${RUNNER_IMAGE}" -f "${ROOT}/docker/hubtest-runner/Dockerfile" "${ROOT}/docker/hubtest-runner"
  fi

  docker run --rm --network host \
    -e CROWDSEC_BYPASS_DB_VOLUME_CHECK=1 \
    -e DISABLE_ONLINE_API=true \
    -e CI_TESTING=true \
    -v "${HUB_DIR}:/hub:z" \
    -v cshub-coverage-data:/var/lib/crowdsec/data \
    -w /hub \
    "${RUNNER_IMAGE}" \
    hubtest run \
      --appsec \
      --hub /hub \
      --crowdsec /usr/local/bin/crowdsec \
      --cscli /usr/local/bin/cscli \
      --target "${HUBTEST_TARGET}" \
      --host "${HUBTEST_APPSEC_HOST}" \
      --clean \
      "$@"
}

case "${USE_DOCKER}" in
  1|true|yes)
    run_docker "$@"
    ;;
  0|false|no)
    "${ROOT}/tests/bin/check-hubtest-requirements"
    run_host "$@"
    ;;
  auto)
    if host_ready; then
      run_host "$@"
    else
      echo "Host cscli/crowdsec/nuclei not found; using Docker runner (${RUNNER_IMAGE})" >&2
      run_docker "$@"
    fi
    ;;
  *)
    echo "invalid HUBTEST_USE_DOCKER=${USE_DOCKER}" >&2
    exit 2
    ;;
esac
