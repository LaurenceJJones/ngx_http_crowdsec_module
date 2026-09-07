#!/usr/bin/env bash
# Report CrowdSec hub AppSec test coverage (rules with/without hubtests).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HUB_DIR="${HUB_DIR:-${ROOT}/.hub}"
CSCLI="${CSCLI:-cscli}"
CSCLI_CONFIG="${CSCLI_CONFIG:-${ROOT}/docker/hubtest-cscli/coverage-config.yaml}"
CROWDSEC_IMAGE="${CROWDSEC_IMAGE:-crowdsecurity/crowdsec:v1.8.1}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [--percent] [--json]

Shows which hub AppSec rules have functional tests in .appsec-tests/.
Use before/after adding module fixes to track gaps.

  --percent   Only print overall coverage percentage
  --json      JSON output (cscli -o json)

Requires: ./scripts/hubtest-setup.sh
EOF
}

percent_only=0
output_args=()

while (($# > 0)); do
  case "$1" in
    --percent)
      percent_only=1
      output_args+=(--percent)
      ;;
    --json)
      output_args+=(-o json)
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown flag: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

"${ROOT}/scripts/hubtest-setup.sh"

run_cscli() {
  if command -v "${CSCLI}" >/dev/null 2>&1; then
    (cd "${HUB_DIR}" && exec "${CSCLI}" -c "${CSCLI_CONFIG}" hubtest coverage --appsec --hub "${HUB_DIR}" "${output_args[@]}")
    return
  fi

  docker run --rm --entrypoint cscli -w /hub \
    -v "${HUB_DIR}:/hub:z" \
    -v "${ROOT}/docker/hubtest-cscli:/etc/crowdsec:ro,z" \
    -v cshub-coverage-data:/var/lib/crowdsec/data \
    "${CROWDSEC_IMAGE}" \
    -c /etc/crowdsec/coverage-config.yaml hubtest coverage --appsec --hub /hub "${output_args[@]}"
}

if ((percent_only)); then
  run_cscli 2>/dev/null | rg -o 'appsec_rules=[0-9]+%' || run_cscli
else
  run_cscli 2>&1 | rg -v '^level=info'
fi
