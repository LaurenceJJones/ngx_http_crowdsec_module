#!/usr/bin/env bash
# Quick smoke: one known hub AppSec test + coverage summary (local dev).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE_TEST="${HUBTEST_SMOKE_TEST:-CVE-2017-9841}"

echo "=== Hub AppSec smoke (${SMOKE_TEST}) ==="
"${ROOT}/scripts/hubtest-run.sh" "${SMOKE_TEST}"

echo
echo "=== Hub AppSec coverage (percent) ==="
"${ROOT}/scripts/hubtest-coverage.sh" --percent
