#!/usr/bin/env bash

# Per-file setup helpers (mirrors crowdsec/test/lib/setup_file.sh).

bats_require_minimum_version 1.5.0

debug() {
  echo 'exec 1<&-; exec 2<&-; exec 1>&3; exec 2>&1'
}
export -f debug

eval "$(debug)"

cd "${TEST_DIR}"
export PATH="${TEST_DIR}/bin:${PATH}"
