#!/usr/bin/env bash

# Shared setup for every test (mirrors crowdsec/test/lib/setup.sh).

bats_require_minimum_version 1.5.0

load "${TEST_DIR}/lib/bats-support/load.bash"
load "${TEST_DIR}/lib/bats-assert/load.bash"

load "${TEST_DIR}/lib/common.bash"
load "${TEST_DIR}/lib/http.bash"

case "${TEST_STACK}" in
  integration|challenge)
    load "${TEST_DIR}/lib/crowdsec.bash"
    ;;
esac

case "${TEST_STACK}" in
  integration)
    load "${TEST_DIR}/lib/integration_stack.bash"
    ;;
  challenge)
    load "${TEST_DIR}/lib/challenge_stack.bash"
    ;;
esac

rune() {
  run --separate-stderr "$@"
}
export -f rune
