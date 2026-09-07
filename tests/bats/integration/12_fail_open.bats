#!/usr/bin/env bats

setup() {
  load "${TEST_DIR}/lib/setup.sh"
  crowdsec_cleanup_decisions
}

@test "requests succeed when CrowdSec LAPI is stopped (fail-open)" {
  run docker stop "$LAPI_CONTAINER"
  assert_success
  sleep 11
  assert_http_code 200
}
