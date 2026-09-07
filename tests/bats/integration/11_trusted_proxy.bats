#!/usr/bin/env bats

setup() {
  load "${TEST_DIR}/lib/setup.sh"
  crowdsec_cleanup_decisions
}

proxy_curl() {
  local xff="$1"
  shift
  docker exec "$CLIENT_CONTAINER" curl -s -H "X-Forwarded-For: ${xff}" "$@"
}

@test "trusted proxy resolves client IP from X-Forwarded-For for stream bans" {
  local xff_ip="203.0.113.50"
  local xff_header="X-Forwarded-For: ${xff_ip}"

  decision_add_ip "$xff_ip" ban
  run wait_for_http_code 403 GET "http://proxy:8081/" "" "$STREAM_SYNC_WAIT" "$xff_header"
  assert_success

  run proxy_curl "$xff_ip" -si "http://proxy:8081/"
  assert_success
  assert_output --partial "403"

  decision_delete_ip "$xff_ip"
  run wait_for_http_code 200 GET "http://proxy:8081/" "" "$STREAM_SYNC_WAIT" "$xff_header"
  assert_success
}
