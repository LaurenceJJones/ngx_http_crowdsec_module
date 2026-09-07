#!/usr/bin/env bats

setup() {
  load "${TEST_DIR}/lib/setup.sh"
  crowdsec_cleanup_decisions
}

@test "JSON ban template used on /api location" {
  decision_add_ip "$CLIENT_IP" ban
  assert_http_eventually 403 GET http://nginx:8080/api

  run client_curl_si http://nginx:8080/api
  assert_success
  assert_output --partial "403"
  assert_output --partial "application/json"
  assert_output --partial "access_denied"

  decision_delete_ip "$CLIENT_IP"
  assert_http_eventually 200 GET http://nginx:8080/api
}

@test "crowdsec disabled location bypasses enforcement" {
  decision_add_ip "$CLIENT_IP" ban
  wait_for_http_code 403 GET http://nginx:8080/ "" "$STREAM_SYNC_WAIT" >/dev/null

  assert_http_code 200 GET http://nginx:8080/test

  decision_delete_ip "$CLIENT_IP"
}
