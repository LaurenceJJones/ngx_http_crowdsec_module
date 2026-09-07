#!/usr/bin/env bats

setup() {
  load "${TEST_DIR}/lib/setup.sh"
  crowdsec_cleanup_decisions
}

@test "static asset ban returns empty 403 without HTML ban page" {
  decision_add_ip "$CLIENT_IP" ban
  assert_http_eventually 403

  run client_curl_si http://nginx:8080/favicon.ico
  assert_success
  assert_output --partial "403"
  refute_output --partial "Access restricted"

  run client_curl_si http://nginx:8080/
  assert_success
  assert_output --partial "Access restricted"

  decision_delete_ip "$CLIENT_IP"
  assert_http_eventually 200
}

@test "HTML ban template used on /simple location" {
  decision_add_ip "$CLIENT_IP" ban
  assert_http_eventually 403 GET http://nginx:8080/simple

  run client_curl_body GET http://nginx:8080/simple
  assert_success
  assert_output --partial "Access restricted"
  assert_output --partial "$CLIENT_IP"

  decision_delete_ip "$CLIENT_IP"
  assert_http_eventually 200 GET http://nginx:8080/simple
}
