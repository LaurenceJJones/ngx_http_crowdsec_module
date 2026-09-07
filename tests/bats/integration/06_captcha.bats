#!/usr/bin/env bats

setup() {
  load "${TEST_DIR}/lib/setup.sh"
  crowdsec_cleanup_decisions
}

@test "stream captcha decision renders captcha page" {
  decision_add_ip "$CLIENT_IP" captcha
  assert_response_eventually_contains "hcaptcha"

  run client_curl_body GET http://nginx:8080/
  assert_success
  assert_output --partial "hcaptcha"
  assert_output --partial "captcha-wrapper"

  decision_delete_ip "$CLIENT_IP"
  assert_response_eventually_contains "Hello from NGINX with CrowdSec!"
}
