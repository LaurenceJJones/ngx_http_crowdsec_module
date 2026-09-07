#!/usr/bin/env bats

setup() {
  load "${TEST_DIR}/lib/setup.sh"
  crowdsec_cleanup_decisions
}

@test "stream IP ban blocks client" {
  decision_add_ip "$CLIENT_IP" ban
  assert_http_eventually 403
}

@test "stream IP ban unban restores access" {
  decision_add_ip "$CLIENT_IP" ban
  wait_for_http_code 403 GET http://nginx:8080/ "" "$STREAM_SYNC_WAIT" >/dev/null

  decision_delete_ip "$CLIENT_IP"
  assert_http_eventually 200
}

@test "unknown remediation type mapped to ban (fallback_remediation)" {
  decision_add_ip "$CLIENT_IP" mfa
  assert_http_eventually 403

  decision_delete_ip "$CLIENT_IP"
  assert_http_eventually 200
}
