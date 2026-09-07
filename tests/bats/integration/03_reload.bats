#!/usr/bin/env bats

setup() {
  load "${TEST_DIR}/lib/setup.sh"
  crowdsec_cleanup_decisions
}

@test "stream CIDR ban blocks client after reload" {
  run docker exec "$NGINX_CONTAINER" nginx -s reload
  assert_success
  sleep 2

  decision_add_cidr "${CLIENT_IP}/32"
  assert_http_eventually 403

  decision_delete_cidr "${CLIENT_IP}/32"
  assert_http_eventually 200
}

@test "reload stress keeps requests healthy" {
  local i
  for i in $(seq 1 10); do
    run docker exec "$NGINX_CONTAINER" nginx -s reload
    assert_success
    sleep 1
    assert_http_code 200
  done
}
