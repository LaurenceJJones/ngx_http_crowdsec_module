#!/usr/bin/env bats

setup() {
  load "${TEST_DIR}/lib/setup.sh"
}

@test "nginx config is valid" {
  run docker exec "$NGINX_CONTAINER" nginx -t
  assert_success
}

@test "baseline request returns 200" {
  assert_http_code 200
}

@test "health endpoint bypasses crowdsec" {
  assert_http_code 200 GET http://nginx:8080/health
}
