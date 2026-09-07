#!/usr/bin/env bats

setup() {
  load "${TEST_DIR}/lib/setup.sh"
  crowdsec_cleanup_decisions
}

@test "AppSec blocks sensitive path probe (/.git/config)" {
  assert_http_code 403 GET "http://nginx:8080/.git/config"
}

@test "AppSec allows normal GET request" {
  assert_http_code 200 GET http://nginx:8080/
}

@test "AppSec POST allow proxies body to upstream" {
  assert_http_code 204 POST http://nginx:8080/proxy/test form=data
}
