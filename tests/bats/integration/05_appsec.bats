#!/usr/bin/env bats

setup() {
  load "${TEST_DIR}/lib/setup.sh"
  crowdsec_cleanup_decisions
}

@test "AppSec blocks sensitive path probe (/.git/config)" {
  assert_http_code 403 GET "http://nginx:8080/.git/config"
}

@test "AppSec ban renders HTML ban template" {
  run client_curl_si "http://nginx:8080/.git/config"
  assert_success
  assert_output --partial "403"
  assert_output --partial "text/html"
  assert_output --partial "Access restricted"
  assert_output --partial "appsec"
}

@test "AppSec ban renders JSON template on /api" {
  run client_curl_si "http://nginx:8080/api/.git/config"
  assert_success
  assert_output --partial "403"
  assert_output --partial "application/json"
  assert_output --partial "access_denied"
  assert_output --partial '"origin": "appsec"'
}

@test "AppSec allows normal GET request" {
  assert_http_code 200 GET http://nginx:8080/
}

@test "AppSec POST allow proxies body to upstream" {
  assert_http_code 204 POST http://nginx:8080/proxy/test form=data
}
