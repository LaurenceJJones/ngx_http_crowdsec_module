#!/usr/bin/env bats

setup() {
  load "${TEST_DIR}/lib/setup.sh"
}

@test "CrowdSec 1.8 bot challenge serves fingerprint page" {
  run client_curl_si -A "curl/bats-integration" http://nginx:8080/
  assert_success
  assert_output --partial "200 OK"
  assert_output --partial "CrowdSec Challenge"
  assert_output --partial "__crowdsecChallengeStatus"
  assert_output --partial "text/html"
}

@test "browser-like User-Agent receives challenge page (no e2e submit)" {
  run client_curl_si \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
    http://nginx:8080/
  assert_success
  assert_output --partial "200 OK"
  assert_output --partial "CrowdSec Challenge"
}
