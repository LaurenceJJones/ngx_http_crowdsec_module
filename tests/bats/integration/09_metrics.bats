#!/usr/bin/env bats

setup() {
  load "${TEST_DIR}/lib/setup.sh"
  crowdsec_cleanup_decisions
}

@test "Prometheus metrics endpoint exposes CrowdSec counters" {
  assert_http_eventually 200

  run client_curl_body GET http://nginx:8080/crowdsec-metrics
  assert_success
  assert_output --partial "crowdsec_http_remediation_lookups_total"
  assert_output --partial "crowdsec_lapi_stream_polls_success_total"
  assert_output --partial "crowdsec_decision_cache_entries"
  assert_output --partial "crowdsec_appsec_requests_total"
  assert_output --partial "crowdsec_appsec_blocks_total"
  assert_output --partial "crowdsec_appsec_errors_total"
}

@test "AppSec block increments Prometheus AppSec counters" {
  assert_http_code 403 GET "http://nginx:8080/.git/config"
  run client_curl_body GET http://nginx:8080/crowdsec-metrics
  assert_success
  assert_output --regexp 'crowdsec_appsec_requests_total [1-9][0-9]*'
  assert_output --regexp 'crowdsec_appsec_blocks_total [1-9][0-9]*'
}
