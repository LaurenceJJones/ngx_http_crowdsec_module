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
}
