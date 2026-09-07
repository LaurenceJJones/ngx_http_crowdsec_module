setup_suite() {
  load "${TEST_DIR}/lib/setup.sh"
  integration_stack_up
}

# Stack teardown + log dump on failure are handled by scripts/test-bats-integration.sh EXIT trap.
