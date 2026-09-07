#!/usr/bin/env bash

# Per-file teardown (mirrors crowdsec/test/lib/teardown_file.sh).

eval "$(debug)"
# Stack teardown is handled by scripts/test-bats-*.sh EXIT traps.
