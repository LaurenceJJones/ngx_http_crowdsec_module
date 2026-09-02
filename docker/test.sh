#!/bin/bash
# Test script for CrowdSec NGINX module
set -e

if [ -z "${CONTAINER_ENGINE:-}" ]; then
    CONTAINER_ENGINE=$(command -v docker || command -v podman || true)
fi
[ -n "$CONTAINER_ENGINE" ] || { echo "docker or podman is required" >&2; exit 1; }

NGINX_URL="${NGINX_URL:-http://localhost:9090}"
CROWDSEC_CONTAINER="${CROWDSEC_CONTAINER:-crowdsec}"

echo "=== CrowdSec NGINX Module Test Suite ==="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    exit 1
}

info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

# Wait for services to be ready
info "Waiting for services to be ready..."
sleep 5

# Test 1: Health endpoint should work (crowdsec disabled)
echo ""
echo "Test 1: Health endpoint (CrowdSec disabled)"
HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$NGINX_URL/health")
if [ "$HEALTH_STATUS" = "200" ]; then
    pass "Health endpoint returns 200"
else
    fail "Health endpoint returned $HEALTH_STATUS (expected 200)"
fi

# Test 2: Normal request should pass (no ban)
echo ""
echo "Test 2: Normal request (no ban decision)"
NORMAL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$NGINX_URL/")
if [ "$NORMAL_STATUS" = "200" ]; then
    pass "Normal request returns 200"
else
    fail "Normal request returned $NORMAL_STATUS (expected 200)"
fi

# Test 3: Add a ban decision for a test IP
echo ""
echo "Test 3: Adding ban decision for IP 192.168.100.100"
"$CONTAINER_ENGINE" exec "$CROWDSEC_CONTAINER" cscli decisions add --ip 192.168.100.100 --type ban --duration 10m --reason "test ban"
if [ $? -eq 0 ]; then
    pass "Ban decision added successfully"
else
    fail "Failed to add ban decision"
fi

# Give the module time to sync (stream polling interval)
info "Waiting for decision sync (15 seconds)..."
sleep 15

# Test 4: Check that decisions are visible in CrowdSec
echo ""
echo "Test 4: Verify decision exists in CrowdSec"
DECISION_COUNT=$("$CONTAINER_ENGINE" exec "$CROWDSEC_CONTAINER" cscli decisions list -o json | grep -c "192.168.100.100" || true)
if [ "$DECISION_COUNT" -gt 0 ]; then
    pass "Decision exists in CrowdSec"
else
    fail "Decision not found in CrowdSec"
fi

# Test 5: Request from banned IP should be blocked
# Note: This test simulates the scenario, but in Docker networking
# the actual client IP seen by NGINX will be different
echo ""
echo "Test 5: Normal request still works (we can't easily spoof source IP)"
NORMAL_STATUS2=$(curl -s -o /dev/null -w "%{http_code}" "$NGINX_URL/")
if [ "$NORMAL_STATUS2" = "200" ]; then
    pass "Normal request still returns 200 (expected - source IP not spoofable)"
else
    info "Request returned $NORMAL_STATUS2"
fi

# Test 6: Remove the ban decision
echo ""
echo "Test 6: Removing ban decision"
"$CONTAINER_ENGINE" exec "$CROWDSEC_CONTAINER" cscli decisions delete --ip 192.168.100.100
if [ $? -eq 0 ]; then
    pass "Ban decision removed successfully"
else
    fail "Failed to remove ban decision"
fi

# Test 7: Check NGINX logs for CrowdSec activity
echo ""
echo "Test 7: Check NGINX logs for module activity"
NGINX_LOGS=$("$CONTAINER_ENGINE" logs nginx-crowdsec 2>&1 | grep -i "crowdsec" | head -5 || true)
if [ -n "$NGINX_LOGS" ]; then
    pass "CrowdSec module is logging"
    echo "    Sample logs:"
    echo "$NGINX_LOGS" | while read line; do echo "    $line"; done
else
    info "No CrowdSec logs found (module may be quiet)"
fi

echo ""
echo "=== Test Suite Complete ==="
echo ""
info "Note: Full integration testing requires network manipulation"
info "to test actual IP blocking. Consider using:"
info "  - Network namespaces"
info "  - X-Forwarded-For header support (future feature)"
info "  - Direct LAPI query testing"
