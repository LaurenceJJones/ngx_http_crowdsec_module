# cscli helpers against the real CrowdSec container (crowdsec/test-style).

cscli() {
  docker exec "$LAPI_CONTAINER" cscli "$@"
}

crowdsec_cleanup_decisions() {
  local ids
  ids="$(cscli decisions list -o json 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
except json.JSONDecodeError:
    sys.exit(0)
for item in data if isinstance(data, list) else []:
    if 'id' in item:
        print(item['id'])
" 2>/dev/null || true)"

  if [[ -z "$ids" ]]; then
    return 0
  fi

  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    cscli decisions delete "$id" >/dev/null 2>&1 || true
  done <<<"$ids"
}

decision_add_ip() {
  local ip="$1"
  local type="${2:-ban}"
  local duration="${3:-10m}"
  cscli decisions add --ip "$ip" --type "$type" --duration "$duration" --reason "bats integration"
}

decision_delete_ip() {
  local ip="$1"
  cscli decisions delete --ip "$ip"
}

decision_add_cidr() {
  local cidr="$1"
  cscli decisions add --range "$cidr" --type ban --duration 10m --reason "bats integration"
}

decision_delete_cidr() {
  local cidr="$1"
  cscli decisions delete --range "$cidr"
}

decision_add_captcha() {
  local ip="$1"
  cscli decisions add --ip "$ip" --type captcha --duration 10m --reason "bats integration"
}

wait_for_crowdsec_ready() {
  local i
  for i in $(seq 1 60); do
    if docker exec "$LAPI_CONTAINER" cscli lapi status >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for CrowdSec LAPI" >&2
  return 1
}

wait_for_bouncer_registered() {
  local i
  for i in $(seq 1 60); do
    if docker exec "$LAPI_CONTAINER" cscli bouncers list 2>/dev/null | grep -qi nginx; then
      return 0
    fi
    sleep 1
  done
  echo "timeout waiting for nginx bouncer registration" >&2
  return 1
}

wait_for_appsec_ready() {
  local i
  for i in $(seq 1 90); do
    if docker logs "$LAPI_CONTAINER" 2>&1 | grep -q "Appsec Runner ready"; then
      return 0
    fi
    sleep 2
  done
  echo "timeout waiting for AppSec runner" >&2
  return 1
}
