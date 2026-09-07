# Real CrowdSec docker-compose lifecycle helpers.

integration_stack_up() {
  integration_stack_down

  docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT_NAME" up -d --wait

  wait_for_crowdsec_ready
  wait_for_bouncer_registered
  wait_for_appsec_ready

  docker exec "$NGINX_CONTAINER" nginx -t

  local i
  for i in $(seq 1 30); do
    if docker exec "$CLIENT_CONTAINER" curl -sf -o /dev/null http://nginx:8080/ 2>/dev/null \
      && docker exec "$CLIENT_CONTAINER" curl -sf -o /dev/null http://proxy:8081/ 2>/dev/null; then
      break
    fi
    sleep 1
  done

  CLIENT_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CLIENT_CONTAINER")"
  export CLIENT_IP
  [[ -n "$CLIENT_IP" ]]
}

integration_stack_down() {
  docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT_NAME" down --remove-orphans -v 2>/dev/null || true
}

integration_stack_logs() {
  docker logs "$NGINX_CONTAINER" 2>&1 || true
  docker logs "$LAPI_CONTAINER" 2>&1 || true
  docker logs "${UPSTREAM_CONTAINER:-cs-int-upstream}" 2>&1 || true
}

STREAM_SYNC_WAIT="${STREAM_SYNC_WAIT:-25}"
