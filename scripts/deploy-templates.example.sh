#!/usr/bin/env bash
# Example: copy to deploy-templates.local.sh and set your host (local file is gitignored).
#
#   cp scripts/deploy-templates.example.sh scripts/deploy-templates.local.sh
#   $EDITOR scripts/deploy-templates.local.sh
#   ./scripts/deploy-templates.local.sh
#
# Required environment (set in the local copy or export before running):
#   CROWDSEC_DEPLOY_HOST   e.g. root@your-server.example.com
#   CROWDSEC_DEPLOY_PORT   SSH port (default: 22)
#   CROWDSEC_TEMPLATE_DIR  Remote template directory (default: /etc/nginx/templates)
#   CROWDSEC_SSH_KEY       Optional path to private key

set -euo pipefail

: "${CROWDSEC_DEPLOY_HOST:?Set CROWDSEC_DEPLOY_HOST (e.g. in deploy-templates.local.sh)}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="$CROWDSEC_DEPLOY_HOST"
PORT="${CROWDSEC_DEPLOY_PORT:-22}"
DEST="${CROWDSEC_TEMPLATE_DIR:-/etc/nginx/templates}"

SSH_OPTS=(-p "$PORT" -o StrictHostKeyChecking=accept-new)
SCP_OPTS=(-P "$PORT" -o StrictHostKeyChecking=accept-new)
if [[ -n "${CROWDSEC_SSH_KEY:-}" ]]; then
  SSH_OPTS+=(-i "$CROWDSEC_SSH_KEY")
  SCP_OPTS+=(-i "$CROWDSEC_SSH_KEY")
fi
# Do not set BatchMode=yes — password fallback works when run interactively in a terminal.

echo "[deploy] Uploading templates to ${HOST}:${DEST}/"
ssh "${SSH_OPTS[@]}" "$HOST" "mkdir -p '$DEST'"
scp "${SCP_OPTS[@]}" \
  "$ROOT/templates/default.html" \
  "$ROOT/templates/captcha.html" \
  "$ROOT/templates/simple.html" \
  "$HOST:$DEST/"

echo "[deploy] Validating nginx and reloading..."
ssh "${SSH_OPTS[@]}" "$HOST" "nginx -t && systemctl reload nginx"

echo "[deploy] Done."
