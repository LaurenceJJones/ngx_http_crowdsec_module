#!/usr/bin/env bash
# Local repro: AppSec POST body inspection must reach proxy_pass upstream (not nginx 404).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${1:-nginx-crowdsec:test}"
STATE="${RUNNER_TEMP:-/tmp}/cs-proxy-post-state"
NET=cs-proxy-post-net
UA='Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0'
MP=$'------b\r\nContent-Disposition: form-data; name="email"\r\n\r\na@b.c\r\n------b--\r\n'

rm -rf "$STATE"
mkdir -p "$STATE"
echo '{"new":[],"deleted":[]}' >"$STATE/decisions.json"
echo '{"_status":200,"action":"allow"}' >"$STATE/appsec.json"

docker rm -f cs-mock cs-up nginx-test client-test 2>/dev/null || true
docker network rm "$NET" 2>/dev/null || true
docker network create "$NET"

docker run -d --name cs-mock --network "$NET" --network-alias crowdsec \
  -v "$ROOT/tests:/mock:ro" -v "$STATE:/state:ro" \
  python:3.13-alpine python /mock/mock_lapi.py

docker run -d --name cs-up --network "$NET" --network-alias upstream \
  -v "$ROOT/tests:/mock:ro" \
  python:3.13-alpine python /mock/mock_upstream.py

upstream_ready=0
for _ in $(seq 1 30); do
  if docker run --rm --network "$NET" python:3.13-alpine \
    python -c "import socket; s=socket.create_connection(('upstream',9000),1); s.close()" \
    2>/dev/null; then
    upstream_ready=1
    break
  fi
  sleep 1
done
test "$upstream_ready" = 1
UPSTREAM_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' cs-up)

docker run -d --name nginx-test --network "$NET" \
  --add-host "upstream:${UPSTREAM_IP}" \
  -e CROWDSEC_BOUNCER_KEY=test-bouncer-key-12345 \
  -e CAPTCHA_SITE_KEY=x -e CAPTCHA_SECRET_KEY=x \
  -e CAPTCHA_SIGNING_KEY=0000000000000000000000000000000000000000000000000000000000000000 \
  "$IMAGE"

sleep 3
docker run -d --name client-test --network "$NET" curlimages/curl:8.16.0 sleep 300

docker exec nginx-test nginx -t

post() {
  docker exec client-test curl -s -o /dev/null -w '%{http_code}' "$@"
}

urlencoded=$(post -X POST -d 'x=y' -H "User-Agent: $UA" http://nginx-test:8080/proxy/login)
multipart=$(post -X POST -H "User-Agent: $UA" \
  -H 'Content-Type: multipart/form-data; boundary=----b' \
  --data-binary "$MP" http://nginx-test:8080/proxy/login)

echo "image: $IMAGE"
echo "urlencoded POST: $urlencoded (expect 204)"
echo "multipart POST:  $multipart (expect 204)"

test "$urlencoded" = 204
test "$multipart" = 204

echo "OK: AppSec POST + proxy_pass"
