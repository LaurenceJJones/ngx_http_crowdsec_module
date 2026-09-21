#!/usr/bin/env bash
# Build the module .so against Debian 13 nginx (for apt nginx 1.26.x).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAG="${1:-crowdsec-module:debian-trixie}"
OUT="${2:-$ROOT/dist/libngx_http_crowdsec_module-debian-trixie.so}"

mkdir -p "$(dirname "$OUT")"

echo "Building $TAG (Debian 13 nginx-dev + apt source)..."
docker build -f "$ROOT/docker/Dockerfile.debian-trixie-module" --target builder -t "$TAG" "$ROOT"

cid=$(docker create "$TAG")
docker cp "$cid:/build/target/release/libngx_http_crowdsec_module.so" "$OUT"
docker rm "$cid"

echo "Wrote: $OUT"
md5sum "$OUT"
ls -lh "$OUT"
