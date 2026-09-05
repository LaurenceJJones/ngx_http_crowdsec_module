#!/usr/bin/env bash
# Build the module .so against Ubuntu nginx-dev (for VPS apt nginx, e.g. 24.04 + 1.24.0).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAG="${1:-crowdsec-module:ubuntu-noble}"
OUT="${2:-$ROOT/dist/libngx_http_crowdsec_module-ubuntu-noble.so}"

mkdir -p "$(dirname "$OUT")"

echo "Building $TAG (Ubuntu 24.04 nginx-dev)..."
docker build -f "$ROOT/docker/Dockerfile.ubuntu-module" --target builder -t "$TAG" "$ROOT"

cid=$(docker create "$TAG")
docker cp "$cid:/build/target/release/libngx_http_crowdsec_module.so" "$OUT"
docker rm "$cid"

echo "Wrote: $OUT"
md5sum "$OUT"
ls -lh "$OUT"
