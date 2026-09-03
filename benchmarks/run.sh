#!/usr/bin/env bash
# Compare ngx_http_crowdsec_module (Rust) vs crowdsecurity/openresty (Lua bouncer).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCH="$ROOT/benchmarks"
COMPOSE=(docker compose -f "$BENCH/docker-compose.yml" -p bench)
WRK_THREADS="${WRK_THREADS:-2}"
WRK_CONNECTIONS="${WRK_CONNECTIONS:-64}"
WRK_DURATION="${WRK_DURATION:-10s}"
SYNC_WAIT="${SYNC_WAIT:-8}"
STATE_DIR="$BENCH/.state"
RESULTS="$BENCH/results.md"
JSON="$BENCH/results.json"

log() { printf '[bench] %s\n' "$*" >&2; }

write_state() {
  local decisions="$1"
  mkdir -p "$STATE_DIR"
  python3 "$BENCH/generate_decisions.py" "$decisions" >"$STATE_DIR/decisions.json"
  printf '%s' "${2:-{\"_status\":200,\"action\":\"allow\"}}" >"$STATE_DIR/appsec.json"
}

stop_stack() {
  "${COMPOSE[@]}" down --remove-orphans >/dev/null 2>&1 || true
}

wait_http() {
  local url="$1"
  for _ in $(seq 1 40); do
    if docker run --rm --network bench_bench curlimages/curl:8.16.0 -sf -o /dev/null "$url"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

sample_stats() {
  docker stats "$1" --no-stream --format '{{.MemUsage}} | {{.CPUPerc}}' 2>/dev/null | head -1
}

run_wrk() {
  local scenario="$1"
  local bouncer="$2"
  local url="$3"
  local container="$4"
  log "wrk $scenario ($bouncer)"
  local idle loaded out
  idle="$(sample_stats "$container")"
  out="$(docker exec bench-wrk-1 wrk -t"$WRK_THREADS" -c"$WRK_CONNECTIONS" -d"$WRK_DURATION" --latency "$url" 2>&1)" || out="ERROR: wrk failed"
  loaded="$(sample_stats "$container")"
  python3 - "$scenario" "$bouncer" "$idle" "$loaded" "$out" <<'PY'
import json, re, sys

scenario, bouncer, idle, loaded, out = sys.argv[1:6]

def to_ms(val, unit):
    v = float(val)
    if unit == "s":
        return v * 1000
    if unit == "ms":
        return v
    return v / 1000

row = {
    "scenario": scenario,
    "bouncer": bouncer,
    "rps": None,
    "latency_avg_ms": None,
    "p99_ms": None,
    "mem_cpu_idle": idle.strip(),
    "mem_cpu_loaded": loaded.strip(),
}
m = re.search(r"Requests/sec:\s+([\d.]+)", out)
if m:
    row["rps"] = float(m.group(1))
m = re.search(r"Latency\s+([\d.]+)(ms|us|s)", out)
if m:
    row["latency_avg_ms"] = to_ms(m.group(1), m.group(2))
m = re.search(r"99%\s+([\d.]+)(ms|us|s)", out)
if m:
    row["p99_ms"] = to_ms(m.group(1), m.group(2))
print(json.dumps(row))
PY
}

run_scenario() {
  local name="$1"
  local rust_conf="$2"
  local decisions="$3"
  local appsec="${4:-off}"
  log "=== Scenario: $name (decisions=$decisions, appsec=$appsec) ==="
  write_state "$decisions"
  if [[ "$rust_conf" != "nginx.conf" ]]; then
    cp "$BENCH/rust/$rust_conf" "$BENCH/rust/nginx.conf"
  fi

  export BENCH_STATE="$STATE_DIR"
  if [[ "$appsec" == "on" ]]; then
    APPSEC_URL=http://mock:7422 "${COMPOSE[@]}" up -d --force-recreate mock nginx-rust openresty wrk >/dev/null
    docker exec bench-openresty-1 sh -c \
      'if [ -f /etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf ]; then
         sed -i "s|^APPSEC_URL=.*|APPSEC_URL=http://mock:7422|" /etc/crowdsec/bouncers/crowdsec-openresty-bouncer.conf
       fi; nginx -s reload 2>/dev/null || true' || true
  else
    APPSEC_URL= "${COMPOSE[@]}" up -d --force-recreate mock nginx-rust openresty wrk >/dev/null
  fi

  docker exec bench-wrk-1 sh -c 'command -v wrk >/dev/null || apk add --no-cache wrk >/dev/null'

  sleep "$SYNC_WAIT"
  wait_http "http://nginx-rust:8080/" || log "warn: rust bouncer slow to start"
  wait_http "http://openresty/" || log "warn: openresty slow to start"

  run_wrk "$name" "Rust module" "http://nginx-rust:8080/" "bench-nginx-rust-1"
  run_wrk "$name" "OpenResty Lua" "http://openresty/" "bench-openresty-1"
}

chmod +x "$BENCH/generate_decisions.py" 2>/dev/null || true

log "Building nginx-crowdsec:bench"
docker build -f "$ROOT/docker/Dockerfile" -t nginx-crowdsec:bench "$ROOT" >/dev/null

stop_stack
mkdir -p "$STATE_DIR"
RESULT_FILE="$(mktemp)"
RUN_DATE="$(date -u +"%Y-%m-%d %H:%M UTC")"
HOSTINFO="$(uname -sr 2>/dev/null; grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs)"

{
  run_scenario "stream-empty" "nginx.conf" 0 off
  run_scenario "stream-5k-miss" "nginx.conf" 5000 off
  run_scenario "appsec-get-allow" "nginx-appsec.conf" 0 on
} >"$RESULT_FILE"
python3 - "$RUN_DATE" "$HOSTINFO" "$WRK_THREADS" "$WRK_CONNECTIONS" "$WRK_DURATION" "$RESULT_FILE" <<'PY' >"$JSON"
import json, sys
rows = [json.loads(line) for line in open(sys.argv[6]) if line.strip()]
payload = {
    "date_utc": sys.argv[1],
    "host": sys.argv[2],
    "wrk_threads": int(sys.argv[3]),
    "wrk_connections": int(sys.argv[4]),
    "wrk_duration": sys.argv[5],
    "rows": rows,
}
json.dump(payload, sys.stdout, indent=2)
PY

python3 - "$JSON" "$RESULTS" "$RUN_DATE" "$HOSTINFO" <<'PY'
import json, pathlib, sys

data = json.load(open(sys.argv[1]))
out = pathlib.Path(sys.argv[2])
run_date, host = sys.argv[3], sys.argv[4]
threads, conns, duration = data["wrk_threads"], data["wrk_connections"], data["wrk_duration"]

def fmt(v, spec):
    return format(v, spec) if v is not None else "n/a"

lines = [
    "# Benchmark: Rust module vs OpenResty Lua bouncer",
    "",
    f"**Run:** {run_date}  ",
    f"**Host:** {host}  ",
    f"**Load:** `wrk -t{threads} -c{conns} -d{duration} --latency`",
    "",
    "## Methodology",
    "",
    "| | Rust module | OpenResty Lua |",
    "|---|-------------|---------------|",
    "| Image | `nginx-crowdsec:bench` (this repo) | `crowdsecurity/openresty:latest` |",
    "| Mode | Stream (`crowdsec_poll_interval 5`) | Stream (`UPDATE_FREQUENCY=5`) |",
    "| Workers | 2 | 2 (OpenResty default) |",
    "| Upstream | Static `200 ok` | Static `200 ok` |",
    "| LAPI | Shared mock (`tests/mock_lapi.py`) | Same |",
    "",
    "**Scenarios**",
    "",
    "1. **stream-empty** — no decisions; pure bouncer overhead on allow path.",
    "2. **stream-5k-miss** — 5,000 ban entries synced; client IP not banned (cache lookup miss).",
    "3. **appsec-get-allow** — mock AppSec returns allow on every GET.",
    "",
    "## Results",
    "",
    "| Scenario | Bouncer | RPS | Avg latency | p99 | Mem \\| CPU (under load) |",
    "|----------|---------|----:|--------------:|----:|------------------------|",
]
for row in data["rows"]:
    lines.append(
        "| {scenario} | {bouncer} | {rps} | {avg} | {p99} | {mem} |".format(
            scenario=row["scenario"],
            bouncer=row["bouncer"],
            rps=fmt(row.get("rps"), ".0f"),
            avg=fmt(row.get("latency_avg_ms"), ".2f") + (" ms" if row.get("latency_avg_ms") else ""),
            p99=fmt(row.get("p99_ms"), ".2f") + (" ms" if row.get("p99_ms") else ""),
            mem=row.get("mem_cpu_loaded", "n/a"),
        )
    )

# Summary ratios for README snippet
by_scenario = {}
for row in data["rows"]:
    by_scenario.setdefault(row["scenario"], {})[row["bouncer"]] = row
summary = []
for scen, vals in by_scenario.items():
    rust, lua = vals.get("Rust module"), vals.get("OpenResty Lua")
    if rust and lua and rust.get("rps") and lua.get("rps"):
        ratio = rust["rps"] / lua["rps"]
        summary.append(f"- **{scen}:** Rust {rust['rps']:.0f} req/s vs Lua {lua['rps']:.0f} req/s ({ratio:.2f}×)")

lines += ["", "## Summary", ""] + summary + [
    "",
    "## Reproduce",
    "",
    "```bash",
    "chmod +x benchmarks/run.sh",
    "./benchmarks/run.sh",
    "```",
    "",
    "Optional: `WRK_THREADS=4 WRK_CONNECTIONS=128 WRK_DURATION=30s ./benchmarks/run.sh`",
    "",
]
out.write_text("\n".join(lines) + "\n")
print(out)
PY

stop_stack
log "Results: $RESULTS"
cat "$RESULTS"
