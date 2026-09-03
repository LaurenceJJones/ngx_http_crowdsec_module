# Benchmark: Rust module vs OpenResty Lua bouncer

**Run:** 2026-09-03 08:52 UTC  
**Host:** Linux 7.0.9-105.fc43.x86_64
12th Gen Intel(R) Core(TM) i7-12700H  
**Load:** `wrk -t2 -c64 -d10s --latency`

## Methodology

| | Rust module | OpenResty Lua |
|---|-------------|---------------|
| Image | `nginx-crowdsec:bench` (this repo) | `crowdsecurity/openresty:latest` |
| Mode | Stream (`crowdsec_poll_interval 5`) | Stream (`UPDATE_FREQUENCY=5`) |
| Workers | 2 | 2 (OpenResty default) |
| Upstream | Static `200 ok` | Static `200 ok` |
| LAPI | Shared mock (`tests/mock_lapi.py`) | Same |

**Scenarios**

1. **stream-empty** — no decisions; pure bouncer overhead on allow path.
2. **stream-5k-miss** — 5,000 ban entries synced; client IP not banned (cache lookup miss).
3. **appsec-get-allow** — mock AppSec returns allow on every GET.

## Results

| Scenario | Bouncer | RPS | Avg latency | p99 | Mem \| CPU (under load) |
|----------|---------|----:|--------------:|----:|------------------------|
| stream-empty | Rust module | 437893 | 0.12 ms | 0.34 ms | 8.559MiB / 31.07GiB | 0.00% |
| stream-empty | OpenResty Lua | 244711 | 0.26 ms | 0.34 ms | 7.336MiB / 31.07GiB | 0.00% |
| stream-5k-miss | Rust module | 423075 | 0.12 ms | 0.32 ms | 10.92MiB / 31.07GiB | 0.00% |
| stream-5k-miss | OpenResty Lua | 248654 | 0.26 ms | 0.34 ms | 9.629MiB / 31.07GiB | 0.00% |
| appsec-get-allow | Rust module | 412780 | 0.12 ms | 0.32 ms | 8.258MiB / 31.07GiB | 0.00% |
| appsec-get-allow | OpenResty Lua | 246534 | 0.26 ms | 0.35 ms | 7.555MiB / 31.07GiB | 0.01% |

## Summary

- **stream-empty:** Rust 437893 req/s vs Lua 244711 req/s (1.79×)
- **stream-5k-miss:** Rust 423075 req/s vs Lua 248654 req/s (1.70×)
- **appsec-get-allow:** Rust 412780 req/s vs Lua 246534 req/s (1.67×)

## Reproduce

```bash
chmod +x benchmarks/run.sh
./benchmarks/run.sh
```

Optional: `WRK_THREADS=4 WRK_CONNECTIONS=128 WRK_DURATION=30s ./benchmarks/run.sh`

