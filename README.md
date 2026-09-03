# ngx_http_crowdsec_module

CrowdSec enforcement as a **native NGINX dynamic module** (Rust). Stream IP bans from LAPI, optional captcha remediations, AppSec, and Prometheus metrics — without OpenResty or Lua.

> **Status:** [v0.2.0-rc3](CHANGELOG.md) — stream bans, captcha, AppSec (including POST bodies), trusted proxy IP, bypass lists, ban redirects, metrics. See [CHANGELOG](CHANGELOG.md).

## Why this module?

The official [lua-cs-bouncer](https://github.com/crowdsecurity/lua-cs-bouncer) runs inside **OpenResty**. This project targets teams that already run stock NGINX (or a vendor build) and want CrowdSec at the edge with fewer moving parts.

| | This module | OpenResty + Lua bouncer |
|---|-------------|-------------------------|
| Runtime | Standard NGINX + one `.so` | OpenResty + LuaJIT + bouncer scripts |
| AppSec POST bodies | Yes (PRECONTENT phase) | Yes |
| Hot-path overhead | Lower (~1.7× in [synthetic bench](benchmarks/results.md)) | Baseline |
| Real-world latency | Usually dominated by upstream / AppSec RTT, not bouncer | Same |

**Good fit when you:**

- Already have NGINX and don't want to switch to OpenResty
- Need AppSec on POST/PUT/PATCH/DELETE without a separate WAF hop
- Want shared-memory bans across workers, fail-open behaviour, and optional Prometheus metrics in one module

**Performance note:** Benchmarks show roughly **1.7–1.8×** higher throughput and ~half the average bouncer latency vs OpenResty on a static allow path ([methodology](benchmarks/results.md)). That is a solid win on high-RPS edges; for typical sites behind TLS and `proxy_pass`, users won't feel a 2× difference — treat speed as a bonus, not the main reason to adopt.

## Quick start

### 1. Try it locally (Docker)

Fastest way to see bans working — includes CrowdSec LAPI and a pre-built module:

```bash
git clone https://github.com/LaurenceJJones/ngx_http_crowdsec_module.git
cd ngx_http_crowdsec_module
docker compose up --build -d

curl http://localhost:9090/         # protected
curl http://localhost:9090/health   # crowdsec off

docker exec crowdsec cscli decisions add --ip 1.2.3.4 --type ban --duration 1h --reason "test"
docker compose down
```

More detail: [docker/README.md](docker/README.md).

### 2. Production NGINX

**Requirements:** NGINX with dynamic module support, CrowdSec LAPI, a bouncer API key. Two small SHM zones: `crowdsec_decisions` (size from `crowdsec_shm_size`) and `crowdsec_metrics` (8 KB).

1. **Install the module** — download a release `.so` that matches your NGINX version from [Releases](https://github.com/LaurenceJJones/ngx_http_crowdsec_module/releases), or [build](#building) for your exact `nginx -V` output.

2. **Register a bouncer** on the CrowdSec host:

   ```bash
   cscli bouncers add nginx-bouncer
   ```

3. **Configure NGINX** — minimal stream-mode setup:

   ```nginx
   load_module /etc/nginx/modules/libngx_http_crowdsec_module.so;

   http {
       crowdsec_url http://127.0.0.1:8080;
       crowdsec_api_key YOUR_BOUNCER_KEY;
       crowdsec_shm_size 16m;

       server {
           listen 80;
           crowdsec on;

           location / {
               proxy_pass http://your-upstream;
           }

           location /health {
               crowdsec off;
               return 200 "OK";
           }
       }
   }
   ```

4. **Validate and reload:**

   ```bash
   nginx -t && systemctl reload nginx
   ```

Behind Cloudflare or another L7 proxy, ensure nginx sees the real client IP — either with the standard [`real_ip`](docs/configuration.md#client-ip-behind-a-reverse-proxy) module (no CrowdSec IP directives needed if already configured) or with `crowdsec_trusted_proxies` + `crowdsec_real_ip_header`. AppSec, captcha, metrics, and ban templates: [docs/configuration.md](docs/configuration.md).

## Documentation

| Topic | Link |
|-------|------|
| All directives, AppSec, captcha, templates | [docs/configuration.md](docs/configuration.md) |
| Docker dev environment & tests | [docker/README.md](docker/README.md) |
| Ban page templates | [templates/README.md](templates/README.md) |
| Benchmarks vs OpenResty Lua | [benchmarks/results.md](benchmarks/results.md) |
| Changelog & roadmap | [CHANGELOG.md](CHANGELOG.md) |

## Building

**Docker (recommended):**

```bash
docker build -f docker/Dockerfile -t nginx-crowdsec .
# Pin NGINX version if needed:
docker build -f docker/Dockerfile --build-arg NGINX_VERSION=1.24.0 -t nginx-crowdsec .
```

**From source** against your NGINX tree: set `NGINX_SOURCE_DIR` and `NGINX_BUILD_DIR`, then `cargo build --release`. The artifact is `target/release/libngx_http_crowdsec_module.so`. See [docker/Dockerfile](docker/Dockerfile) for the full configure flags used in CI.

## Troubleshooting

- **SHM after upgrade** — if reload fails with a layout/magic mismatch, do a full `nginx` stop/start (not reload).
- **Wrong `.so`** — module must match NGINX version and build; check `nginx -V` against the release compatibility file.
- **No decisions** — test LAPI: `curl -H "X-Api-Key: KEY" http://127.0.0.1:8080/v1/decisions/stream?startup=true`.

More: [docs/configuration.md#troubleshooting](docs/configuration.md#troubleshooting).

## Contributing

Fork, branch, PR. See existing [CI](.github/workflows/ci.yml) for test expectations.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2025 CrowdSec.
