# ngx_http_crowdsec_module

Native CrowdSec enforcement for NGINX — one `.so`, normal directives, no Lua bouncer in the request path.

Stream bans, captcha, AppSec WAF, bot challenge, and Prometheus metrics. Compiled into NGINX; fails open when LAPI is unreachable.

## Why this instead of the Lua bouncer?

- **Same job, fewer moving parts** — load a module, set `crowdsec on`; no bouncer scripts to ship or JIT on every request.
- **Features you expect** — LAPI stream decisions, captcha providers, AppSec on GET/POST, trusted proxies, custom ban pages.
- **Tested** — 21 CI tests against real CrowdSec v1.8.1; **100%** hub AppSec block coverage (211/211 rules; [details](docs/testing.md)).

## Try it

```bash
git clone https://github.com/LaurenceJJones/ngx_http_crowdsec_module.git
cd ngx_http_crowdsec_module
docker compose up --build -d

curl http://localhost:9090/
curl http://localhost:9090/health    # crowdsec off
```

More: [docker/README.md](docker/README.md).

## Test it (CI path)

```bash
git submodule update --init --recursive
docker build -f docker/Dockerfile -t nginx-crowdsec:test .
./scripts/test-bats-ci.sh
```

**21 tests** — real CrowdSec v1.8.1 + AppSec, bot challenge. Full matrix: [docs/testing.md](docs/testing.md).

Optional — run all **211 hub AppSec rule tests** against the module (~7 min, local only):

```bash
./scripts/hubtest-target.sh up && ./scripts/hubtest-run.sh --all
```

## Production

1. Install a release `.so` matching your `nginx -V` from [Releases](https://github.com/LaurenceJJones/ngx_http_crowdsec_module/releases), or [build](#building).
2. Register a bouncer: `cscli bouncers add nginx-bouncer`
3. Configure:

```nginx
load_module /etc/nginx/modules/libngx_http_crowdsec_module.so;

http {
    crowdsec_url http://127.0.0.1:8080;
    crowdsec_api_key YOUR_BOUNCER_KEY;
    crowdsec_shm_size 16m;
    crowdsec_ban_template /etc/nginx/templates/default.html;

    server {
        listen 80;
        crowdsec on;

        location / { proxy_pass http://upstream; }
        location /health { crowdsec off; return 200 "OK"; }
    }
}
```

4. `nginx -t && systemctl reload nginx`

AppSec, captcha, templates, proxies: [docs/configuration.md](docs/configuration.md).

## Docs

| | |
|-|-|
| Configuration | [docs/configuration.md](docs/configuration.md) |
| Testing & coverage | [docs/testing.md](docs/testing.md) |
| Docker dev stack | [docker/README.md](docker/README.md) |
| Ban templates | [templates/README.md](templates/README.md) |
| Benchmarks vs Lua | [benchmarks/results.md](benchmarks/results.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

## Building

```bash
docker build -f docker/Dockerfile -t nginx-crowdsec .
```

From source: set `NGINX_SOURCE_DIR` / `NGINX_BUILD_DIR`, then `cargo build --release`. See [docker/Dockerfile](docker/Dockerfile).

## License

MIT — [LICENSE](LICENSE). Copyright (c) 2025 Laurence Jones.
