# ngx_http_crowdsec_module

**CrowdSec enforcement built into NGINX** — a native dynamic module, not a Lua bouncer script.

CrowdSec watches your logs, spots attackers, and tells your bouncer who to block. The official [lua-cs-bouncer](https://github.com/crowdsecurity/lua-cs-bouncer) runs that logic as **Lua inside the request path**: scripts loaded at runtime, executed on every check. Most distros can install NGINX with a Lua module — you do not need a special fork — but you are still running interpreted bouncer code in the hot path, maintaining scripts, and trusting a separate runtime to do security work on every request.

This module does the same job differently. It is compiled into a single `.so`, configured with normal NGINX directives, and runs as part of the server itself. Point it at your LAPI, turn it on per server or location, and you get bans, captcha, AppSec, and metrics without bolting on a scripting layer.

## Why use it?

**It is part of NGINX, not a script on top of it.** Load one module, set `crowdsec on`, done. No bouncer Lua files to deploy, update, or debug. Configuration lives in your NGINX config where it belongs.

**No Lua runtime in the security path.** Enforcement is compiled ahead of time — not JIT'd or interpreted on each request. That means fewer moving parts, a smaller attack surface, and behavior you can reason about from a binary built for your NGINX version rather than scripts that change independently of your server.

**You get the features CrowdSec users expect.** Stream bans from LAPI into shared memory so every worker sees the same decisions. Captcha remediations (hCaptcha, reCAPTCHA, Turnstile). AppSec on GET and POST. Prometheus metrics if you want them. Bypass lists and trusted-proxy handling when NGINX sits behind Cloudflare or another reverse proxy.

**It fails open when things go wrong.** If LAPI is down, traffic keeps flowing — your site does not go dark because the bouncer could not phone home. One worker polls; the rest read from shared memory. Misconfiguration shows up at `nginx -t`.

**It is fast on top of all that.** In synthetic benchmarks against the Lua bouncer, this module handles roughly **1.7×** the throughput on a simple allow path ([details](benchmarks/results.md)). On most real sites that difference is hard to notice — but it is there if you need it.

## Try it in five minutes

Docker spins up NGINX, CrowdSec, and a pre-built module:

```bash
git clone https://github.com/LaurenceJJones/ngx_http_crowdsec_module.git
cd ngx_http_crowdsec_module
docker compose up --build -d

curl http://localhost:9090/         # protected
curl http://localhost:9090/health   # crowdsec off

docker exec crowdsec cscli decisions add --ip 1.2.3.4 --type ban --duration 1h --reason "test"
docker compose down
```

More in [docker/README.md](docker/README.md).

## Production setup

You need NGINX with dynamic module support, a running CrowdSec LAPI, and a bouncer API key.

1. **Get the module** — download a release `.so` that matches your NGINX version from [Releases](https://github.com/LaurenceJJones/ngx_http_crowdsec_module/releases), or [build](#building) against your exact `nginx -V` output.

2. **Register a bouncer** on the CrowdSec host:

   ```bash
   cscli bouncers add nginx-bouncer
   ```

3. **Configure NGINX:**

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

4. **Test and reload:**

   ```bash
   nginx -t && systemctl reload nginx
   ```

Behind a CDN or reverse proxy, make sure NGINX sees the real client IP — usually with the standard [`real_ip`](docs/configuration.md#client-ip-behind-a-reverse-proxy) module, or with `crowdsec_trusted_proxies` if you prefer CrowdSec-specific settings. Captcha and custom ban pages need template files; examples are in [`templates/`](templates/).

Full directive reference: [docs/configuration.md](docs/configuration.md).

## Documentation

| Topic | Link |
|-------|------|
| All directives, AppSec, captcha, templates | [docs/configuration.md](docs/configuration.md) |
| Docker dev environment | [docker/README.md](docker/README.md) |
| Ban page templates | [templates/README.md](templates/README.md) |
| Benchmarks vs Lua bouncer | [benchmarks/results.md](benchmarks/results.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

## Building

**Docker (recommended):**

```bash
docker build -f docker/Dockerfile -t nginx-crowdsec .
docker build -f docker/Dockerfile --build-arg NGINX_VERSION=1.24.0 -t nginx-crowdsec .
```

**From source:** set `NGINX_SOURCE_DIR` and `NGINX_BUILD_DIR`, then `cargo build --release`. Output: `target/release/libngx_http_crowdsec_module.so`. See [docker/Dockerfile](docker/Dockerfile) for the configure flags used in CI.

## Troubleshooting

- **Module won't load** — the `.so` must match your NGINX version and platform. Check `nginx -V` against the release compatibility notes.
- **Reload fails after upgrade** — do a full stop/start, not reload, if shared memory layout changed.
- **No bans appearing** — confirm LAPI is reachable and the bouncer key is valid: `curl -H "X-Api-Key: KEY" http://127.0.0.1:8080/v1/decisions/stream?startup=true`.
- **No poll messages in the log** — normal when nothing changed; see [logging and debugging](docs/configuration.md#logging-and-debugging-lapi-polling).

More: [docs/configuration.md#troubleshooting](docs/configuration.md#troubleshooting).

## Contributing

Fork, branch, PR. CI runs on every push — see [.github/workflows/ci.yml](.github/workflows/ci.yml).

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2025 Laurence Jones.
