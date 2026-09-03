# Configuration reference

## Loading the module

```nginx
load_module /etc/nginx/modules/libngx_http_crowdsec_module.so;
```

NGINX dynamic modules are **ABI-specific**. The `.so` must match your NGINX version, platform, and build flags. See release compatibility files on [GitHub Releases](https://github.com/LaurenceJJones/ngx_http_crowdsec_module/releases).

## Directives

All directives can be set at `http`, `server`, or `location` unless noted.

| Directive | Context | Default | Description |
|-----------|---------|---------|-------------|
| `crowdsec` | http, server, location | `off` | Enable/disable CrowdSec checking |
| `crowdsec_url` | http | - | CrowdSec LAPI URL (required) |
| `crowdsec_api_key` | http | - | Bouncer API key (required) |
| `crowdsec_trusted_proxies` | http, server | - | Optional. CIDRs of reverse proxies; client IP from forwarded header (see [Client IP](#client-ip-behind-a-reverse-proxy)) |
| `crowdsec_real_ip_header` | http, server | `X-Forwarded-For` | Header read when `crowdsec_trusted_proxies` is set |
| `crowdsec_bypass` | http, server | - | CIDRs that skip enforcement (resolved client IP) |
| `crowdsec_shm_size` | http | `1m` | Shared memory for decision cache |
| `crowdsec_max_retries` | http | `3` | Startup connection retries |
| `crowdsec_retry_interval` | http | `5` | Seconds between retries |
| `crowdsec_poll_interval` | http, server | `10` | Seconds between successful LAPI stream polls |
| `crowdsec_lapi_timeout` | http, server | `30` | LAPI HTTP timeout (seconds) |
| `crowdsec_ban_template` | http, server, location | - | **Required** when `crowdsec on` and `ban_action` is `block` |
| `crowdsec_ban_action` | http, server, location | `block` | `block` (403) or `redirect` |
| `crowdsec_ban_redirect_url` | http, server, location | - | Redirect target when `ban_action` is `redirect` |
| `crowdsec_ban_redirect_code` | http, server, location | `302` | Redirect status: `301`–`308` |
| `crowdsec_captcha_provider` | http, server, location | - | **Required for captcha.** `hcaptcha`, `recaptcha`, or `turnstile` |
| `crowdsec_captcha_site_key` | http, server, location | - | Provider site key |
| `crowdsec_captcha_secret_key` | http, server, location | - | Provider secret key |
| `crowdsec_captcha_signing_key` | http, server, location | - | 64-char hex key (`openssl rand -hex 32`) |
| `crowdsec_captcha_cookie_name` | http, server, location | `crowdsec_captcha` | Session cookie name |
| `crowdsec_captcha_expiry` | http, server, location | `3600` | Session lifetime (seconds) |
| `crowdsec_captcha_fail_open` | http, server, location | `on` | Allow on operational verification failure |
| `crowdsec_captcha_bind_ip` | http, server, location | `on` | Bind sessions to client IP |
| `crowdsec_captcha_cookie_secure` | http, server, location | `auto` | `auto`, `on`, or `off` |
| `crowdsec_captcha_template` | http, server, location | - | **Required** when captcha provider keys are configured |
| `crowdsec_appsec_url` | http, server | - | AppSec agent base URL |
| `crowdsec_appsec` | http, server, location | `off` | Enable AppSec inspection |
| `crowdsec_appsec_api_key` | http, server | - | Defaults to `crowdsec_api_key` |
| `crowdsec_appsec_timeout` | http, server, location | `1000` | AppSec timeout (ms) |
| `crowdsec_appsec_max_body_size` | http, server, location | `10m` | Max body forwarded to AppSec |
| `crowdsec_appsec_failure_action` | http, server, location | `passthrough` | Action when AppSec is unreachable |
| `crowdsec_appsec_drop_unreadable_body` | http, server, location | `off` | Reject bodies that cannot be buffered |
| `crowdsec_bot_challenge` | http, server, location | `off` | CrowdSec 1.8 bot challenge (experimental) |
| `crowdsec_metrics` | http, server, location | `off` | Expose Prometheus metrics at this location |

## Full example

```nginx
load_module /etc/nginx/modules/libngx_http_crowdsec_module.so;

events {
    worker_connections 1024;
}

http {
    crowdsec_url http://127.0.0.1:8080;
    crowdsec_api_key your-bouncer-api-key;
    crowdsec_shm_size 16m;

    # Required when crowdsec on (examples in templates/)
    crowdsec_ban_template /etc/nginx/templates/default.html;

    # Optional captcha (generate signing key: openssl rand -hex 32)
    # crowdsec_captcha_provider turnstile;
    # crowdsec_captcha_site_key ...;
    # crowdsec_captcha_secret_key ...;
    # crowdsec_captcha_signing_key ...;

    # Optional: behind CDN / reverse proxy — only if you do NOT already use
    # nginx real_ip (see "Client IP" section below).
    # crowdsec_trusted_proxies 10.0.0.0/8;
    # crowdsec_real_ip_header CF-Connecting-IP;

    # Optional AppSec
    # crowdsec_appsec_url http://127.0.0.1:7422/;
    # crowdsec_appsec on;

    server {
        listen 80;
        crowdsec on;

        location / {
            proxy_pass http://backend;
        }

        location /health {
            crowdsec off;
            return 200 "OK";
        }
    }
}
```

## AppSec and bot challenge

AppSec and bot challenge are **off by default**. Enable explicitly:

```nginx
crowdsec_appsec_url http://127.0.0.1:7422/;
crowdsec_appsec on;
crowdsec_appsec_timeout 1000;
crowdsec_appsec_max_body_size 10m;
crowdsec_appsec_failure_action passthrough;
crowdsec_bot_challenge on;  # experimental — CrowdSec 1.8
```

POST/PUT/PATCH/DELETE bodies are inspected in the **PRECONTENT** phase; GET/HEAD use the access phase. Internal `/crowdsec-internal/challenge/*` paths must stay on the bouncer, not the origin.

## Client IP behind a reverse proxy

The module resolves the client IP from the request **connection address** (the same underlying value `$remote_addr` uses after nginx has processed the request). Ban lookups, bypass rules, captcha IP binding, and AppSec all use this address.

### If you already use nginx `real_ip`

If `set_real_ip_from`, `real_ip_header`, and (when needed) `real_ip_recursive` are configured correctly, **you do not need** `crowdsec_trusted_proxies` or `crowdsec_real_ip_header`. The realip module runs in `POST_READ` (before CrowdSec's access handler) and rewrites the connection address to the end client; CrowdSec then sees that address automatically.

Example (Cloudflare) — no CrowdSec IP directives required:

```nginx
set_real_ip_from 173.245.48.0/20;
# ... other Cloudflare ranges ...
real_ip_header CF-Connecting-IP;
```

Verify with `curl` through the proxy: `$remote_addr` in access logs should match the client you expect to ban.

### If you do not use nginx `real_ip`

Use the module's built-in resolver instead. It mirrors `real_ip_recursive on`: when the TCP peer matches `crowdsec_trusted_proxies`, the client IP is taken from `crowdsec_real_ip_header` (default `X-Forwarded-For`) with right-to-left trusted stripping.

```nginx
crowdsec_trusted_proxies 10.0.0.0/8 172.16.0.0/12;
crowdsec_real_ip_header X-Forwarded-For;
```

For Cloudflare without the realip module:

```nginx
crowdsec_trusted_proxies 173.245.48.0/20;  # repeat for all CF ranges you trust
crowdsec_real_ip_header CF-Connecting-IP;
```

### Pick one approach

Do not configure both nginx `real_ip` and `crowdsec_trusted_proxies` for the same hop — it is redundant. Prefer whichever you already maintain site-wide; the module only needs the connection address to reflect the real client by the time its handlers run.

## Ban templates

Template variables: `{{client_ip}}`, `{{request_method}}`, `{{request_uri}}`, `{{scenario}}`, `{{origin}}`, `{{host}}`.

Built-in examples live in [`templates/`](../templates/). See [`templates/README.md`](../templates/README.md).

## CrowdSec setup

```bash
cscli bouncers add nginx-bouncer   # copy API key into nginx.conf
cscli decisions add --ip 1.2.3.4 --type ban --duration 1h --reason "test"
```

## Architecture

```
NGINX master
  └── shared memory (decision cache, metrics)
        ▲
  workers ──► one elected poller streams LAPI /v1/decisions/stream
        └── access / precontent handlers check each request
```

After a module upgrade that changes the SHM layout, a full **stop/start** (not reload) may be required. See troubleshooting in the main README.

## Troubleshooting

**Module not loading** — check `error_log`; confirm `nginx -V` matches the release you built against.

**LAPI connectivity** — `curl -H "X-Api-Key: KEY" http://127.0.0.1:8080/v1/decisions/stream?startup=true` and `cscli bouncers list`.

**Debug** — `error_log ... debug;` in `nginx.conf`.
