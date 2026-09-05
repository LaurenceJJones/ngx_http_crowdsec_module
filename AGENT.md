# Agent Instructions

This document provides guidance for AI assistants working on this codebase.

## Project Overview

**ngx_http_crowdsec_module** is a high-performance NGINX dynamic module written in Rust that integrates CrowdSec security into NGINX. It enables real-time IP-based threat enforcement through the CrowdSec Local API (LAPI).

**Version**: `0.3.2` (see `Cargo.toml` and [CHANGELOG.md](CHANGELOG.md)).

### Current Status

- **Core functionality**: Working (IP bans, decision streaming, shared memory cache with layout versioning, reload-safe poller)
- **Captcha flow**: Working (verification, JWT sessions, cookie handling, redirects)
- **AppSec / bot challenge**: Working but experimental (`crowdsec_appsec`, `crowdsec_bot_challenge`; CrowdSec 1.8 protocol)
- **Operational extras**: LAPI usage metrics, trusted-proxy client IP (`realip.rs`), IP bypass lists, ban redirects, Prometheus metrics (`metrics.rs`), nginx-native logging (`log.rs`), configurable poll/LAPI timeouts
- **Goal**: Feature parity with [lua-cs-bouncer](https://github.com/crowdsecurity/lua-cs-bouncer)

### Supported Remediations

- **Ban**: 403 with customizable template, or HTTP redirect via `crowdsec_ban_action redirect` (template variables include `{{scenario}}`, `{{origin}}`, `{{host}}`, plus `client_ip` / request fields)
- **Captcha**: Challenges user with hCaptcha, reCAPTCHA, or Cloudflare Turnstile
- **AppSec**: Request inspection against CrowdSec AppSec component; may allow, ban, or emit bot challenge responses

## NGINX Rust (`ngx`) SDK — read before coding

This module is built on the **[ngx-rust](https://github.com/nginx/ngx-rust)** crate. **Always confirm the pinned version and its public API before writing or refactoring NGINX integration code.** Do not assume APIs from other versions, from C NGINX examples, or from blog posts.

### Version pin (source of truth)

| Item | Where to look |
|------|----------------|
| **`ngx` crate version** | `Cargo.toml` → `[dependencies] ngx = "…"` (currently **`0.5.1`**) |
| **Rust toolchain** | `Cargo.toml` → `rust-version` (currently **`1.85`**) |
| **NGINX for local/Docker builds** | `docker/Dockerfile` `NGINX_VERSION` arg |
| **Locked transitive deps** | `Cargo.lock` (includes `nginx-sys`) |

Before calling a new `ngx` or `nginx_sys` symbol, verify it exists for **our exact pin**:

1. **[docs.rs for our version](https://docs.rs/ngx/0.5.1/ngx/)** — `Request`, `HttpModule`, `Pool`, `Status`, macros (`http_request_handler!`, `ngx_log_error!`, `ngx_conf_log_error!`), etc.
2. **Vendor / registry source** — after a Docker or `cargo build` with NGINX env, read `~/.cargo/registry/src/.../ngx-0.5.1/` (or the path from the build log) for traits and methods not obvious in docs.
3. **[nginx-acme](https://github.com/nginx/nginx-acme)** — reference module from the ngx maintainers; same `ngx = "0.5.1"`. Prefer patterns proven there (logging, `NgxConfExt`, SHM zone lifecycle, `Request::output_filter`) over inventing raw FFI.

### APIs and conventions in *this* repo

- **Module registration**: `HttpModule`, `HttpModuleMainConf`, `HttpModuleLocationConf`, `ngx_modules!` (behind `export-modules` feature).
- **Handlers**: `http_request_handler!`; return `Status` / map from `HandlerResult`.
- **Config**: C directive handlers in `config.rs`; prefer `conf::NgxConfExt` and `ngx_conf_log_error!` for parse-time errors.
- **Logging**: `crowdsec_*!` macros in `log.rs` for worker/cycle context; `ngx_log_debug_http!` for per-request debug. **Do not use `eprintln!`** for operational logs.
- **Responses**: `response.rs` helpers + `Request::output_filter`; finalize still uses `ngx_http_finalize_request` (no `Request::finalize` in 0.5.1).
- **SHM**: Custom slab layout in `shm.rs` + `DecisionsSharedZone` state machine; not a full `SlabPool` rewrite unless deliberately scoped.
- **Background LAPI poll**: `std::thread` + `ureq` in `stream.rs` — **`ngx` `async` feature is not enabled**; do not introduce `ngx::async_` without an explicit dependency and design change.

### When upgrading `ngx`

1. Bump `ngx` (and usually `nginx-sys`) in `Cargo.toml`, run `cargo update`, rebuild via **Docker** (not bare `cargo build`).
2. Read the [ngx-rust release notes](https://github.com/nginx/ngx-rust/releases) for breaking changes.
3. Re-check every `ngx::` / raw FFI callsite; run CI and integration tests.
4. Update this section’s version numbers and any API notes that changed.

## Building and Testing

### Primary Method: Podman/Docker Compose

**Do NOT use `cargo build` directly** - it won't work without NGINX source configured.

**Toolchain (ngx 0.5)**: Per [ngx-rust v0.5.0](https://github.com/nginx/ngx-rust/releases/tag/v0.5.0), use **Rust ≥ 1.81.0** and **NGINX ≥ 1.22** (older NGINX may compile but is not regularly tested upstream). Match NGINX sources to what you run in production.

```bash
# Build and run the full test environment
podman-compose up --build

# Rebuild after code changes
podman-compose build && podman-compose up -d

# View logs
podman-compose logs -f nginx

# Stop environment
podman-compose down
```

The compose setup includes:

- **CrowdSec LAPI** on port 8080 (internal) - manages security decisions
- **NGINX with module** on port 9090 (external) - the test server

### Testing Endpoints

```bash
# Normal request (should work if IP not banned)
curl http://localhost:9090/

# Test captcha flow (add captcha decision first)
curl http://localhost:9090/captcha-test
```

### Adding Test Decisions

```bash
# Add a ban decision
podman exec crowdsec cscli decisions add --ip <YOUR_IP> --type ban --duration 1h

# Add a captcha decision (for testing captcha flow)
podman exec crowdsec cscli decisions add --ip <YOUR_IP> --type captcha --duration 1h

# List decisions
podman exec crowdsec cscli decisions list

# Remove a decision
podman exec crowdsec cscli decisions delete --ip <YOUR_IP>
```

To find your IP as seen by the container:

```bash
# Check nginx logs for the client IP
podman-compose logs nginx | grep "client IP"
```

### Environment Variables

Copy `.env.example` to `.env` and configure captcha keys for testing:

```bash
cp .env.example .env
# Edit .env with your captcha provider keys
```

## Project Structure

```
src/
├── lib.rs              # Module entry point, NGINX integration, poller lifecycle
├── log.rs              # crowdsec_*! logging macros (cycle/conf/request log targets)
├── conf/               # NgxConfExt and config parse helpers
├── lapi.rs             # Shared LAPI User-Agent and ureq agent
├── response.rs         # send_header → output_filter → finalize helpers
├── usage_metrics.rs    # LAPI POST /v1/usage-metrics
├── appsec.rs           # CrowdSec AppSec + bot challenge HTTP client
├── config.rs           # Configuration structures and directive handlers
├── handler.rs          # Main access phase handler (ban/captcha/appsec routing)
├── metrics.rs          # Prometheus text metrics location
├── realip.rs           # Trusted-proxy client IP (X-Forwarded-For, etc.)
├── template.rs         # Ban page template rendering (incl. {{scenario}})
├── shm.rs              # Shared memory (decision cache, metrics zone, DecisionsSharedZone)
├── stream.rs           # CrowdSec LAPI streaming client (background thread)
├── types.rs            # Core types (Decision, DecisionType, etc.)
└── captcha/
    ├── mod.rs          # Captcha module exports
    ├── config.rs       # Captcha configuration (provider, keys, cookie settings)
    ├── handler.rs      # Captcha page serving and session validation
    ├── body.rs         # POST body reading and verification callback
    ├── verifier.rs     # Provider API verification (hCaptcha/reCAPTCHA/Turnstile)
    ├── jwt.rs          # HMAC-SHA256 session token creation/validation
    └── cookie.rs       # Cookie utilities, HTTPS detection

docker/
├── Dockerfile          # Multi-stage build (NGINX + Rust module)
├── nginx.conf          # Test NGINX configuration template
└── entrypoint.sh       # Container startup script

templates/              # Customizable ban/captcha page templates
```

## Key Technical Details

### NGINX Module Architecture

- **Access phase handler**: SHM ban/captcha + AppSec for bodyless requests
- **PRECONTENT phase handler**: AppSec for POST/PUT/PATCH/DELETE bodies
- **Shared memory**: All workers share decision cache via `shm.rs`
- **Poller thread**: Background thread polls CrowdSec LAPI for decision updates
- **Callback-based body reading**: Captcha POST handling uses `ngx_http_read_client_request_body`

### Captcha Flow

1. Request arrives, IP has captcha decision in cache
2. If valid session cookie exists (JWT), allow request
3. Otherwise, serve captcha challenge page (GET) or verify submission (POST)
4. On successful verification, create JWT token, set cookie, redirect to original URI
5. Subsequent requests pass through with valid cookie

**Important**: The body callback context requires `(*r).set_keepalive(0)` to prevent connection hanging after redirect.

### Cookie Secure Flag

The module auto-detects HTTPS via:

1. Direct TLS connection (`connection->ssl`)
2. `X-Forwarded-Proto: https` header
3. `X-Forwarded-Ssl: on` header

Can be overridden with `crowdsec_captcha_cookie_secure auto|on|off`.

### Static Asset Handling

For `.ico` requests (favicon), the module returns minimal responses instead of full HTML pages:

- Ban + `.ico` → 403 Forbidden (no body)
- Captcha + `.ico` → 200 OK (minimal body)

### Debug and operational logging

- **Per-request debug**: `ngx_log_debug_http!(request, "…")` or `ngx_log_debug!(log, "…")` — only when `error_log … debug;`.
- **Worker / poller / SHM**: `crowdsec_notice!`, `crowdsec_warn!`, etc. with `log::cycle_log()` — written to nginx `error_log` at the matching level.
- **Config parse**: `ngx_conf_log_error!` or `NgxConfExt::error()`.

See [docs/configuration.md — Logging and debugging LAPI polling](docs/configuration.md#logging-and-debugging-lapi-polling) for what the stream poller logs and when steady-state polls are silent.

## Configuration Directives

```nginx
# Main context
crowdsec_url "http://crowdsec:8080";
crowdsec_api_key "your-api-key";
crowdsec_shm_size 512k;
# crowdsec_poll_interval 10;   # seconds between successful LAPI stream polls (default 10)
# crowdsec_lapi_timeout 30;    # HTTP timeout per LAPI request in seconds (default 30)

# Optional: real client IP when NGINX sees only your edge proxy/LB (CIDRs of trusted TCP peers)
# crowdsec_trusted_proxies 10.0.0.0/8;
# crowdsec_real_ip_header X-Forwarded-For;
# Optional: resolved client IPs in these networks skip CrowdSec (e.g. kube-probe, VPC health checks)
# crowdsec_bypass 127.0.0.1 ::1 10.42.0.0/16;

# Optional AppSec / bot challenge (experimental; CrowdSec 1.8)
# crowdsec_appsec_url http://127.0.0.1:7422/;
# crowdsec_appsec on;
# crowdsec_bot_challenge on;

# Captcha configuration (http context)
crowdsec_captcha_provider hcaptcha|turnstile|recaptcha;
crowdsec_captcha_site_key "your-site-key";
crowdsec_captcha_secret_key "your-secret-key";
crowdsec_captcha_signing_key "32-byte-hex-key";
crowdsec_captcha_cookie_name "crowdsec_captcha";
crowdsec_captcha_expiry 3600;
crowdsec_captcha_cookie_secure auto|on|off;

# Dedicated metrics (no enforcement in this location)
# Text exposition includes crowdsec_lapi_stream_last_success_unixtime (gauge, Unix seconds).
# location /crowdsec-metrics {
#     crowdsec off;
#     crowdsec_metrics on;
# }

# Location context
crowdsec on|off;
crowdsec_metrics on|off;
crowdsec_ban_template "/path/to/template.html";
crowdsec_ban_action block|redirect;
crowdsec_ban_redirect_url "https://example.com/blocked";
crowdsec_ban_redirect_code 301|302|303|307|308;
crowdsec_captcha_template "/path/to/template.html";
```

## Known Limitations

- **Decision SHM upgrades**: The `crowdsec_decisions` zone is tagged with a layout version; `nginx -s reload` reuses it only when the running module matches. After upgrading the `.so` when the layout changes, use a **full restart**, not only reload (see README troubleshooting).
- **302 redirect body**: After successful captcha, the 302 response includes a minimal body ("Redirecting..."). Browsers handle this correctly but it's not ideal. Deferred for future improvement.
- **Blocking captcha verification**: The HTTP call to verify captcha with the provider blocks the NGINX worker briefly. Consider async in future.

## Useful Commands

```bash
# Watch nginx logs during development
podman-compose logs -f nginx

# Shell into nginx container for debugging
podman exec -it nginx-crowdsec /bin/bash

# Shell into crowdsec container
podman exec -it crowdsec /bin/bash

# Quick rebuild after changes
podman-compose build && podman-compose up -d

# Full clean rebuild
podman-compose down -v && podman-compose build --no-cache && podman-compose up
```

## Code Style Notes

- Verify **`ngx` 0.5.1 APIs** on docs.rs (or registry source) before adding new NGINX integration code — see [NGINX Rust SDK](#nginx-rust-ngx-sdk--read-before-coding).
- Use `crowdsec_*!` / `ngx_log_debug_http!` for logging; never `eprintln!` for module output.
- NGINX FFI requires careful memory management (allocate from request pool).
- All NGINX types require `unsafe` blocks where raw pointers are used.
- The `ngx` crate provides safe wrappers where possible — prefer them over new raw FFI.
- Prefer editing existing files over creating new ones.
- Match patterns in [nginx-acme](https://github.com/nginx/nginx-acme) when unsure about idiomatic ngx-rust usage.

