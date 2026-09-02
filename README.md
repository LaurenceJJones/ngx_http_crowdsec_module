# ngx_http_crowdsec_module

A high-performance NGINX dynamic module written in Rust that integrates [CrowdSec](https://www.crowdsec.net/) security into your NGINX web server. This module enables real-time IP-based threat enforcement through seamless integration with the CrowdSec Local API (LAPI).

> **Status**: **v0.2.0-rc2** release candidate — IP bans, captcha remediations, AppSec/bot challenge (including POST body inspection), trusted reverse-proxy client IP, IP bypass lists, ban redirects, and Prometheus metrics. See [CHANGELOG.md](CHANGELOG.md) and [Roadmap](#roadmap).

## Features

- **Real-time decision streaming** - Continuously polls CrowdSec LAPI for ban decisions
- **Cross-worker shared memory** - All NGINX workers share a single decision cache
- **Fast lookups** - O(1) hash table for individual IPs with CIDR range support
- **Multiple decision types** - Supports Ban and Captcha decisions
- **Captcha verification** - Supports hCaptcha, reCAPTCHA, and Cloudflare Turnstile with signed session cookies
- **Trusted reverse-proxy IP** — Optional `crowdsec_trusted_proxies` + forwarded header (default `X-Forwarded-For`) with safe recursive stripping
- **Bypass by client IP** — Optional `crowdsec_bypass` CIDR list so probes and internal traffic skip enforcement without per-location `crowdsec off`
- **Automatic expiration** - TTL-based cleanup of expired decisions
- **LRU eviction** - Clock algorithm for memory management when cache fills
- **Customizable responses** - Template-based ban pages (HTML, JSON, plain text)
- **Prometheus metrics** — Optional `crowdsec_metrics on` location exposing counters, cache size, and last successful LAPI poll time (`crowdsec_metrics` SHM zone)
- **Fail-open design** - Allows traffic if CrowdSec LAPI is unreachable

### Build Requirements

- Rust 1.85+ with Cargo
- NGINX source code (matching your target NGINX version)
- Build tools: `gcc`, `make`, `clang`, `llvm`
- Libraries: `libssl-dev`, `libpcre2-dev`, `zlib1g-dev`

### Runtime Requirements

- NGINX 1.30+ (compiled with dynamic module support)
- Two small **shared-memory zones** are registered: `crowdsec_decisions` (size from `crowdsec_shm_size`) and `crowdsec_metrics` (8KB, for counters)
- CrowdSec LAPI (v1.x)
- Registered bouncer API key

## Quick Start with Docker

> [!IMPORTANT]
> NGINX dynamic modules are ABI-specific. A downloaded `.so` must match the
> NGINX version, platform, architecture, and configure arguments listed in its
> release compatibility file. Use the published container image when those do
> not match your host.

The easiest way to try the module is using Docker:

```bash
# Clone the repository
git clone https://github.com/LaurenceJJones/ngx_http_crowdsec_module.git
cd ngx_http_crowdsec_module

# Build and start the containers
docker compose up --build -d

# Test the endpoints
curl http://localhost:9090/        # Protected endpoint
curl http://localhost:9090/health  # Health check (bypasses CrowdSec)

# Add a test ban
docker exec crowdsec cscli decisions add --ip 1.2.3.4 --type ban --duration 1h --reason "test"

# View decisions
docker exec crowdsec cscli decisions list

# Stop the containers
docker compose down
```

See [docker/README.md](docker/README.md) for detailed Docker documentation.

## Building from Source

### Option 1: Docker Build (Recommended)

```bash
docker build -f docker/Dockerfile -t nginx-crowdsec .
```

### Option 2: Manual Build

1. **Download and configure NGINX source**:

```bash
# Download NGINX source (use version matching your production NGINX)
wget https://nginx.org/download/nginx-1.30.3.tar.gz
tar -xzf nginx-1.30.3.tar.gz
cd nginx-1.30.3

# Configure NGINX
./configure \
    --with-compat \
    --with-http_ssl_module \
    --add-dynamic-module=/path/to/ngx_http_crowdsec_module
```

2. **Build the module**:

```bash
# Set environment variables for nginx-sys crate
export NGINX_SOURCE_DIR=/path/to/nginx-1.30.3
export NGINX_BUILD_DIR=/path/to/nginx-1.30.3/objs

# Build with Cargo
cd /path/to/ngx_http_crowdsec_module
cargo build --release
```

3. **Install the module**:

```bash
# Copy the compiled module
cp target/release/libngx_http_crowdsec_module.so /etc/nginx/modules/
```

## Configuration

### AppSec and CrowdSec 1.8 bot detection

```nginx
crowdsec_appsec_url http://127.0.0.1:7422/;
crowdsec_appsec on;
crowdsec_appsec_timeout 1000;
crowdsec_appsec_max_body_size 10m;
crowdsec_appsec_failure_action passthrough;
crowdsec_bot_challenge on;
```

`crowdsec_appsec_api_key` defaults to `crowdsec_api_key`. AppSec and bot
challenges are disabled unless explicitly enabled. Bot detection follows the
CrowdSec 1.8 challenge protocol and should be treated as experimental until
CrowdSec marks that feature stable. Invalid challenge envelopes fail closed.

The internal `/crowdsec-internal/challenge/*` paths are handled by AppSec and
must not be routed around this module to the protected origin.

### Loading the Module

Add to the top of your `nginx.conf`:

```nginx
load_module /etc/nginx/modules/libngx_http_crowdsec_module.so;
```

### Directives

All directives can be set at the `http`, `server`, or `location` level unless noted.

| Directive | Context | Default | Description |
|-----------|---------|---------|-------------|
| `crowdsec` | http, server, location | `off` | Enable/disable CrowdSec checking (`on`/`off`) |
| `crowdsec_url` | http | - | CrowdSec LAPI URL (required) |
| `crowdsec_api_key` | http | - | Bouncer API key (required) |
| `crowdsec_trusted_proxies` | http, server | - | One or more CIDRs (or `off`). When the TCP client matches, the client IP is taken from `X-Forwarded-For` (or `crowdsec_real_ip_header`) using recursive trusted stripping (right-to-left). Repeat the directive to append more CIDRs. |
| `crowdsec_real_ip_header` | http, server | `X-Forwarded-For` | Header to read when trusted proxies are configured (single token, case-insensitive match). |
| `crowdsec_bypass` | http, server | - | One or more CIDRs (or `off`). If the **resolved** client IP (after trusted-proxy logic) matches, the request skips CrowdSec (no cache lookup). Repeat to append. Exposed as `crowdsec_http_bypass_total`. |
| `crowdsec_shm_size` | http | `1m` | Shared memory zone size for decision cache |
| `crowdsec_max_retries` | http | `3` | Max connection retries on startup |
| `crowdsec_retry_interval` | http | `5` | Seconds between retry attempts |
| `crowdsec_poll_interval` | http, server | `10` | Seconds to wait after each successful stream response before polling LAPI again |
| `crowdsec_lapi_timeout` | http, server | `30` | Per-request HTTP timeout (seconds) when calling LAPI |
| `crowdsec_ban_template` | http, server, location | built-in | Path to custom ban response template |
| `crowdsec_captcha_provider` | http, server, location | `turnstile` | `hcaptcha`, `recaptcha`, or `turnstile` |
| `crowdsec_captcha_site_key` | http, server, location | - | Captcha provider site key |
| `crowdsec_captcha_secret_key` | http, server, location | - | Captcha provider secret key |
| `crowdsec_captcha_signing_key` | http, server, location | - | 64-character hex key for signed sessions |
| `crowdsec_captcha_cookie_name` | http, server, location | `crowdsec_captcha` | Session cookie name |
| `crowdsec_captcha_expiry` | http, server, location | `3600` | Session lifetime in seconds |
| `crowdsec_captcha_fail_open` | http, server, location | `on` | Allow requests when verification fails operationally |
| `crowdsec_captcha_bind_ip` | http, server, location | `on` | Bind captcha sessions to client IP |
| `crowdsec_captcha_cookie_secure` | http, server, location | `auto` | Secure cookie mode: `auto`, `on`, or `off` |
| `crowdsec_captcha_template` | http, server, location | built-in | Path to custom captcha template |
| `crowdsec_ban_action` | http, server, location | `block` | `block` → 403 (with template if set); `redirect` → redirect to `crowdsec_ban_redirect_url` |
| `crowdsec_ban_redirect_url` | http, server, location | - | Absolute `http://` or `https://` URL (max 2048 chars). Required when `ban_action` is `redirect`. |
| `crowdsec_ban_redirect_code` | http, server, location | `302` | Status for ban redirect: `301`, `302`, `303`, `307`, or `308`. |
| `crowdsec_metrics` | http, server, location | `off` | `on` → this location serves Prometheus text metrics (use a dedicated URI; protect with `allow` / `internal` / auth). |

### Example Configuration

```nginx
load_module /etc/nginx/modules/libngx_http_crowdsec_module.so;

events {
    worker_connections 1024;
}

http {
    # CrowdSec LAPI connection settings (http level only)
    crowdsec_url http://127.0.0.1:8080;
    crowdsec_api_key your-bouncer-api-key;
    crowdsec_shm_size 1m;

    # Generate the signing key with: openssl rand -hex 32
    crowdsec_captcha_provider hcaptcha;
    crowdsec_captcha_site_key your-site-key;
    crowdsec_captcha_secret_key your-secret-key;
    crowdsec_captcha_signing_key your-64-character-hex-key;

    # Optional: behind L7 reverse proxies / CDNs — list CIDRs of peers that terminate TCP for you.
    # crowdsec_trusted_proxies 10.0.0.0/8 172.16.0.0/12;
    # crowdsec_real_ip_header X-Forwarded-For;  # default; Cloudflare often uses CF-Connecting-IP instead

    # Default ban template for all servers
    crowdsec_ban_template /etc/nginx/templates/default.html;
    # Optional: send banned users to an info page instead of 403 + template
    # crowdsec_ban_action redirect;
    # crowdsec_ban_redirect_url "https://www.example.com/blocked";
    # crowdsec_ban_redirect_code 307;

    # Internal Prometheus metrics (no CrowdSec enforcement on this URI)
    # location /crowdsec-metrics {
    #     internal;
    #     crowdsec off;
    #     crowdsec_metrics on;
    # }

    server {
        listen 80;
        server_name example.com;

        # Enable CrowdSec for all locations by default
        crowdsec on;

        location / {
            proxy_pass http://backend;
        }

        # Disable for health checks
        location /health {
            crowdsec off;
            return 200 "OK";
        }

        # Custom JSON response for API endpoints
        location /api {
            crowdsec_ban_template /etc/nginx/templates/api.json;
            proxy_pass http://api-backend;
        }
    }
}
```

## Ban Templates

The module supports customizable ban response templates with variable substitution.

### Available Variables

| Variable | Description |
|----------|-------------|
| `{{client_ip}}` | The blocked client's IP address |
| `{{request_method}}` | HTTP method (GET, POST, etc.) |
| `{{request_uri}}` | Requested URI path |
| `{{reason}}` | CrowdSec ban `reason` from the LAPI stream when present (truncated to the same max length as scenarios, 127 bytes UTF-8) |
| `{{scenario}}` | CrowdSec scenario name when stored on the decision (from LAPI stream) |
| `{{origin}}` | Decision source: `crowdsec`, `cscli`, `capi`, `console`, `lists`, or `unknown` |
| `{{host}}` | Value of the request `Host` header when present |

### Included Templates

- `templates/default.html` - Modern styled HTML page
- `templates/simple.html` - Basic HTML template
- `templates/minimal.html` - Minimal HTML response
- `templates/api.json` - JSON response for APIs

See [templates/README.md](templates/README.md) for more details on creating custom templates.

## CrowdSec Setup

### Register a Bouncer

```bash
# On your CrowdSec machine
cscli bouncers add nginx-bouncer

# Copy the generated API key to your NGINX configuration
```

### Managing Decisions

```bash
# List all decisions
cscli decisions list

# Add a manual ban
cscli decisions add --ip 1.2.3.4 --type ban --duration 1h --reason "manual ban"

# Remove a ban
cscli decisions delete --ip 1.2.3.4

# Ban a CIDR range
cscli decisions add --range 10.0.0.0/24 --type ban --duration 24h
```

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │            NGINX Master             │
                    │  ┌───────────────────────────────┐  │
                    │  │     Shared Memory Zone        │  │
                    │  │  ┌─────────────────────────┐  │  │
                    │  │  │   Decision Hash Table   │  │  │
                    │  │  │   (IP/CIDR → Decision)  │  │  │
                    │  │  └─────────────────────────┘  │  │
                    │  └───────────────────────────────┘  │
                    └─────────────────────────────────────┘
                                      ▲
        ┌─────────────────────────────┼─────────────────────────────┐
        │                             │                             │
┌───────┴───────┐           ┌─────────┴─────────┐         ┌─────────┴───────┐
│ Worker 1      │           │ Worker 2 (Poller) │         │ Worker N        │
│               │           │ ┌───────────────┐ │         │                 │
│ Access Phase  │           │ │ Poll Thread   │ │         │ Access Phase    │
│ Handler       │           │ │               │ │         │ Handler         │
│               │           │ │ LAPI Stream   │ │         │                 │
└───────────────┘           │ └───────┬───────┘ │         └─────────────────┘
                            │         │         │
                            └─────────┼─────────┘
                                      │
                                      ▼
                            ┌─────────────────────┐
                            │  CrowdSec LAPI      │
                            │  /v1/decisions/     │
                            │       stream        │
                            └─────────────────────┘
```

### Key Components

- **Shared Memory Zone**: Cross-worker cache storing IP/CIDR decisions
- **Poller Election**: First worker to initialize becomes the dedicated poller
- **Poll Thread**: Background thread streaming decisions from LAPI
- **Access Phase Handler**: Checks each request against the decision cache
- **Prometheus metrics**: Optional `crowdsec_metrics` SHM + `crowdsec_metrics on` location (includes `crowdsec_lapi_stream_last_success_unixtime` for alerting when polls stall)

## Roadmap

**v0.2.0-rc2** completes the parity goals tracked against [lua-cs-bouncer](https://github.com/crowdsecurity/lua-cs-bouncer):

- [x] X-Forwarded-For style client IP when behind trusted proxies (`crowdsec_trusted_proxies`, `crowdsec_real_ip_header`)
- [x] Captcha challenge flow (hCaptcha, reCAPTCHA, and Turnstile)
- [x] Prometheus metrics endpoint (`crowdsec_metrics on` + `crowdsec_metrics` shared zone)
- [x] AppSec/WAF integration (request body inspection) and CrowdSec 1.8 bot challenge
- [x] Ban action customization (`crowdsec_ban_action block|redirect`, `crowdsec_ban_redirect_url`, `crowdsec_ban_redirect_code`)
- [x] IP/CIDR bypass without disabling the module per location (`crowdsec_bypass`)

Future work (post-0.2.0): async captcha provider verification, richer AppSec/bot-challenge stability as CrowdSec 1.8 matures, and additional lua-cs-bouncer edge cases as they are identified.

## Troubleshooting

### Shared memory after module upgrade

The `crowdsec_decisions` zone embeds a **layout version** and **magic** value. On `nginx -s reload`, the module reuses the existing zone only if those match.

- If you upgrade to a build that changes the in-memory layout, reload may log an incompatibility message and **fail** until you perform a **full nginx stop/start** (or remove the old shared segment by restarting the host / changing the zone name in a fork).

### Module not loading

```bash
# Check NGINX error log
tail -f /var/log/nginx/error.log

# Verify module was built for correct NGINX version
nginx -V 2>&1 | grep version
```

### LAPI connection issues

```bash
# Test LAPI connectivity
curl -H "X-Api-Key: your-api-key" http://localhost:8080/v1/decisions/stream?startup=true

# Check bouncer registration
cscli bouncers list
```

### Debug logging

The module logs to NGINX's error log. Set `error_log` level to `debug` for verbose output:

```nginx
error_log /var/log/nginx/error.log debug;
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 CrowdSec
