# ngx_http_crowdsec_module

A high-performance NGINX dynamic module written in Rust that integrates [CrowdSec](https://www.crowdsec.net/) security into your NGINX web server. This module enables real-time IP-based threat enforcement through seamless integration with the CrowdSec Local API (LAPI).

> **Status**: Proof of Concept - This module implements core functionality for IP-based blocking. See [Roadmap](#roadmap) for planned features.

## Features

- **Real-time decision streaming** - Continuously polls CrowdSec LAPI for ban decisions
- **Cross-worker shared memory** - All NGINX workers share a single decision cache
- **Fast lookups** - O(1) hash table for individual IPs with CIDR range support
- **Multiple decision types** - Supports Ban, Captcha (framework ready), and extensible types
- **Automatic expiration** - TTL-based cleanup of expired decisions
- **LRU eviction** - Clock algorithm for memory management when cache fills
- **Customizable responses** - Template-based ban pages (HTML, JSON, plain text)
- **Fail-open design** - Allows traffic if CrowdSec LAPI is unreachable

## Requirements

### Build Requirements

- Rust 1.70+ with Cargo
- NGINX source code (matching your target NGINX version)
- Build tools: `gcc`, `make`, `clang`, `llvm`
- Libraries: `libssl-dev`, `libpcre2-dev`, `zlib1g-dev`

### Runtime Requirements

- NGINX 1.24+ (compiled with dynamic module support)
- CrowdSec LAPI (v1.x)
- Registered bouncer API key

## Quick Start with Docker

The easiest way to try the module is using Docker:

```bash
# Clone the repository
git clone https://github.com/crowdsecurity/ngx_http_crowdsec_module.git
cd ngx_http_crowdsec_module

# Build and start the containers
docker-compose up --build -d

# Test the endpoints
curl http://localhost:9090/        # Protected endpoint
curl http://localhost:9090/health  # Health check (bypasses CrowdSec)

# Add a test ban
docker exec crowdsec cscli decisions add --ip 1.2.3.4 --type ban --duration 1h --reason "test"

# View decisions
docker exec crowdsec cscli decisions list

# Stop the containers
docker-compose down
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
wget https://nginx.org/download/nginx-1.26.2.tar.gz
tar -xzf nginx-1.26.2.tar.gz
cd nginx-1.26.2

# Configure NGINX
./configure \
    --with-compat \
    --with-http_ssl_module \
    --add-dynamic-module=/path/to/ngx_http_crowdsec_module
```

2. **Build the module**:

```bash
# Set environment variables for nginx-sys crate
export NGINX_SOURCE_DIR=/path/to/nginx-1.26.2
export NGINX_BUILD_DIR=/path/to/nginx-1.26.2/objs

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
| `crowdsec_shm_size` | http | `1m` | Shared memory zone size for decision cache |
| `crowdsec_max_retries` | http | `3` | Max connection retries on startup |
| `crowdsec_retry_interval` | http | `5` | Seconds between retry attempts |
| `crowdsec_ban_template` | http, server, location | built-in | Path to custom ban response template |

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

    # Default ban template for all servers
    crowdsec_ban_template /etc/nginx/templates/default.html;

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
| `{{reason}}` | Ban reason from CrowdSec (if available) |

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

## Roadmap

Features planned for future releases (working towards feature parity with [lua-cs-bouncer](https://github.com/crowdsecurity/lua-cs-bouncer)):

- [ ] X-Forwarded-For header support (extracting real client IP behind proxies)
- [ ] Captcha challenge flow (redirect to captcha page, verify response)
- [ ] Prometheus metrics endpoint
- [ ] AppSec/WAF integration (request body inspection)
- [ ] Live recaptcha/turnstile integration
- [ ] Ban action customization (redirect vs block)

## Troubleshooting

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
