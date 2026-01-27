# Docker Development Environment

This directory contains the Docker setup for testing the CrowdSec NGINX module.

## Quick Start

From the project root directory:

```bash
# Build and start the containers
docker-compose up --build -d

# View logs
docker-compose logs -f

# Run the test suite
./docker/test.sh

# Stop the containers
docker-compose down
```

## Services

### CrowdSec LAPI

- **Container name**: `crowdsec`
- **Port**: `8080` (exposed to host)
- **Bouncer key**: `test-bouncer-key-12345` (pre-configured)

You can interact with CrowdSec using `cscli`:

```bash
# List decisions
docker exec crowdsec cscli decisions list

# Add a test ban
docker exec crowdsec cscli decisions add --ip 1.2.3.4 --type ban --duration 1h --reason "test"

# Remove a ban
docker exec crowdsec cscli decisions delete --ip 1.2.3.4

# List bouncers
docker exec crowdsec cscli bouncers list
```

### NGINX with CrowdSec Module

- **Container name**: `nginx-crowdsec`
- **Port**: `9090` (mapped to internal `8080`)
- **Module**: `/etc/nginx/modules/libngx_http_crowdsec_module.so`

Test endpoints:

```bash
# Normal endpoint (CrowdSec enabled)
curl http://localhost:9090/

# Health endpoint (CrowdSec disabled)
curl http://localhost:9090/health

# Status endpoint (CrowdSec disabled)
curl http://localhost:9090/status
```

## Configuration

### NGINX Configuration

The NGINX configuration is in `docker/nginx.conf`. Key directives:

```nginx
# At http level - configure LAPI connection
crowdsec_url http://crowdsec:8080;
crowdsec_api_key ${CROWDSEC_BOUNCER_KEY};

# At location level - enable/disable
crowdsec on;   # Enable checking
crowdsec off;  # Disable checking
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CROWDSEC_BOUNCER_KEY` | API key for LAPI authentication | `test-bouncer-key-12345` |

## Testing IP Blocking

Due to Docker networking, testing actual IP blocking requires some workarounds:

### Option 1: Add decision for Docker network IP

```bash
# Find your container's IP
docker inspect nginx-crowdsec | grep IPAddress

# Ban that IP (will block yourself!)
docker exec crowdsec cscli decisions add --ip <container_ip> --type ban --duration 5m
```

### Option 2: Use a separate test container

```bash
# Run a test container
docker run --rm -it --network ngx_http_crowdsec_module_crowdsec_net alpine sh

# Inside the container
apk add curl
curl http://nginx-crowdsec:8080/
```

### Option 3: Check LAPI stream directly

```bash
# Verify the module is receiving decisions
docker exec crowdsec curl -s -H "X-Api-Key: test-bouncer-key-12345" \
  "http://localhost:8080/v1/decisions/stream?startup=true"
```

## Troubleshooting

### Module not loading

Check NGINX error logs:

```bash
docker logs nginx-crowdsec 2>&1 | grep -i error
```

### LAPI connection issues

Verify CrowdSec is running:

```bash
docker exec crowdsec cscli lapi status
```

Check bouncer registration:

```bash
docker exec crowdsec cscli bouncers list
```

### Rebuild after code changes

```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## Development Workflow

1. Make code changes in `src/`
2. Rebuild: `docker-compose build`
3. Restart: `docker-compose up -d`
4. Test: `./docker/test.sh`
5. Check logs: `docker-compose logs -f nginx`
