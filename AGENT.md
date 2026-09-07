# Agent Instructions

Guidance for AI assistants working on **ngx_http_crowdsec_module** — a Rust NGINX dynamic module for CrowdSec (LAPI bans/captcha, AppSec WAF).

**Version**: see `Cargo.toml` / [CHANGELOG.md](CHANGELOG.md).  
**User docs**: [README.md](README.md), [docs/configuration.md](docs/configuration.md), [docs/testing.md](docs/testing.md).  
**Reference module**: [nginx-acme](https://github.com/nginx/nginx-acme) (same `ngx` pin).

---

## Build and test

**Do not run bare `cargo build`** — requires `NGINX_SOURCE_DIR` / `NGINX_BUILD_DIR` (set in Docker).

| Task | Command |
|------|---------|
| CI-equivalent image | `docker build -f docker/Dockerfile -t nginx-crowdsec:test .` |
| CI BATS (integration + challenge) | `./scripts/test-bats-ci.sh` |
| Local hub AppSec suite (not CI) | `./scripts/hubtest-run.sh --all` — see [docs/testing.md](docs/testing.md) |
| Local compose stack | `podman-compose up --build` (nginx `:9090`, real CrowdSec LAPI) |
| AppSec POST + proxy test | `scripts/test-appsec-proxy-post.sh nginx-crowdsec:test` |
| Ubuntu/apt nginx `.so` | `scripts/build-ubuntu-module.sh` → `dist/*-ubuntu-noble.so` |
| Unit check | `docker build --target rust-builder -t nginx-crowdsec:builder -f docker/Dockerfile . && docker run --rm nginx-crowdsec:builder cargo check --tests --locked` |

Match **NGINX ABI** to production (Debian Docker image vs Ubuntu `nginx-dev` on VPS). After `.so` swap use **`systemctl restart nginx`**, not only reload, when testing phase-handler changes.

---

## ngx SDK (pin before coding)

| Item | Source |
|------|--------|
| `ngx` crate | `Cargo.toml` (currently **0.5.1**) |
| Rust MSRV | `Cargo.toml` `rust-version` |
| NGINX in Docker | `docker/Dockerfile` `NGINX_VERSION` |

Verify symbols on [docs.rs/ngx/0.5.1](https://docs.rs/ngx/0.5.1/ngx/) or registry source — do not assume C NGINX blog patterns.

**This repo’s patterns**

- Handlers: `http_request_handler!` → `HandlerResult` → `Status` (`src/handler.rs`, `src/lib.rs`).
- Config: C directive handlers in `config.rs`; `ngx_conf_log_error!` for parse errors.
- Logging: `crowdsec_*!` / `ngx_log_debug_http!` — never `eprintln!`.
- LAPI poll: blocking `std::thread` + `ureq` in `stream.rs` (no `ngx::async_` unless explicitly scoped).
- SHM: custom layout in `shm.rs`; full **restart** after layout-breaking upgrades, not reload-only.

---

## Module behaviour (accurate)

| Phase | Role |
|-------|------|
| **ACCESS** | IP ban/captcha routing; **AppSec** (headers + request body via `inspect_access`) |
| **PRECONTENT** | Captcha POST verification only; AppSec `inspect_precontent` is a no-op |

**AppSec + request bodies** (`src/appsec.rs`, `src/request_body.rs`):

- Body reads run in **ACCESS**, not PRECONTENT, so `proxy_pass` keeps the correct content handler.
- **Sync** body read: return `HandlerResult` from the phase handler (no `finalize_allow` in the handler).
- **Async** body callback on allow: **`finalize_allow`** restores `clcf->handler` into `r->content_handler` then `ngx_http_core_run_phases` — **never** `ngx_http_finalize_request(NGX_DECLINED)` alone (that clears `content_handler` and breaks `proxy_pass`).

Key files: `appsec.rs`, `handler.rs`, `request_body.rs`, `captcha/body.rs`, `shm.rs`, `stream.rs`.

---

## Debugging NGINX (especially AppSec + proxy)

### Symptom → meaning

| Client sees | Likely cause |
|-------------|--------------|
| **403** from CrowdSec module | Ban/AppSec deny — check module logs |
| **419/502/etc. from app** | Request reached upstream — nginx/proxy OK |
| **404** body `<center>nginx</center>` | **Default nginx static handler**, not your app — request never reached `proxy_pass` |
| **405** on POST to `try_files` location | AppSec allowed but location has no POST handler |

`try_files` and `proxy_pass` are different **content handlers**. AppSec must not resume phases in a way that drops the location’s handler.

### Enable debug logging

Debug is **off by default** and very noisy — turn it on only while reproducing a bug, then revert to `warn` or `notice`.

**1. Set log level** (any of these scopes; `http` block is enough for request tracing):

```nginx
# http { } in nginx.conf — typical for VPS
error_log /var/log/nginx/debug.log debug;

# or one vhost only (less noise)
server {
    error_log /var/log/nginx/debug-accounts.log debug;
    ...
}
```

**2. Reload or restart**

```bash
nginx -t && systemctl reload nginx   # enough for error_log path/level changes
# use restart (not reload) when testing phase-handler / .so changes
```

**3. Docker / CI** — already at debug in `docker/nginx.conf`:

```bash
docker logs <nginx-container> 2>&1 | grep -E 'phase|proxy|filename'
```

**Notes**

- Distro nginx packages (Debian/Ubuntu) ship with debug symbols — no special build needed.
- `debug` captures **all** `ngx_log_debug_http!` CrowdSec lines **and** core nginx phase/upstream traces.
- Module poller messages still use the main `error_log` at `notice`/`warn` — see [docs/configuration.md](docs/configuration.md#logging-and-debugging-lapi-polling).
- Truncate or rotate before a capture run; a busy site generates MB/s:

```bash
: > /var/log/nginx/debug.log    # or truncate -s 0 ...
```

### Parse the debug log

**Line shape** (each request gets a connection id `*NNN` — filter on that):

```text
2026/09/07 10:00:00 [debug] 12345#0: *678 http script var: "..."
2026/09/07 10:00:00 [debug] 12345#0: *678 http finalize request: 404, "/path"
```

**Workflow**

```bash
# 1. Clear log, 2. reproduce once (curl/browser), 3. grab the request's *id from the end
curl -sk -X POST -H 'User-Agent: Mozilla/5.0' -H 'Host: example.com' \
  -d 'x=1' https://example.com/auth/login -o /dev/null

REQ=$(grep 'POST /auth/login' /var/log/nginx/debug.log | tail -1 \
  | sed -n 's/.*: \*\([0-9]*\).*/\1/p')
grep "\*${REQ}" /var/log/nginx/debug.log \
  | grep -E 'phase|body|proxy|filename|finalize|upstream|crowdsec|appsec'
```

**Phase trail** — follow `http … phase:` lines in order. CrowdSec/AppSec runs in **access**; `proxy_pass` / `try_files` / static run in **content** (and later phases). If access ends with `finalize request: 403` and you never see content/proxy lines, the block happened before upstream.

| Grep pattern | Meaning |
|--------------|---------|
| `http access phase` | ACCESS handlers (CrowdSec ban/captcha/AppSec) |
| `http read client request body` | Body buffering (AppSec POST path) |
| `http finalize request: 403` | Request terminated in a phase handler |
| `finalize http proxy request` | **Healthy** — heading to upstream |
| `http upstream:` / `proxy:` | Upstream connect/send (request reached backend) |
| `http filename:` | **Static/try_files handler** — not proxy_pass |
| `http file:` + `404` | Default docroot miss → `<center>nginx</center>` 404 |
| `limiting requests` | Rate limit (429), not AppSec |

**Healthy POST → proxy_pass** (abbreviated):

```text
*678 http access phase: …
*678 http read client request body
*678 http finalize request: 0          # NGX_DECLINED — handler yielded
*678 http content handler              # location handler still set
*678 finalize http proxy request
*678 http upstream: …
```

**Broken POST (v0.3.2 bug)** — AppSec allowed but `content_handler` was cleared:

```text
*678 http read client request body
*678 http finalize request: 0
*678 http filename: "/usr/share/nginx/html/auth/login"   # wrong handler
*678 http finalize request: 404, "/usr/share/nginx/html/auth/login"
```

**403 vs upstream OK**

- Bare nginx 403 HTML, blocked at **access phase**, no `upstream:` → AppSec/ban/captcha or `deny`.
- App status (419 CSRF, 502, app JSON) → request reached upstream; debug is still useful to confirm body/proxy path.

**Quick greps** (when you are not isolating a single `*id`):

```bash
grep -E 'phase:|filename:|proxy|finalize request|upstream|read client request body' \
  /var/log/nginx/debug.log | tail -80
grep -iE 'crowdsec|appsec' /var/log/nginx/debug.log | tail -40
```

### `proxy_pass` / upstream resolution

| Config | When hostname is resolved | Startup fails if host missing? |
|--------|---------------------------|--------------------------------|
| `proxy_pass http://host:port/;` | Config load / worker start | **Yes** |
| `upstream { server host:port; }` + `proxy_pass http://name/` | Same (static server name) | **Yes** |
| `set $u http://host; proxy_pass $u;` + `resolver …` | Per request | No |
| `proxy_pass http://host;` + `docker run --add-host host:IP` | `/etc/hosts` at startup | No (CI pattern) |

### Test matrix (AppSec on)

1. GET → expect upstream response (200).
2. POST with body → if **404 nginx default**, phase/handler bug; if **app status** (e.g. 419 CSRF), upstream OK.
3. Compare **`crowdsec_appsec off`** on the vhost — isolates module vs nginx config.
4. Use a **browser User-Agent** — default `curl` UA can trigger AppSec bot rules (403), masking proxy issues.

### Production deploy notes

- Build `.so` against target nginx (Ubuntu `nginx-dev` vs Debian Docker).
- Module path: `/usr/lib/nginx/modules/libngx_http_crowdsec_module.so`.
- `nginx -t && systemctl restart nginx`.

---

## Git commits

Use **[Conventional Commits](https://www.conventionalcommits.org/)**: `type(scope): summary`

Types: `feat`, `fix`, `docs`, `chore`, `ci`, `test`, `refactor`, `release`.  
Scopes: `appsec`, `captcha`, `ci`, `shm`, `config`, etc.

```text
fix(appsec): restore content_handler after async body read
fix(ci): map proxy test upstream via docker add-host
release: v0.3.2
```

**Signing**: keep GPG signing on commits and tags (`-s`). If pinentry fails in a non-interactive session, ask the user to commit locally — do not use `commit.gpgsign=false`.

---

## Agent checklist

- [ ] Read changed phase/body code paths when touching AppSec or captcha POST.
- [ ] Re-run `scripts/test-appsec-proxy-post.sh` after AppSec/proxy changes.
- [ ] Build via Docker; match ABI for deployment target.
- [ ] Update [CHANGELOG.md](CHANGELOG.md) for user-visible fixes.
- [ ] Point config questions to [docs/configuration.md](docs/configuration.md) — do not duplicate full directive lists here.

## Known limitations

- SHM layout version mismatch → full nginx restart after upgrade.
- Captcha provider HTTP call blocks the worker briefly.
- AppSec / bot challenge experimental (CrowdSec 1.8+).
