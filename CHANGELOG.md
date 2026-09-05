# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **AppSec POST + proxy_pass** — POST bodies with AppSec enabled returned nginx 404 instead of reaching `proxy_pass`. Run body inspection in ACCESS (not PRECONTENT); return the AppSec result directly on synchronous body reads. After async body reads, restore the location `content_handler` and resume phases — `ngx_http_finalize_request(NGX_DECLINED)` clears it and drops proxy handlers.

## [0.3.1] - 2026-09-04

Patch: forward any client request body to AppSec, including GET.

### Fixed

- **AppSec GET with body** — Requests that include a body (including GET) are read in PRECONTENT and forwarded to the WAF agent, matching core ruleset coverage for non-standard methods (e.g. CRS rule 920170).

## [0.3.0] - 2026-09-04

Minor release: nginx-acme-inspired integration improvements, LAPI usage metrics, and operational logging.

### Added

- **LAPI usage metrics** — Push `processed`, `dropped`, and `active_decisions` to `POST /v1/usage-metrics` (default interval 900s; `crowdsec_usage_metrics_interval off` to disable). Counters flushed on worker shutdown/reload.
- **Bouncer User-Agent** — LAPI requests identify as `ngx_http_crowdsec_module/<version>` (fixes `ureq` showing in `cscli bouncers list`).
- **NGINX-native logging** — `src/log.rs` with `crowdsec_*!` macros; stream/SHM/config messages go to the error log instead of stderr.
- **`NgxConfExt`** — Config parse errors logged via `ngx_conf_log_error!` (`src/conf/ext.rs`).
- **Response helper** — Shared `src/response.rs` for ban/metrics/captcha body output via `Request::output_filter`.
- **SHM zone state machine** — `DecisionsSharedZone` dummy-init pattern (nginx-acme) for safer early zone registration.
- **`export-modules` feature** — Gates `ngx_modules!` export (default on for standalone `.so` builds).

### Changed

- **Metrics origin labels** — `CAPI` casing matches LAPI/Lua; `lists:<scenario>` no longer truncated (usage-metrics SHM auto-sized).
- **AppSec User-Agent** — Client UA forwarded only in `X-Crowdsec-Appsec-User-Agent`, not HTTP `User-Agent`.
- **LAPI config validation** — Warns at `nginx -t` when `crowdsec on` or partial LAPI settings but URL/key missing.
- **Release profile** — `codegen-units = 1` for smaller release binary.
- **Documentation** — Logging and debugging LAPI polling (`docs/configuration.md`); steady-state poll silence and `error_log` levels explained.

### Fixed

- **Usage metrics SHM** — Zone size increased after origin label expansion (was 64KB, caused alloc failure on nginx start).

## [0.2.2] - 2026-09-03

Patch: AppSec always mode, static asset bypass, zero compiler warnings.

## [0.2.1] - 2026-09-03

Patch release: required ban/captcha templates, captcha static-site fix, and template cleanup validated in production.

### Added

- **Template deploy helper** — `scripts/deploy-templates.example.sh` (copy to a gitignored `*.local.sh` with your host).
- **Config validation** — `nginx -t` fails when `crowdsec on` has no `crowdsec_ban_template` (unless redirect mode), or captcha keys are set without `crowdsec_captcha_template`.

### Changed

- **Ban/captcha templates** — Redesigned `default.html`, `simple.html`, `captcha.html`, and `api.json`; no built-in HTML fallback in the module.
- **Template variables** — Dropped `{{reason}}`; use `{{scenario}}` only (CrowdSec stores cscli `--reason` and scenario names in `scenario`).
- **Captcha POST handling** — 303 See Other after successful verification so POST is not forwarded to static backends.
- **Shared memory** — Layout v3 (reason table removed); **full nginx restart** required after upgrade, not `reload` only.

## [0.2.0] - 2026-09-03

First stable 0.2 release. Combines the rc1–rc3 feature set (AppSec with POST body inspection, captcha, Prometheus metrics, bypass lists, ban redirects, trusted-proxy client IP) with rc3 stability fixes validated in production.

### Added

- **OpenResty benchmark harness** — `./benchmarks/run.sh` compares throughput and latency against the official Lua bouncer ([results](benchmarks/results.md)).
- **Configuration reference** — Full directive documentation in `docs/configuration.md`.

### Changed

- **README** — Restructured around why/use-cases and Docker vs production quick-start paths.
- **Client IP documentation** — nginx `real_ip` is sufficient when already configured; `crowdsec_trusted_proxies` is optional.
- **Captcha provider** — Must be set explicitly (`hcaptcha`, `recaptcha`, or `turnstile`); no implicit default at runtime.
- **Copyright** — MIT license attributed to Laurence Jones.

### Known limitations

- **AppSec / bot challenge** — Bot challenge remains experimental (CrowdSec 1.8 protocol). Requires `crowdsec_appsec_url` and a matching AppSec component.
- **Captcha verification** — Provider API calls on POST are synchronous in the worker; high traffic may need async verification (planned).
- **Prometheus metrics** — No built-in authentication; protect the `crowdsec_metrics on` location with `allow`, `internal`, or auth.
- **Shared-memory upgrades** — Incompatible `crowdsec_decisions` layout changes require a full nginx restart, not `reload` only.
- **Remediation types** — Ban and captcha only; throttle and other LAPI types are ignored.
- **Release artifacts** — Published `.so` targets nginx 1.30.3 on Debian bookworm amd64; other nginx versions require a source build matching `nginx -V`.
- **Parity gaps** — Some lua-cs-bouncer edge cases may remain.

## [0.2.0-rc3] - 2026-09-03

Third release candidate: PRECONTENT AppSec body inspection, AppSec 403 fix, poller hardening.

### Added

- **PRECONTENT phase AppSec handler** — POST/PUT/PATCH/DELETE bodies are read in `NGX_HTTP_PRECONTENT_PHASE` instead of stalling the access phase; GET/HEAD AppSec remains in access.
- **Unit test compile gate in CI** — `cargo check --tests` runs in the Docker `rust-builder` stage (ngx module tests cannot link outside the NGINX host binary).

### Fixed

- **AppSec HTTP 403 handling** — Restore parsing when ureq returns `Error::Status(403, …)` so ban/challenge envelopes work again (regression from rc2).
- **AppSec PRECONTENT re-entry** — Skip body inspection when the request body is already buffered, avoiding a double callback after `finalize_allow()` resumes phases (worker SIGSEGV on POST allow).
- **AppSec captcha on POST** — Show captcha page directly instead of re-initiating body read (avoids double-finalize crashes).
- **Stale poller PID** — Re-elect stream poller when the recorded worker PID is dead (e.g. after SIGSEGV).
- **Captcha POST bodies** — Reject chunked/unbounded uploads; cap extraction at 64KB.

### Changed

- **CI** — AppSec integration tests run before the reload stress loop; release workflow requires green CI and marks `-rc` tags as prerelease.
- **Access handler** — Fail open gracefully when module config pointers are missing instead of panicking.

## [0.2.0-rc2] - 2026-09-02

Second release candidate: AppSec POST body inspection and metrics SHM reliability.

### Added

- **AppSec request body forwarding** — POST, PUT, PATCH, and DELETE bodies are buffered asynchronously and sent to the AppSec agent so form fields and JSON payloads are evaluated by the WAF (lua-cs-bouncer parity).
- **`crowdsec_appsec_drop_unreadable_body`** — When `on`, reject requests whose body cannot be buffered in memory (e.g. spooled to disk) instead of calling AppSec without the body.
- **Shared request body helpers** — `request_body.rs` centralizes async body reads for AppSec and captcha verification.

### Fixed

- **Metrics shared memory** — Zone size increased to 8KB so slab allocation succeeds on typical 4KB pages; init failure is non-fatal and disables counters instead of blocking module startup.

### Changed

- **CI** — AppSec integration test covers POST body forwarding via mock LAPI `check_body` matching.

## [0.2.0-rc1] - 2026-09-02

Release candidate: major feature expansion since 0.1.0, combining upstream merges and local development work.

### Added

- **AppSec and CrowdSec 1.8 bot challenge** — Optional `crowdsec_appsec` integration with configurable URL, API key, timeout, max body size, and failure action; `crowdsec_bot_challenge` for the CrowdSec challenge protocol (experimental). Internal `/crowdsec-internal/challenge/*` paths are handled by the module.
- **Trusted reverse-proxy client IP** — `crowdsec_trusted_proxies` and `crowdsec_real_ip_header` (default `X-Forwarded-For`) with recursive trusted stripping, matching nginx `real_ip_recursive` semantics.
- **IP/CIDR bypass** — `crowdsec_bypass` skips CrowdSec enforcement for resolved client IPs in listed networks (health checks, probes) without per-location `crowdsec off`.
- **Prometheus metrics** — `crowdsec_metrics on` on a dedicated location exposes counters (lookups, bans, captcha, bypass, LAPI poll success/error), decision cache size, and `crowdsec_lapi_stream_last_success_unixtime` via a separate `crowdsec_metrics` shared-memory zone.
- **Ban redirect remediation** — `crowdsec_ban_action redirect` with `crowdsec_ban_redirect_url` and configurable `crowdsec_ban_redirect_code` (`301`, `302`, `303`, `307`, `308`).
- **Ban reason in templates** — Ban `reason` from the LAPI stream is stored in shared memory and exposed as `{{reason}}` in ban templates (alongside existing `{{scenario}}`, `{{origin}}`, `{{host}}`, etc.).
- **LAPI tuning directives** — `crowdsec_poll_interval` (seconds between successful stream polls, default 10) and `crowdsec_lapi_timeout` (per-request HTTP timeout, default 30).
- **CI and release automation** — GitHub Actions CI builds the module image, validates ban/CIDR enforcement, reload hand-off, AppSec/challenge paths, and fail-open behavior against a mock LAPI; release workflow publishes container images to GHCR and attaches the compiled `.so` plus compatibility metadata on version tags.

### Changed

- **Shared-memory performance** — Decision cache lookups use read locks (`ngx_rwlock_rlock`) so worker hot paths no longer contend on write locks; poller thread alone performs writes.
- **LAPI stream client** — Reuses a persistent HTTP agent across polls and avoids per-poll parser allocations.
- **Reload-safe polling** — Poller election and stream thread survive `nginx -s reload`; stale poller claims are reset when compatible shared memory is reused. CI exercises repeated reloads and CIDR enforcement after hand-off.
- **Shared-memory layout versioning** — `crowdsec_decisions` zone header includes magic (`CsD1`) and layout version; reload reuses the zone only when both match—otherwise a full nginx restart is required after incompatible upgrades (documented in README troubleshooting).

### Fixed

- Decision polling remains active across worker reloads instead of stopping when the previous poller worker exits.

### Known limitations (RC)

- **AppSec / bot challenge** — Experimental; CrowdSec 1.8 challenge protocol may change. Requires `crowdsec_appsec_url` and a matching CrowdSec AppSec component.
- **Captcha verification** — Provider API calls on POST are synchronous in the worker; high traffic may need async verification (planned post-0.2.0).
- **Prometheus metrics** — No built-in authentication; protect the `crowdsec_metrics on` location with `allow`, `internal`, or auth. Metrics SHM init failure disables counters but does not block the module.
- **Shared-memory upgrades** — Incompatible `crowdsec_decisions` layout changes require a full nginx restart, not `reload` only.
- **Remediation types** — Ban and captcha only; throttle and other LAPI types are ignored.
- **Trusted-proxy IP** — Forwarded headers are honored only when the TCP peer matches `crowdsec_trusted_proxies`.
- **Parity gaps** — Some lua-cs-bouncer edge cases may remain; tracked for post-0.2.0.

## [0.1.0] - 2025

Initial release.

### Added

- CrowdSec LAPI decision streaming with cross-worker shared-memory cache (IP and CIDR lookups).
- Ban remediation with customizable HTML/JSON/plain templates.
- Captcha remediation with hCaptcha, reCAPTCHA, and Cloudflare Turnstile, signed session cookies, and fail-open verification.
- Docker-based build and test environment.
