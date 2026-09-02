# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
