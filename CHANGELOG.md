# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.2] - 2026-09-21

Hardening after 0.5.1: AppSec header handling, captcha open-redirect/JWT checks, SHM lock reclaim, and thread-pool task posting. No SHM layout bump — `reload` is enough if you already restarted for 0.5.0.

### Changed

- **AppSec request** — HTTP `Host` is the AppSec agent. The incoming vhost is `X-Crowdsec-Appsec-Host`. Client headers are copied first (skipping `Host`, `Content-Length`, hop-by-hop, `User-Agent`, and client `X-Crowdsec-*`); CrowdSec metadata headers are applied last so they overwrite any leftover copies.
- **AppSec oversized / temp-file bodies** — headers-only inspect by default (no event-loop file read). `crowdsec_appsec_drop_unreadable_body on` still denies with the ban template.
- **Captcha `Secure` cookie (`auto`)** — `X-Forwarded-Proto` / `X-Forwarded-Ssl` are trusted only when the TCP peer is in `crowdsec_trusted_proxies`.
- **Usage metrics** — failed LAPI pushes retry on the next poll instead of waiting a full interval; worker-exit flush uses a 2s timeout so reload/stop is not blocked by the LAPI HTTP timeout.
- **Config warnings** — `crowdsec on` without `crowdsec_url` / `crowdsec_api_key`, and `crowdsec_appsec on` without `crowdsec_appsec_url`, are logged after location merge (previously the LAPI warning ran too early to see `crowdsec on`).

### Fixed

- Protocol-relative captcha return URIs (`//host`) no longer become open redirects.
- Captcha JWT requires `typ=captcha_pass` and rejects `iat` more than 60s in the future.
- Captcha provider-key and cookie-name lengths are rejected at config parse (they must fit the POST context).
- Thread-pool tasks arm keepalive / `blocked` / `aio` before `ngx_thread_task_post`, and roll those back if the queue is full. Captcha queue-unavailable shows the challenge error page instead of fail-open.
- Completing a thread-pool task after client disconnect runs `ngx_http_run_posted_requests`; panics in work/complete are caught.
- SHM writer lock is cleared when reclaiming a dead poller PID (not only on zone init). Clock eviction prefers expired slots; `clear_all` zeros CIDR prefix scratch; removing a decision type clears its expiry bit.
- Usage `dropped` counters increment only after a captcha page is actually sent (or a verification POST starts).
- Captcha template/IP/header failures return 403 instead of 500 or allow.

### Added

- CI job that compiles the Ubuntu 24.04 / nginx 1.24 apt module. Release artifacts include the Debian 13 (trixie) `.so`.

## [0.5.1] - 2026-09-21

Patch: bump `rustls` 0.23.43 → 0.23.45 so `cargo audit` passes ([RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285) / GHSA-2mjx-qc3c-rqvc). TLS 1.3 handshake messages packed across a key change in the same record are now rejected. Transitive via `ureq`; no module API change. Full restart is **not** required if you already restarted for 0.5.0.

## [0.5.0] - 2026-09-21

Minor: AppSec and captcha-provider HTTP run on nginx's native thread pool (workers no longer block on `ureq`), ban and captcha deadlines expire independently, and an AppSec `captcha` action is applied as a ban.

**Upgrade requires a full `nginx` restart** (`systemctl restart nginx`), not `reload`:

- Decision SHM is **layout version 4** (independent ban vs captcha expiry for IPs and CIDRs).
- Metrics SHM is **layout version 2** (AppSec Prometheus counters).

Reload after this restart is fine until the next layout bump. A layout mismatch logs that the zone is incompatible and skips reuse.

nginx must be built with **`--with-threads`**. Ubuntu 24.04 apt (`1.24.0`), Debian 13 apt (`1.26.x`), and this project's Docker image (`1.30.3`) already enable it. Confirm with `nginx -V`. Size the pool in the main context if needed, for example `thread_pool default threads=4 max_queue=128;` — a full queue uses the configured AppSec/captcha failure policy, and queue wait is additional to the HTTP timeout.

### Breaking / behavioral

- **`--with-threads` is required** at compile time and at runtime. Source builds without it will fail to load the module.
- **AppSec `captcha` is a ban.** Solving a stream captcha never bypasses a WAF rule. Captcha verification remains for LAPI stream decisions only.
- **`crowdsec_appsec_failure_action deny`** and unreadable/too-large body deny use the same ban template / `crowdsec_ban_action` as an AppSec `ban` (no more bare nginx 403).

### Added

- **Thread-pool offload** — AppSec inspect and captcha-provider verify are posted to nginx's `default` pool (`ngx_thread_task_post`). Completions run back on the event loop; a non-cancelable keepalive timer holds the worker open while work is queued so `reload` does not abort with “open socket left in connection”. Compatible with nginx 1.24 (uses connection `error` instead of `r->terminated`, which exists only on ≥ 1.25.5).
- **Prometheus AppSec counters** — `crowdsec_appsec_requests_total`, `crowdsec_appsec_blocks_total`, and `crowdsec_appsec_errors_total`. `requests` increments when the inspect is queued.
- **Debian 13 (trixie) module image** — `docker/Dockerfile.debian-trixie-module` and `scripts/build-debian-trixie-module.sh` for apt nginx 1.26.x.
- **Pure Rust unit crate** (`tests/unit`, `cargo test -p crowdsec-unit-tests`) and **in-image regressions** (`tests/regression.py`) covering captcha-session writes, AppSec captcha bans, slow verification, client disconnects, IP/CIDR expiry, metrics during uploads, queue saturation, and reload-during-inflight.

### Changed

- **Independent expiry** — an IP or CIDR can drop its ban at the ban deadline while a captcha decision on the same key remains, and the reverse. Unlimited (`expires=0`) still dominates a finite deadline when merging.
- **Captcha sessions** — a valid cookie lets application POST/PUT/PATCH/DELETE through unchanged. Only the captcha verification submission itself 303-redirects.
- **Usage metrics** — LAPI uploads serialize and ACK the same snapshot (`fetch_sub` the posted values) so traffic recorded during the HTTP round-trip is kept. Shutdown flush waits for the poller to finish.
- **AppSec HTTP version** — `X-Crowdsec-Appsec-Http-Version` is the version nginx saw (`10` / `11` / `20` / `30`) instead of always `11`.
- **Docs** — `crowdsec_appsec_timeout` no longer claims to block the worker; thread-pool sizing, AppSec captcha-as-ban, and the restart requirement are documented. Docker/Ubuntu module Dockerfiles pass `--with-threads`.
- **CI** — builder runs `cargo test -p crowdsec-unit-tests` and `python3 tests/regression.py --captcha-stall`. BATS integration count is 22 (24 including challenge).

### Fixed

- JWT captcha claims parse with serde JSON, so signed tokens whose `uri` contains Unicode no longer panic in the worker.
- Reload while an AppSec/captcha thread-pool task is in flight no longer hits `ngx_event_no_more_timers()` and worker abort.

## [0.4.2] - 2026-09-07

Patch: AppSec inspection returns to **PRECONTENT** (nginx `mirror`), and AppSec bans use the ban template.

Upgrade requires a **full `nginx` restart** (not reload): the PRECONTENT handler is registered again.

### Changed

- AppSec inspection (headers and request body) runs in **PRECONTENT**, matching nginx `mirror`. ACCESS is IP ban/captcha only; remediations are deferred when `crowdsec_appsec_always` must inspect first. Body resume sets `r->preserve_body` so `proxy_pass` still sees the POST body.
- AppSec `ban` (and invalid AppSec 403 JSON) uses `crowdsec_ban_template` / `crowdsec_ban_action` like LAPI bans. `{{origin}}` is `appsec`; `{{scenario}}` is empty (CrowdSec does not send the matched rule to the bouncer).

## [0.4.1] - 2026-09-07

Patch: AppSec/captcha POST body reads no longer leak nginx worker memory, plus lifecycle and lookup fixes.

Upgrade requires a **full `nginx` restart** (not reload): metrics SHM is layout-versioned, and the body-read count fix lives in the ACCESS path.

### Fixed

- AppSec/captcha ACCESS body reads now call `ngx_http_finalize_request(NGX_DONE)` after `ngx_http_read_client_request_body` (nginx mirror pattern), so request pools and connections are freed. Previously every POST with a body leaked worker RSS.
- Captcha POST ctx is magic-checked; the template is read from location conf instead of a raw pointer.
- Stream `startup=true` replaces the decision cache (`clear_all`) so LAPI unbans are not stale after reload.
- IPv4-mapped IPv6 clients (`::ffff:a.b.c.d`) match IPv4 bans, bypass, and trusted proxies.
- Poller thread is joined on worker exit; SHM rwlock is reset on zone reuse only when the previous poller PID is gone. Every worker runs a standby poller thread so reload does not overlap two LAPI writers.
- `crowdsec_captcha_bind_ip on` rejects JWT `sub=anonymous` tokens.
- Internal `/crowdsec-internal/challenge/*` denies when AppSec is unconfigured instead of passing to origin.
- Captcha body-read errors honor `crowdsec_unenforceable_action`.
- Usage-metrics `dropped` and Prometheus `http_ban` count remediations actually applied (not captcha passes / unenforceable allow). AppSec bans increment `http_ban`.
- Invalid `on`/`off` flag values fail `nginx -t`. `crowdsec_metrics` is location-only and does not inherit.
- XFF `host:port` tokens parse; all `Cookie` headers are scanned.
- AppSec body context is allocated from the main request pool.

### Changed

- PRECONTENT CrowdSec handler is no longer registered (AppSec body inspect is ACCESS-only).
- Internal cleanup: shared body-read result packing, one captcha FFI send path, unused SHM wrappers and one-shot helpers removed.
- Simulated LAPI decisions are skipped. Stream deltas log at `info`, not `notice`.
- Prometheus `crowdsec_decision_cache_entries` is non-expired rows; added `crowdsec_decision_cache_evictions_total`.
- Metrics and usage-metrics SHM zones are layout-versioned.

## [0.4.0] - 2026-09-07

Minor release: Lua bouncer remediation parity, optional ban templates, and real CrowdSec CI.

### Breaking changes

- **`crowdsec_ban_template`** is no longer required when `crowdsec_ban_action` is `block`. Without a template the module returns **`crowdsec_ban_status`** (default 403) with a minimal body. To fail closed when a template is missing, set `crowdsec_unenforceable_action block`.
- **`crowdsec_captcha_template`** is required only when captcha keys are set **and** `crowdsec_unenforceable_action` is `block`. With the default `allow`, captcha keys without a template no longer fail `nginx -t`.
- **Unknown LAPI remediation types** are handled explicitly via **`crowdsec_fallback_remediation`** (default `allow`). Set `ban` or `captcha` if you relied on implicit behavior for future decision types.

### Added

- **`crowdsec_ban_status`** — Block-mode ban HTTP status (400–599, default 403). Lua bouncer parity with `RET_CODE`.
- **`crowdsec_fallback_remediation allow|ban|captcha`** — Unknown LAPI remediation types (http level). Default `allow` (ignore/store skip).
- **`crowdsec_unenforceable_action allow|block`** — When a known remediation (`ban` or `captcha`) cannot be applied (missing config/template, send failure). Default `allow` (fail-open). `block` returns `crowdsec_ban_status`.
- **Real CrowdSec CI** — 21 BATS tests (integration + bot challenge) against CrowdSec v1.8.1; mock LAPI stack removed from CI.
- **Hub AppSec harness** (local) — Run CrowdSec hub `.appsec-tests` against the module; see [docs/testing.md](docs/testing.md).

### Changed

- **Documentation** — Lean README; testing and configuration docs updated for new directives and CI layout.
- **CI** — GitHub Actions runs `./scripts/test-bats-ci.sh` (integration + challenge only).

### Fixed

- **`NGX_CONF_1MORE`** on `crowdsec_trusted_proxies`, `crowdsec_bypass`, and `crowdsec_static_extensions` — multiple values in one directive now parse correctly.

## [0.3.2] - 2026-09-05

Patch: AppSec POST body inspection no longer breaks `proxy_pass`.

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
