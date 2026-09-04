//! Push remediation usage metrics to CrowdSec LAPI (`POST /v1/usage-metrics`).
//!
//! Matches the lua-cs-bouncer model: `processed` and `dropped` counters with
//! `ip_type` / `origin` labels, plus an `active_decisions` snapshot from the
//! decision cache before each push.

use crate::log::cycle_log;
use crate::shm::{self, Origin};
use ngx::ffi::{ngx_int_t, ngx_shm_zone_t, ngx_slab_alloc_locked, ngx_slab_pool_t, ngx_str_t};
use ngx::ngx_string;
use std::collections::HashMap;
use std::ffi::c_void;
use std::net::IpAddr;
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BUCKETS: usize = 512;
/// Max `origin` label length (`lists:` + scenario; must not truncate list UUIDs).
const ORIGIN_MAX: usize = 6 + crate::shm::MAX_SCENARIO_LEN;

const USAGE_METRICS_DATA_SIZE: usize =
    std::mem::size_of::<UsageMetricsHeader>() + std::mem::size_of::<UsageBucket>() * MAX_BUCKETS;
/// ngx slab pool metadata + page alignment headroom.
const USAGE_METRICS_SLAB_OVERHEAD: usize = 8192;
const USAGE_METRICS_SHM_SIZE: usize =
    (USAGE_METRICS_DATA_SIZE + USAGE_METRICS_SLAB_OVERHEAD + 4095) & !4095;

const KIND_PROCESSED: u8 = 1;
const KIND_DROPPED: u8 = 2;
const KIND_ACTIVE: u8 = 3;

static USAGE_SHM_ZONE: AtomicPtr<ngx_shm_zone_t> = AtomicPtr::new(ptr::null_mut());

#[repr(C)]
struct UsageMetricsHeader {
    startup_unix_secs: AtomicU64,
    last_push_unix_secs: AtomicU64,
    bucket_count: u32,
}

#[repr(C)]
struct UsageBucket {
    key_hash: AtomicU32,
    value: AtomicU64,
    kind: u8,
    ip_type: u8,
    origin_len: u8,
    _pad: u8,
    origin: [u8; ORIGIN_MAX],
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct BucketKey {
    kind: u8,
    ip_type: u8,
    origin: [u8; ORIGIN_MAX],
    origin_len: u8,
}

impl BucketKey {
    fn hash(&self) -> u32 {
        let mut h: u32 = 2166136261;
        h = fnv_mix(h, self.kind);
        h = fnv_mix(h, self.ip_type);
        for i in 0..self.origin_len as usize {
            h = fnv_mix(h, self.origin[i]);
        }
        if h < 2 {
            h + 2
        } else {
            h
        }
    }

    fn from_labels(kind: u8, ip_type: u8, origin: &str) -> Self {
        let mut key = Self {
            kind,
            ip_type,
            origin: [0; ORIGIN_MAX],
            origin_len: 0,
        };
        let bytes = origin.as_bytes();
        let len = bytes.len().min(ORIGIN_MAX);
        key.origin[..len].copy_from_slice(&bytes[..len]);
        key.origin_len = len as u8;
        key
    }
}

fn fnv_mix(hash: u32, byte: u8) -> u32 {
    (hash ^ byte as u32).wrapping_mul(16777619)
}

fn ip_type_byte(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 6,
    }
}

fn ip_type_label(ip_type: u8) -> &'static str {
    if ip_type == 6 { "ipv6" } else { "ipv4" }
}

/// Origin label for usage metrics (lists use `lists:<scenario>` like lua-cs-bouncer).
///
/// Lua stores the LAPI `origin` field verbatim (except `lists` → `lists:<scenario>`).
/// Metrics must use the same strings so Console aggregation matches other bouncers.
pub fn origin_label(origin: Origin, scenario_id: u16) -> String {
    if origin == Origin::Lists {
        if let Some(scenario) = shm::get_scenario(scenario_id) {
            return format!("lists:{scenario}");
        }
        return "lists".to_string();
    }
    origin.metrics_label().to_string()
}

fn header_ptr() -> Option<*mut UsageMetricsHeader> {
    let zone = USAGE_SHM_ZONE.load(Ordering::SeqCst);
    if zone.is_null() {
        return None;
    }
    unsafe {
        let data = (*zone).data.cast::<UsageMetricsHeader>();
        if data.is_null() { None } else { Some(data) }
    }
}

fn buckets_ptr(header: *mut UsageMetricsHeader) -> *mut UsageBucket {
    unsafe { header.add(1).cast::<UsageBucket>() }
}

fn bucket_inc(key: BucketKey, delta: u64) {
    let Some(header) = header_ptr() else {
        return;
    };
    let hash = key.hash();
    let buckets = buckets_ptr(header);
    let count = unsafe { (*header).bucket_count as usize };
    let mut idx = (hash as usize) % count;
    let start = idx;

    loop {
        let bucket = unsafe { &*buckets.add(idx) };
        let existing = bucket.key_hash.load(Ordering::Acquire);
        if existing == hash {
            bucket.value.fetch_add(delta, Ordering::Relaxed);
            return;
        }
        if existing == 0 {
            if bucket
                .key_hash
                .compare_exchange(0, hash, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                unsafe {
                    let b = &mut *buckets.add(idx);
                    b.kind = key.kind;
                    b.ip_type = key.ip_type;
                    b.origin_len = key.origin_len;
                    b.origin = key.origin;
                    b.value.store(delta, Ordering::Release);
                }
                return;
            }
        }
        idx = (idx + 1) % count;
        if idx == start {
            crowdsec_warn!(cycle_log(), "crowdsec: usage metrics bucket table full");
            return;
        }
    }
}

fn bucket_set(key: BucketKey, value: u64) {
    let Some(header) = header_ptr() else {
        return;
    };
    let hash = key.hash();
    let buckets = buckets_ptr(header);
    let count = unsafe { (*header).bucket_count as usize };
    let mut idx = (hash as usize) % count;
    let start = idx;

    loop {
        let bucket = unsafe { &*buckets.add(idx) };
        let existing = bucket.key_hash.load(Ordering::Acquire);
        if existing == hash {
            bucket.value.store(value, Ordering::Release);
            return;
        }
        if existing == 0 {
            if bucket
                .key_hash
                .compare_exchange(0, hash, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                unsafe {
                    let b = &mut *buckets.add(idx);
                    b.kind = key.kind;
                    b.ip_type = key.ip_type;
                    b.origin_len = key.origin_len;
                    b.origin = key.origin;
                    b.value.store(value, Ordering::Release);
                }
                return;
            }
        }
        idx = (idx + 1) % count;
        if idx == start {
            return;
        }
    }
}

/// Record a request evaluated by the bouncer (`processed` metric).
pub fn record_processed(client_ip: &IpAddr) {
    let ip_type = ip_type_byte(client_ip);
    bucket_inc(BucketKey::from_labels(KIND_PROCESSED, ip_type, ""), 1);
}

/// Record a remediated request (`dropped` metric) from a SHM decision.
pub fn record_dropped(client_ip: &IpAddr, origin: Origin, scenario_id: u16) {
    let label = origin_label(origin, scenario_id);
    bucket_inc(
        BucketKey::from_labels(KIND_DROPPED, ip_type_byte(client_ip), &label),
        1,
    );
}

/// Record an AppSec block (`dropped` with origin `appsec`).
pub fn record_appsec_dropped(client_ip: &IpAddr) {
    bucket_inc(
        BucketKey::from_labels(KIND_DROPPED, ip_type_byte(client_ip), "appsec"),
        1,
    );
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Called once on the elected poller worker at startup.
pub fn record_startup() {
    let Some(header) = header_ptr() else {
        return;
    };
    unsafe {
        header
            .as_ref()
            .unwrap()
            .startup_unix_secs
            .compare_exchange(0, unix_now(), Ordering::SeqCst, Ordering::SeqCst)
            .ok();
    }
}

fn clear_kind_buckets(kind: u8) {
    let Some(header) = header_ptr() else {
        return;
    };
    let buckets = buckets_ptr(header);
    let count = unsafe { (*header).bucket_count as usize };
    for i in 0..count {
        let bucket = unsafe { &*buckets.add(i) };
        if bucket.key_hash.load(Ordering::Acquire) == 0 {
            continue;
        }
        if bucket.kind == kind {
            unsafe {
                let b = &mut *buckets.add(i);
                b.key_hash.store(0, Ordering::Release);
                b.value.store(0, Ordering::Release);
            }
        }
    }
}

fn refresh_active_decisions() {
    clear_kind_buckets(KIND_ACTIVE);
    for (origin, scenario_id, ip_type, count) in shm::count_active_decisions_by_origin() {
        let label = origin_label(origin, scenario_id);
        bucket_set(
            BucketKey::from_labels(KIND_ACTIVE, ip_type, &label),
            count,
        );
    }
}

fn read_os_info() -> (String, String) {
    let content = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let mut name = String::from("linux");
    let mut version = String::new();
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("NAME=") {
            name = trim_quotes(v);
        } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
            version = trim_quotes(v);
        }
    }
    if version.is_empty() {
        version = "unknown".to_string();
    }
    (name, version)
}

fn trim_quotes(s: &str) -> String {
    s.trim_matches('"').to_string()
}

#[derive(Debug, serde::Serialize)]
struct UsageMetricsPayload<'a> {
    log_processors: Option<()>,
    remediation_components: Vec<RemediationComponent<'a>>,
}

#[derive(Debug, serde::Serialize)]
struct RemediationComponent<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    component_type: &'a str,
    version: &'a str,
    feature_flags: Vec<String>,
    utc_startup_timestamp: u64,
    os: OsInfo<'a>,
    metrics: Vec<MetricsWindow>,
}

#[derive(Debug, serde::Serialize)]
struct OsInfo<'a> {
    name: &'a str,
    version: &'a str,
}

#[derive(Debug, serde::Serialize)]
struct MetricsWindow {
    meta: MetricsMeta,
    items: Vec<MetricItem>,
}

#[derive(Debug, serde::Serialize)]
struct MetricsMeta {
    window_size_seconds: u64,
    utc_now_timestamp: u64,
}

#[derive(Debug, serde::Serialize)]
struct MetricItem {
    name: &'static str,
    value: u64,
    unit: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<HashMap<String, String>>,
}

fn collect_items() -> Vec<(BucketKey, u64)> {
    let Some(header) = header_ptr() else {
        return Vec::new();
    };
    let buckets = buckets_ptr(header);
    let count = unsafe { (*header).bucket_count as usize };
    let mut out = Vec::new();
    for i in 0..count {
        let bucket = unsafe { &*buckets.add(i) };
        if bucket.key_hash.load(Ordering::Acquire) == 0 {
            continue;
        }
        let value = bucket.value.load(Ordering::Relaxed);
        if value == 0 {
            continue;
        }
        let origin = std::str::from_utf8(&bucket.origin[..bucket.origin_len as usize])
            .unwrap_or("")
            .to_string();
        out.push((
            BucketKey::from_labels(bucket.kind, bucket.ip_type, &origin),
            value,
        ));
    }
    out
}

fn reset_after_push(items: &[(BucketKey, u64)]) {
    let Some(header) = header_ptr() else {
        return;
    };
    let buckets = buckets_ptr(header);
    let count = unsafe { (*header).bucket_count as usize };

    for (key, value) in items {
        if key.kind == KIND_ACTIVE {
            continue;
        }
        let hash = key.hash();
        let mut idx = (hash as usize) % count;
        let start = idx;
        loop {
            let bucket = unsafe { &*buckets.add(idx) };
            if bucket.key_hash.load(Ordering::Acquire) == hash {
                if key.kind == KIND_PROCESSED {
                    bucket.value.fetch_sub(*value, Ordering::Relaxed);
                } else if key.kind == KIND_DROPPED {
                    bucket.key_hash.store(0, Ordering::Release);
                    bucket.value.store(0, Ordering::Release);
                }
                break;
            }
            idx = (idx + 1) % count;
            if idx == start {
                break;
            }
        }
    }
}

fn build_payload(window_secs: u64, now: u64, startup: u64, os_name: &str, os_version: &str) -> String {
    let mut metric_items = Vec::new();

    for (key, value) in collect_items() {
        let ip_label = ip_type_label(key.ip_type).to_string();
        let origin = std::str::from_utf8(&key.origin[..key.origin_len as usize])
            .unwrap_or("")
            .to_string();
        match key.kind {
            KIND_PROCESSED => {
                let mut labels = HashMap::new();
                labels.insert("ip_type".to_string(), ip_label);
                metric_items.push(MetricItem {
                    name: "processed",
                    value,
                    unit: "request",
                    labels: Some(labels),
                });
            }
            KIND_DROPPED => {
                let mut labels = HashMap::new();
                labels.insert("ip_type".to_string(), ip_label);
                labels.insert("origin".to_string(), origin);
                metric_items.push(MetricItem {
                    name: "dropped",
                    value,
                    unit: "request",
                    labels: Some(labels),
                });
            }
            KIND_ACTIVE => {
                let mut labels = HashMap::new();
                labels.insert("ip_type".to_string(), ip_label);
                labels.insert("origin".to_string(), origin);
                metric_items.push(MetricItem {
                    name: "active_decisions",
                    value,
                    unit: "ip",
                    labels: Some(labels),
                });
            }
            _ => {}
        }
    }

    let version = crate::lapi::BOUNCER_USER_AGENT;
    let payload = UsageMetricsPayload {
        log_processors: None,
        remediation_components: vec![RemediationComponent {
            name: "nginx bouncer",
            component_type: "nginx-module",
            version,
            feature_flags: Vec::new(),
            utc_startup_timestamp: startup,
            os: OsInfo {
                name: os_name,
                version: os_version,
            },
            metrics: vec![MetricsWindow {
                meta: MetricsMeta {
                    window_size_seconds: window_secs,
                    utc_now_timestamp: now,
                },
                items: metric_items,
            }],
        }],
    };

    let mut json = serde_json::to_string(&payload).unwrap_or_default();
    if json.contains("\"feature_flags\":{}") {
        json = json.replace("\"feature_flags\":{}", "\"feature_flags\":[]");
    }
    json
}

/// Push usage metrics to LAPI. No-op when the interval is 0 or SHM is unavailable.
pub fn push_to_lapi(
    lapi_url: &str,
    api_key: &str,
    timeout_secs: u64,
    window_secs: u64,
) -> Result<(), String> {
    if window_secs == 0 {
        return Ok(());
    }
    let Some(header) = header_ptr() else {
        return Ok(());
    };

    refresh_active_decisions();

    let now = unix_now();
    let startup = unsafe {
        header
            .as_ref()
            .unwrap()
            .startup_unix_secs
            .load(Ordering::Relaxed)
    };
    let last_push = unsafe {
        header
            .as_ref()
            .unwrap()
            .last_push_unix_secs
            .load(Ordering::Relaxed)
    };
    let window = if last_push == 0 {
        window_secs
    } else {
        now.saturating_sub(last_push).max(1)
    };

    let items = collect_items();
    if items.iter().all(|(_, v)| *v == 0) {
        return Ok(());
    }

    let (os_name, os_version) = read_os_info();
    let body = build_payload(window, now, startup, &os_name, &os_version);
    let url = format!(
        "{}/v1/usage-metrics",
        lapi_url.trim_end_matches('/')
    );

    let agent = crate::lapi::agent();
    let response = crate::lapi::with_api_key(agent.post(&url), api_key)
        .set("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .send_string(&body)
        .map_err(|e| e.to_string())?;

    let status = response.status();
    if !(200..300).contains(&status) {
        return Err(format!("LAPI usage-metrics HTTP {status}"));
    }

    reset_after_push(&items);
    unsafe {
        header
            .as_ref()
            .unwrap()
            .last_push_unix_secs
            .store(now, Ordering::Relaxed);
    }
    Ok(())
}

/// Push any pending usage metrics before worker shutdown (reload or stop).
///
/// Called from the elected poller worker's `exit_process` hook so counters are not
/// lost on full restart. On `reload`, shared-memory counters survive, but flushing
/// still closes the current reporting window cleanly for LAPI.
pub fn flush_on_shutdown(
    lapi_url: &str,
    api_key: &str,
    timeout_secs: u64,
    interval_secs: u64,
) {
    if interval_secs == 0 {
        return;
    }
    match push_to_lapi(lapi_url, api_key, timeout_secs, interval_secs) {
        Ok(()) => crowdsec_notice!(cycle_log(), "crowdsec: usage-metrics flushed on worker shutdown"),
        Err(e) => crowdsec_warn!(
            cycle_log(),
            "crowdsec: usage-metrics flush on shutdown failed: {e}"
        ),
    }
}

/// Initialize the usage-metrics shared zone.
///
/// # Safety
/// Valid `ngx_conf_t` from NGINX configuration parsing.
pub unsafe fn init_usage_metrics_shm_zone(cf: *mut ngx::ffi::ngx_conf_t) -> Result<(), ()> {
    unsafe {
        let name: ngx_str_t = ngx_string!("crowdsec_usage_metrics");
        let shm_zone = ngx::ffi::ngx_shared_memory_add(
            cf,
            &name as *const _ as *mut _,
            USAGE_METRICS_SHM_SIZE,
            &raw const crate::ngx_http_crowdsec_module as *mut _,
        );
        if shm_zone.is_null() {
            return Err(());
        }
        (*shm_zone).init = Some(usage_metrics_zone_init);
        (*shm_zone).data = ptr::null_mut();
        USAGE_SHM_ZONE.store(shm_zone, Ordering::SeqCst);
    }
    Ok(())
}

unsafe extern "C" fn usage_metrics_zone_init(
    shm_zone: *mut ngx_shm_zone_t,
    data: *mut c_void,
) -> ngx_int_t {
    unsafe {
        if !data.is_null() {
            (*shm_zone).data = data;
            return ngx::ffi::NGX_OK as ngx::ffi::ngx_int_t;
        }

        let shpool = (*shm_zone).shm.addr as *mut ngx_slab_pool_t;
        if shpool.is_null() {
            return ngx::ffi::NGX_ERROR as ngx::ffi::ngx_int_t;
        }

        let header_size = std::mem::size_of::<UsageMetricsHeader>();
        let bucket_size = std::mem::size_of::<UsageBucket>();
        let total = header_size + bucket_size * MAX_BUCKETS;
        let p = ngx_slab_alloc_locked(shpool, total);
        if p.is_null() {
            crowdsec_warn!(
                cycle_log(),
                "crowdsec: warning: failed to allocate usage metrics SHM (need {total} bytes data, zone {} bytes)",
                USAGE_METRICS_SHM_SIZE
            );
            return ngx::ffi::NGX_OK as ngx::ffi::ngx_int_t;
        }

        ptr::write(
            p.cast::<UsageMetricsHeader>(),
            UsageMetricsHeader {
                startup_unix_secs: AtomicU64::new(0),
                last_push_unix_secs: AtomicU64::new(0),
                bucket_count: MAX_BUCKETS as u32,
            },
        );
        ptr::write_bytes(
            p.add(header_size).cast::<UsageBucket>(),
            0,
            MAX_BUCKETS,
        );

        (*shm_zone).data = p;
    }
    ngx::ffi::NGX_OK as ngx::ffi::ngx_int_t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_label_lists_uses_scenario() {
        assert_eq!(origin_label(Origin::Crowdsec, 0), "crowdsec");
        assert_eq!(origin_label(Origin::Lists, 0), "lists");
        assert_eq!(origin_label(Origin::Capi, 0), "CAPI");
    }

    #[test]
    fn usage_metrics_zone_size_covers_buckets() {
        let need = std::mem::size_of::<UsageMetricsHeader>()
            + std::mem::size_of::<UsageBucket>() * MAX_BUCKETS;
        assert!(
            USAGE_METRICS_SHM_SIZE >= need + USAGE_METRICS_SLAB_OVERHEAD,
            "zone {} too small for {need} bytes of bucket data",
            USAGE_METRICS_SHM_SIZE
        );
    }

    #[test]
    fn origin_label_fits_long_list_name() {
        let long = "lists:threat_forecast_df9b68d7-0667-4d06-8a3c-b8616dae9003";
        assert!(long.len() <= ORIGIN_MAX);
        let key = BucketKey::from_labels(KIND_DROPPED, 4, long);
        let stored = std::str::from_utf8(&key.origin[..key.origin_len as usize]).unwrap();
        assert_eq!(stored, long);
    }

    #[test]
    fn bucket_key_hash_stable() {
        let a = BucketKey::from_labels(KIND_DROPPED, 4, "crowdsec");
        let b = BucketKey::from_labels(KIND_DROPPED, 4, "crowdsec");
        assert_eq!(a.hash(), b.hash());
        assert_ne!(
            a.hash(),
            BucketKey::from_labels(KIND_DROPPED, 6, "crowdsec").hash()
        );
    }

    #[test]
    fn payload_serializes_feature_flags_array() {
        let json = build_payload(900, 1_700_000_000, 1_699_999_000, "Fedora", "43");
        assert!(json.contains("\"feature_flags\":[]"));
        assert!(json.contains("\"type\":\"nginx-module\""));
        assert!(json.contains("/v1/usage-metrics") == false);
    }
}
