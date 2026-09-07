//! CrowdSec NGINX Module
//!
//! This module integrates NGINX with CrowdSec LAPI to enforce IP ban and captcha decisions.
//! It uses the stream mode to efficiently sync decisions and checks incoming
//! requests against a shared memory decision cache accessible by all workers.

#[macro_use]
mod log;

mod appsec;
mod captcha;
mod conf;
mod config;
mod lapi;
mod handler;
mod metrics;
mod realip;
mod request_body;
mod response;
pub mod shm;
mod stream;
mod template;
mod types;
mod usage_metrics;

use config::{DEFAULT_SHM_SIZE, LocConfig, MainConfig, NGX_HTTP_CROWDSEC_COMMANDS};
use conf::{ConfValueError, NgxConfExt};
use handler::handle_access;
use ngx::core::Status;
use ngx::ffi::{
    NGX_HTTP_MODULE, NGX_OK, ngx_array_push, ngx_conf_t, ngx_cycle_t, ngx_http_handler_pt,
    ngx_http_module_t, ngx_http_phases_NGX_HTTP_ACCESS_PHASE, ngx_int_t, ngx_module_t,
};
use ngx::http::{
    HttpModule, HttpModuleLocationConf, HttpModuleMainConf, Merge, MergeConfigError,
    NgxHttpCoreModule, Request,
};
use ngx::{http_request_handler, ngx_modules};
use std::os::raw::{c_char, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use stream::{StreamClient, StreamClientConfig};

/// Global configuration extracted at postconfiguration
static GLOBAL_CONFIG: Mutex<Option<StreamClientConfig>> = Mutex::new(None);

/// Handle to the polling thread (for potential cleanup)
static POLLING_HANDLE: Mutex<Option<(JoinHandle<()>, Arc<AtomicBool>)>> = Mutex::new(None);

/// The CrowdSec HTTP module
struct Module;

pub(crate) fn crowdsec_loc_conf(request: &Request) -> Option<&LocConfig> {
    Module::location_conf(request)
}

unsafe impl HttpModuleMainConf for Module {
    type MainConf = MainConfig;
}

unsafe impl HttpModuleLocationConf for Module {
    type LocationConf = LocConfig;
}

impl Merge for LocConfig {
    fn merge(&mut self, prev: &LocConfig) -> Result<(), MergeConfigError> {
        self.merge_from(prev).map_err(|_| MergeConfigError::NoValue)
    }
}

// Access phase handler - uses shared memory for ban and captcha checks
http_request_handler!(
    crowdsec_access_handler,
    |request: &mut ngx::http::Request| {
        let loc_conf = match Module::location_conf(request) {
            Some(c) => c,
            None => return Status::NGX_DECLINED,
        };
        let main_conf = match Module::main_conf(request) {
            Some(c) => c,
            None => return Status::NGX_DECLINED,
        };
        Status::from(handle_access(request, loc_conf, main_conf))
    }
);

impl HttpModule for Module {
    fn module() -> &'static ngx_module_t {
        unsafe { &*::core::ptr::addr_of!(ngx_http_crowdsec_module) }
    }

    unsafe extern "C" fn init_main_conf(cf: *mut ngx_conf_t, conf: *mut c_void) -> *mut c_char {
        let cf = unsafe { cf.as_ref().expect("cf") };
        let conf = unsafe { &*(conf as *mut MainConfig) };
        conf.validate_lapi_config(cf);
        core::ptr::null_mut()
    }

    unsafe extern "C" fn merge_loc_conf(
        cf: *mut ngx_conf_t,
        prev: *mut c_void,
        conf: *mut c_void,
    ) -> *mut c_char {
        let cf = unsafe { cf.as_ref().expect("cf") };
        let prev = unsafe { &*(prev as *mut LocConfig) };
        let conf = unsafe { &mut *(conf as *mut LocConfig) };

        match conf.merge_from(prev) {
            Ok(()) => {
                if conf.enabled == Some(true) {
                    if let Some(main) = Self::main_conf_mut(cf) {
                        main.enforcement_requested = true;
                    }
                }
                core::ptr::null_mut()
            }
            Err(msg) => cf.error("crowdsec", &ConfValueError(msg)),
        }
    }

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        unsafe {
            // Get the main configuration
            let conf = match Self::main_conf_mut(&mut *cf) {
                Some(c) => c,
                None => return Status::NGX_ERROR.into(),
            };

            // Initialize shared memory zone
            let shm_size = conf.shm_size.unwrap_or(DEFAULT_SHM_SIZE);

            if shm::init_decisions_zone(cf, &mut conf.decisions_zone, shm_size).is_err() {
                ngx::ngx_conf_log_error!(
                    ngx::ffi::NGX_LOG_ERR,
                    cf,
                    "crowdsec: failed to initialize shared memory zone"
                );
                return Status::NGX_ERROR.into();
            }

            if shm::init_metrics_shm_zone(cf).is_err() {
                ngx::ngx_conf_log_error!(
                    ngx::ffi::NGX_LOG_WARN,
                    cf,
                    "crowdsec: warning: failed to init crowdsec_metrics shared zone; counters disabled"
                );
            }

            if usage_metrics::init_usage_metrics_shm_zone(cf).is_err() {
                ngx::ngx_conf_log_error!(
                    ngx::ffi::NGX_LOG_WARN,
                    cf,
                    "crowdsec: warning: failed to init crowdsec_usage_metrics shared zone; LAPI metrics disabled"
                );
            }

            // Store configuration for worker init
            *GLOBAL_CONFIG.lock().unwrap_or_else(|e| e.into_inner()) =
                match (&conf.lapi_url, &conf.api_key) {
                    (Some(url), Some(key)) => Some(StreamClientConfig {
                        url: url.clone(),
                        api_key: key.clone(),
                        poll_interval_secs: conf.poll_interval_secs.unwrap_or(10),
                        timeout_secs: conf.lapi_timeout_secs.unwrap_or(30),
                        max_retries: conf.max_retries.unwrap_or(3),
                        retry_interval_secs: conf.retry_interval_secs.unwrap_or(5),
                        usage_metrics_interval_secs: conf
                            .usage_metrics_interval_secs
                            .unwrap_or(900),
                        fallback_remediation: conf.fallback_remediation_or_default(),
                    }),
                    _ => None,
                };
            appsec::configure(conf.appsec_url.as_ref().map(|url| {
                appsec::AppSecConfig {
                    url: url.clone(),
                    api_key: conf
                        .appsec_api_key
                        .clone()
                        .or_else(|| conf.api_key.clone())
                        .unwrap_or_default(),
                    timeout_ms: conf.appsec_timeout_ms.unwrap_or(1000),
                    max_body_size: conf.appsec_max_body_size.unwrap_or(10 * 1024 * 1024),
                    drop_unreadable_body: conf.appsec_drop_unreadable_body.unwrap_or(false),
                }
            }));

            // Register access phase handler
            let cf = &mut *cf;
            let cmcf = NgxHttpCoreModule::main_conf_mut(cf).expect("http core main conf");

            let handler = ngx_array_push(
                &mut cmcf.phases[ngx_http_phases_NGX_HTTP_ACCESS_PHASE as usize].handlers,
            ) as *mut ngx_http_handler_pt;

            if handler.is_null() {
                return Status::NGX_ERROR.into();
            }

            *handler = Some(crowdsec_access_handler);

            Status::NGX_OK.into()
        }
    }
}

/// Worker process initialization callback
///
/// Every worker starts a polling thread. Shared-memory CAS elects a single
/// LAPI poller; the other threads wait so they can take over after reload.
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_http_crowdsec_init_worker(_cycle: *mut ngx_cycle_t) -> ngx_int_t {
    let config = GLOBAL_CONFIG
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let Some(config) = config else {
        return NGX_OK as ngx_int_t;
    };

    // Every worker starts a polling thread. Only the elected poller talks to
    // LAPI; the others wait so they can take over after reload without a gap
    // and without two writers overlapping.
    let client = StreamClient::new(config);
    let handle = client.spawn_polling_thread();
    *POLLING_HANDLE.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);

    NGX_OK as ngx_int_t
}

/// Worker process exit callback
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ngx_http_crowdsec_exit_worker(_cycle: *mut ngx_cycle_t) {
    if shm::is_poller() {
        if let Some(config) = GLOBAL_CONFIG
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            usage_metrics::flush_on_shutdown(
                &config.url,
                &config.api_key,
                config.timeout_secs,
                config.usage_metrics_interval_secs,
            );
        }
    }

    // Join the polling/standby thread before nginx destroys the cycle pool.
    if let Some((handle, running)) = POLLING_HANDLE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
    {
        running.store(false, Ordering::SeqCst);
        let _ = handle.join();
    }
    shm::release_poller();
}

// Module context for HTTP module registration
static NGX_HTTP_CROWDSEC_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: None,
    postconfiguration: Some(Module::postconfiguration),
    create_main_conf: Some(Module::create_main_conf),
    init_main_conf: Some(Module::init_main_conf),
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: Some(Module::create_loc_conf),
    merge_loc_conf: Some(Module::merge_loc_conf),
};

// The module definition
#[used]
#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
pub static mut ngx_http_crowdsec_module: ngx_module_t = ngx_module_t {
    ctx: std::ptr::addr_of!(NGX_HTTP_CROWDSEC_MODULE_CTX) as _,
    commands: unsafe { &NGX_HTTP_CROWDSEC_COMMANDS[0] as *const _ as *mut _ },
    type_: NGX_HTTP_MODULE as _,
    init_process: Some(ngx_http_crowdsec_init_worker),
    exit_process: Some(ngx_http_crowdsec_exit_worker),
    ..ngx_module_t::default()
};

// Export modules for dynamic loading
#[cfg(feature = "export-modules")]
ngx_modules!(ngx_http_crowdsec_module);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::captcha::CookieSecure;
    use crate::config::{BanActionMode, FallbackRemediation, UnenforceableAction};

    #[test]
    fn location_merge_inherits_cookie_security() {
        let parent = LocConfig {
            captcha_cookie_secure: Some(CookieSecure::On),
            ..Default::default()
        };
        let mut child = LocConfig::default();

        child.merge(&parent).unwrap();

        assert_eq!(child.captcha_cookie_secure, Some(CookieSecure::On));
    }

    #[test]
    fn merge_allows_crowdsec_on_without_ban_template() {
        let parent = LocConfig::default();
        let mut child = LocConfig {
            enabled: Some(true),
            ..Default::default()
        };

        assert!(child.merge(&parent).is_ok());
        assert_eq!(child.ban_status_code(), 403);
    }

    #[test]
    fn merge_requires_captcha_template_when_unenforceable_block() {
        let parent = LocConfig::default();
        let mut child = LocConfig {
            enabled: Some(true),
            captcha_provider: Some(crate::captcha::CaptchaProvider::Turnstile),
            captcha_site_key: Some("site".to_string()),
            captcha_secret_key: Some("secret".to_string()),
            captcha_signing_key: Some([1u8; 32]),
            unenforceable_action: Some(UnenforceableAction::Block),
            ..Default::default()
        };

        assert!(child.merge(&parent).is_err());
    }

    #[test]
    fn merge_allows_captcha_keys_without_template_when_unenforceable_allow() {
        let parent = LocConfig::default();
        let mut child = LocConfig {
            enabled: Some(true),
            captcha_provider: Some(crate::captcha::CaptchaProvider::Turnstile),
            captcha_site_key: Some("site".to_string()),
            captcha_secret_key: Some("secret".to_string()),
            captcha_signing_key: Some([1u8; 32]),
            unenforceable_action: Some(UnenforceableAction::Allow),
            ..Default::default()
        };

        assert!(child.merge(&parent).is_ok());
    }

    #[test]
    fn fallback_remediation_resolve_unknown_type() {
        assert_eq!(
            FallbackRemediation::Allow.resolve_unknown_type("mfa"),
            None
        );
        assert_eq!(
            FallbackRemediation::Ban.resolve_unknown_type("mfa"),
            Some(crate::shm::DecisionType::Ban)
        );
        assert_eq!(
            FallbackRemediation::Captcha.resolve_unknown_type("mfa"),
            Some(crate::shm::DecisionType::Captcha)
        );
        assert_eq!(
            FallbackRemediation::Ban.resolve_unknown_type("ban"),
            Some(crate::shm::DecisionType::Ban)
        );
    }

    #[test]
    fn ban_status_code_rejects_non_error_codes() {
        let loc = LocConfig {
            ban_status: Some(200),
            ..Default::default()
        };
        assert_eq!(loc.ban_status_code(), 403);
        let loc = LocConfig {
            ban_status: Some(429),
            ..Default::default()
        };
        assert_eq!(loc.ban_status_code(), 429);
    }

    #[test]
    fn merge_allows_redirect_without_ban_template() {
        let parent = LocConfig::default();
        let mut child = LocConfig {
            enabled: Some(true),
            ban_action: Some(BanActionMode::Redirect),
            ban_redirect_url: Some("https://example.com/blocked".to_string()),
            ..Default::default()
        };

        assert!(child.merge(&parent).is_ok());
    }

    #[test]
    fn merge_does_not_inherit_metrics_enabled() {
        let parent = LocConfig {
            metrics_enabled: Some(true),
            ..Default::default()
        };
        let mut child = LocConfig::default();
        child.merge(&parent).unwrap();
        assert_eq!(child.metrics_enabled, None);
    }
}
