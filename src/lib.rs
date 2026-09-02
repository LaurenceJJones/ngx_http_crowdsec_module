//! CrowdSec NGINX Module
//!
//! This module integrates NGINX with CrowdSec LAPI to enforce IP ban and captcha decisions.
//! It uses the stream mode to efficiently sync decisions and checks incoming
//! requests against a shared memory decision cache accessible by all workers.

mod appsec;
mod captcha;
mod config;
mod handler;
mod metrics;
mod realip;
pub mod shm;
mod stream;
mod template;
mod types;

use config::{DEFAULT_SHM_SIZE, LocConfig, MainConfig, NGX_HTTP_CROWDSEC_COMMANDS};
use handler::handle_access;
use ngx::core::Status;
use ngx::ffi::{
    NGX_HTTP_MODULE, NGX_OK, ngx_array_push, ngx_conf_t, ngx_cycle_t, ngx_http_handler_pt,
    ngx_http_module_t, ngx_http_phases_NGX_HTTP_ACCESS_PHASE, ngx_int_t, ngx_module_t, ngx_str_t,
};
use ngx::http::{
    HttpModule, HttpModuleLocationConf, HttpModuleMainConf, Merge, MergeConfigError,
    NgxHttpCoreModule,
};
use ngx::{http_request_handler, ngx_modules, ngx_string};
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

unsafe impl HttpModuleMainConf for Module {
    type MainConf = MainConfig;
}

unsafe impl HttpModuleLocationConf for Module {
    type LocationConf = LocConfig;
}

impl Merge for LocConfig {
    fn merge(&mut self, prev: &LocConfig) -> Result<(), MergeConfigError> {
        if self.enabled.is_none() {
            self.enabled = prev.enabled;
        }
        if self.ban_template.is_none() {
            self.ban_template = prev.ban_template.clone();
        }
        if self.ban_action.is_none() {
            self.ban_action = prev.ban_action;
        }
        if self.ban_redirect_url.is_none() {
            self.ban_redirect_url = prev.ban_redirect_url.clone();
        }
        if self.ban_redirect_code.is_none() {
            self.ban_redirect_code = prev.ban_redirect_code;
        }
        if self.captcha_template.is_none() {
            self.captcha_template = prev.captcha_template.clone();
        }
        // Captcha configuration inheritance
        if self.captcha_provider.is_none() {
            self.captcha_provider = prev.captcha_provider;
        }
        if self.captcha_site_key.is_none() {
            self.captcha_site_key = prev.captcha_site_key.clone();
        }
        if self.captcha_secret_key.is_none() {
            self.captcha_secret_key = prev.captcha_secret_key.clone();
        }
        if self.captcha_signing_key.is_none() {
            self.captcha_signing_key = prev.captcha_signing_key;
        }
        if self.captcha_cookie_name.is_none() {
            self.captcha_cookie_name = prev.captcha_cookie_name.clone();
        }
        if self.captcha_expiry_secs.is_none() {
            self.captcha_expiry_secs = prev.captcha_expiry_secs;
        }
        if self.captcha_fail_open.is_none() {
            self.captcha_fail_open = prev.captcha_fail_open;
        }
        if self.captcha_bind_ip.is_none() {
            self.captcha_bind_ip = prev.captcha_bind_ip;
        }
        if self.captcha_cookie_secure.is_none() {
            self.captcha_cookie_secure = prev.captcha_cookie_secure;
        }
        if self.appsec_enabled.is_none() {
            self.appsec_enabled = prev.appsec_enabled;
        }
        if self.appsec_failure_action.is_none() {
            self.appsec_failure_action = prev.appsec_failure_action;
        }
        if self.bot_challenge_enabled.is_none() {
            self.bot_challenge_enabled = prev.bot_challenge_enabled;
        }
        if self.metrics_enabled.is_none() {
            self.metrics_enabled = prev.metrics_enabled;
        }
        Ok(())
    }
}

// Access phase handler - uses shared memory for ban and captcha checks
http_request_handler!(
    crowdsec_access_handler,
    |request: &mut ngx::http::Request| {
        let loc_conf = Module::location_conf(request).expect("module config is none");
        let main_conf = Module::main_conf(request).expect("crowdsec main conf missing");
        let result = handle_access(request, loc_conf, main_conf);
        Status::from(result)
    }
);

impl HttpModule for Module {
    fn module() -> &'static ngx_module_t {
        unsafe { &*::core::ptr::addr_of!(ngx_http_crowdsec_module) }
    }

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        unsafe {
            // Get the main configuration
            let conf = match Self::main_conf(&*cf) {
                Some(c) => c,
                None => return Status::NGX_ERROR.into(),
            };

            // Initialize shared memory zone
            let shm_size = conf.shm_size.unwrap_or(DEFAULT_SHM_SIZE);
            let shm_name: ngx_str_t = ngx_string!("crowdsec_decisions");

            if shm::init_shm_zone(cf, &shm_name, shm_size).is_err() {
                eprintln!("crowdsec: failed to initialize shared memory zone");
                return Status::NGX_ERROR.into();
            }

            if shm::init_metrics_shm_zone(cf).is_err() {
                eprintln!(
                    "crowdsec: warning: failed to init crowdsec_metrics shared zone; counters disabled"
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
/// Only the first worker to call this will start the polling thread.
/// All workers share the same shared memory for decision data.
/// Uses atomic CAS in shared memory to elect a single poller across all workers.
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

    // Try to claim poller role using atomic CAS in shared memory
    // Only one worker across all processes will succeed
    if !shm::try_become_poller() {
        // Another worker already claimed the poller role
        return NGX_OK as ngx_int_t;
    }

    // This worker won the election - start polling thread.
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
    // Only the poller worker needs to stop the thread
    if !shm::is_poller() {
        return;
    }

    // Signal polling thread to stop
    if let Some((handle, running)) = POLLING_HANDLE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
    {
        running.store(false, Ordering::SeqCst);
        // Don't join - let the thread terminate naturally
        let _ = handle;
    }
    shm::release_poller();
}

// Module context for HTTP module registration
static NGX_HTTP_CROWDSEC_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: None,
    postconfiguration: Some(Module::postconfiguration),
    create_main_conf: Some(Module::create_main_conf),
    init_main_conf: None,
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
ngx_modules!(ngx_http_crowdsec_module);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::captcha::CookieSecure;

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
}
