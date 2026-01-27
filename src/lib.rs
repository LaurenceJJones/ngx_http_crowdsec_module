//! CrowdSec NGINX Module
//!
//! This module integrates NGINX with CrowdSec LAPI to enforce IP ban decisions.
//! It uses the stream mode to efficiently sync decisions and checks incoming
//! requests against a shared memory decision cache accessible by all workers.

mod config;
mod handler;
pub mod shm;
mod stream;
mod template;
mod types;

// Keep store module for backwards compatibility but it's not used with shm
#[allow(dead_code)]
mod store;

use config::{LocConfig, MainConfig, DEFAULT_SHM_SIZE, NGX_HTTP_CROWDSEC_COMMANDS};
use handler::handle_access;
use ngx::core::Status;
use ngx::ffi::{
    ngx_array_push, ngx_conf_t, ngx_cycle_t, ngx_http_handler_pt, ngx_http_module_t,
    ngx_http_phases_NGX_HTTP_ACCESS_PHASE, ngx_int_t, ngx_module_t, ngx_str_t, NGX_HTTP_MODULE,
    NGX_OK,
};
use ngx::http::{
    HttpModule, HttpModuleLocationConf, HttpModuleMainConf, Merge, MergeConfigError,
    NgxHttpCoreModule,
};
use ngx::{http_request_handler, ngx_modules, ngx_string};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use stream::{StreamClient, StreamClientConfig};

/// Global configuration extracted at postconfiguration
static mut GLOBAL_CONFIG: Option<StreamClientConfig> = None;

/// Handle to the polling thread (for potential cleanup)
static mut POLLING_HANDLE: Option<(JoinHandle<()>, Arc<AtomicBool>)> = None;

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
        Ok(())
    }
}

// Access phase handler - uses shared memory for ban checks
http_request_handler!(crowdsec_access_handler, |request: &mut ngx::http::Request| {
    let loc_conf = Module::location_conf(request).expect("module config is none");
    let result = handle_access(request, loc_conf);
    Status::from(result)
});

impl HttpModule for Module {
    fn module() -> &'static ngx_module_t {
        unsafe { &*::core::ptr::addr_of!(ngx_http_crowdsec_module) }
    }

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
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

        // Store configuration for worker init
        if let (Some(url), Some(key)) = (&conf.lapi_url, &conf.api_key) {
            GLOBAL_CONFIG = Some(StreamClientConfig {
                url: url.clone(),
                api_key: key.clone(),
                poll_interval_secs: 10,
                timeout_secs: 30,
                max_retries: conf.max_retries.unwrap_or(3),
                retry_interval_secs: conf.retry_interval_secs.unwrap_or(5),
            });
        }

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

/// Worker process initialization callback
///
/// Only the first worker to call this will start the polling thread.
/// All workers share the same shared memory for decision data.
/// Uses atomic CAS in shared memory to elect a single poller across all workers.
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[no_mangle]
pub unsafe extern "C" fn ngx_http_crowdsec_init_worker(_cycle: *mut ngx_cycle_t) -> ngx_int_t {
    // Try to claim poller role using atomic CAS in shared memory
    // Only one worker across all processes will succeed
    if !shm::try_become_poller() {
        // Another worker already claimed the poller role
        return NGX_OK as ngx_int_t;
    }

    // This worker won the election - start polling thread
    // Clone config since we need GLOBAL_CONFIG to remain for potential reload
    if let Some(ref config) = GLOBAL_CONFIG {
        let client = StreamClient::new(config.clone());
        let handle = client.spawn_polling_thread();
        POLLING_HANDLE = Some(handle);
    }

    NGX_OK as ngx_int_t
}

/// Worker process exit callback
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[no_mangle]
pub unsafe extern "C" fn ngx_http_crowdsec_exit_worker(_cycle: *mut ngx_cycle_t) {
    // Only the poller worker needs to stop the thread
    if !shm::is_poller() {
        return;
    }

    // Signal polling thread to stop
    if let Some((handle, running)) = POLLING_HANDLE.take() {
        running.store(false, Ordering::SeqCst);
        // Don't join - let the thread terminate naturally
        let _ = handle;
    }
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
#[no_mangle]
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
