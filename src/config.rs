use crate::captcha::{CaptchaConfig, CaptchaProvider, CookieSecure};
use crate::template::BanTemplate;
use ngx::core::{NGX_CONF_ERROR, NGX_CONF_OK, NgxStr};
use ngx::ffi::{
    NGX_CONF_TAKE1, NGX_HTTP_LOC_CONF_OFFSET, NGX_HTTP_MAIN_CONF, NGX_HTTP_MAIN_CONF_OFFSET,
    NGX_HTTP_SRV_CONF, ngx_command_t, ngx_conf_t, ngx_str_t, ngx_uint_t,
};
use ngx::ngx_string;
use std::collections::HashMap;
use std::os::raw::{c_char, c_void};
use std::sync::{Arc, LazyLock, Mutex};

/// Default shared memory size (1MB)
pub const DEFAULT_SHM_SIZE: usize = 1024 * 1024;

/// Main configuration (http block level) for CrowdSec module
#[derive(Debug, Default)]
pub struct MainConfig {
    /// LAPI URL (e.g., http://127.0.0.1:8080)
    pub lapi_url: Option<String>,
    /// Bouncer API key
    pub api_key: Option<String>,
    /// Maximum number of retries for initial connection (default: 3)
    pub max_retries: Option<u32>,
    /// Retry interval in seconds between retry attempts (default: 5)
    pub retry_interval_secs: Option<u64>,
    /// Shared memory size in bytes (default: 1MB)
    pub shm_size: Option<usize>,
}

/// Location configuration for CrowdSec module
/// All fields use Option to support inheritance from parent contexts
#[derive(Debug, Default, Clone)]
pub struct LocConfig {
    /// Whether CrowdSec checking is enabled for this location
    pub enabled: Option<bool>,
    /// Ban template for rendering 403 responses
    pub ban_template: Option<Arc<BanTemplate>>,
    /// Captcha template for rendering captcha challenge pages
    pub captcha_template: Option<Arc<BanTemplate>>,

    // === Captcha configuration (inheritable at server/location level) ===
    /// Captcha provider (hcaptcha, turnstile, recaptcha)
    pub captcha_provider: Option<CaptchaProvider>,
    /// Public site key for the captcha widget
    pub captcha_site_key: Option<String>,
    /// Secret key for server-side verification
    pub captcha_secret_key: Option<String>,
    /// HMAC signing key for JWT tokens (32 bytes)
    pub captcha_signing_key: Option<[u8; 32]>,
    /// Cookie name for storing the captcha session
    pub captcha_cookie_name: Option<String>,
    /// Session expiry in seconds
    pub captcha_expiry_secs: Option<u64>,
    /// Whether to fail open when provider is unreachable
    pub captcha_fail_open: Option<bool>,
    /// Whether to bind JWT to client IP
    pub captcha_bind_ip: Option<bool>,
    /// Cookie Secure flag setting (auto/on/off)
    pub captcha_cookie_secure: Option<CookieSecure>,
}

impl LocConfig {
    /// Build a CaptchaConfig from the merged location config
    /// Returns None if captcha is not fully configured
    pub fn captcha_config(&self) -> Option<CaptchaConfig> {
        // Check if we have the minimum required fields
        let provider = self.captcha_provider?;
        let site_key = self.captcha_site_key.clone()?;
        let secret_key = self.captcha_secret_key.clone()?;
        let signing_key = self.captcha_signing_key?;

        // signing_key must not be all zeros
        if signing_key == [0u8; 32] {
            return None;
        }

        Some(CaptchaConfig {
            provider,
            site_key,
            secret_key,
            signing_key,
            cookie_name: self
                .captcha_cookie_name
                .clone()
                .unwrap_or_else(|| "crowdsec_captcha".to_string()),
            expiry_secs: self.captcha_expiry_secs.unwrap_or(3600),
            fail_open: self.captcha_fail_open.unwrap_or(true),
            bind_ip: self.captcha_bind_ip.unwrap_or(true),
            cookie_secure: self.captcha_cookie_secure.unwrap_or(CookieSecure::Auto),
        })
    }
}

/// Directive handler for `crowdsec on|off;`
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_enable(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut LocConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        // args[0] is the directive name, args[1] is the value
        let value = *args.add(1);

        let value_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => {
                // Invalid UTF-8
                return NGX_CONF_ERROR;
            }
        };

        // Mark as explicitly set
        conf.enabled = Some(value_str.eq_ignore_ascii_case("on"));
    }

    NGX_CONF_OK
}

/// Directive handler for `crowdsec_url <url>;`
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_url(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut MainConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let value = *args.add(1);

        let value_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => {
                return NGX_CONF_ERROR;
            }
        };

        conf.lapi_url = Some(value_str.to_string());
    }

    NGX_CONF_OK
}

/// Directive handler for `crowdsec_api_key <key>;`
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_api_key(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut MainConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let value = *args.add(1);

        let value_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => {
                return NGX_CONF_ERROR;
            }
        };

        conf.api_key = Some(value_str.to_string());
    }

    NGX_CONF_OK
}

/// Directive handler for `crowdsec_max_retries <number>;`
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_max_retries(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut MainConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let value = *args.add(1);

        let value_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => {
                return NGX_CONF_ERROR;
            }
        };

        match value_str.parse::<u32>() {
            Ok(n) if n > 0 && n <= 100 => {
                conf.max_retries = Some(n);
            }
            _ => {
                return NGX_CONF_ERROR;
            }
        }
    }

    NGX_CONF_OK
}

/// Directive handler for `crowdsec_retry_interval <seconds>;`
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_retry_interval(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut MainConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let value = *args.add(1);

        let value_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => {
                return NGX_CONF_ERROR;
            }
        };

        match value_str.parse::<u64>() {
            Ok(n) if n > 0 && n <= 3600 => {
                conf.retry_interval_secs = Some(n);
            }
            _ => {
                return NGX_CONF_ERROR;
            }
        }
    }

    NGX_CONF_OK
}

/// Directive handler for `crowdsec_shm_size <size>;`
/// Size can be specified as bytes, or with k/m suffix (e.g., 1m, 512k)
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_shm_size(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut MainConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let value = *args.add(1);

        let value_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => {
                return NGX_CONF_ERROR;
            }
        };

        // Parse size with optional k/m/g suffix
        let size = parse_size(value_str);
        match size {
            Some(s) if s >= 64 * 1024 => {
                // Minimum 64KB
                conf.shm_size = Some(s);
            }
            _ => {
                eprintln!("crowdsec: invalid shm_size '{}' (minimum 64k)", value_str);
                return NGX_CONF_ERROR;
            }
        }
    }

    NGX_CONF_OK
}

/// Parse a size string with optional k/m/g suffix
fn parse_size(s: &str) -> Option<usize> {
    let s = s.trim().to_lowercase();
    if s.is_empty() {
        return None;
    }

    let (num_str, multiplier) = if s.ends_with('k') {
        (&s[..s.len() - 1], 1024)
    } else if s.ends_with('m') {
        (&s[..s.len() - 1], 1024 * 1024)
    } else if s.ends_with('g') {
        (&s[..s.len() - 1], 1024 * 1024 * 1024)
    } else {
        (s.as_str(), 1)
    };

    num_str.parse::<usize>().ok().map(|n| n * multiplier)
}

/// Template cache to avoid re-parsing the same file multiple times
/// Stores Arc<BanTemplate> so all locations using the same template file share one instance
/// This is safe because configuration parsing happens in a single thread
static TEMPLATE_CACHE: LazyLock<Mutex<HashMap<String, Arc<BanTemplate>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Directive handler for `crowdsec_ban_template <path>;`
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_ban_template(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut LocConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let value = *args.add(1);

        let path_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => {
                return NGX_CONF_ERROR;
            }
        };

        // Check cache first to avoid re-parsing the same file
        let mut cache = TEMPLATE_CACHE.lock().unwrap();

        let template = match cache.get(path_str) {
            Some(cached_template) => {
                // Use cached Arc (clone just increments ref count)
                Arc::clone(cached_template)
            }
            None => {
                // Load and parse the template file
                match BanTemplate::from_file(path_str) {
                    Ok(template) => {
                        // Wrap in Arc and cache for future use
                        let arc_template = Arc::new(template);
                        cache.insert(path_str.to_string(), Arc::clone(&arc_template));
                        arc_template
                    }
                    Err(e) => {
                        // Log error - in production would use ngx::log
                        eprintln!(
                            "crowdsec: failed to load ban template from {}: {}",
                            path_str, e
                        );
                        return NGX_CONF_ERROR;
                    }
                }
            }
        };

        conf.ban_template = Some(template);
    }

    NGX_CONF_OK
}

/// Directive handler for `crowdsec_captcha_provider hcaptcha|turnstile|recaptcha;`
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_captcha_provider(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut LocConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let value = *args.add(1);

        let value_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => return NGX_CONF_ERROR,
        };

        let provider = match CaptchaProvider::from_str(value_str) {
            Some(p) => p,
            None => {
                eprintln!(
                    "crowdsec: invalid captcha provider '{}' (expected: hcaptcha, turnstile, recaptcha)",
                    value_str
                );
                return NGX_CONF_ERROR;
            }
        };

        conf.captcha_provider = Some(provider);
    }

    NGX_CONF_OK
}

/// Directive handler for `crowdsec_captcha_site_key <key>;`
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_captcha_site_key(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut LocConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let value = *args.add(1);

        let value_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => return NGX_CONF_ERROR,
        };

        conf.captcha_site_key = Some(value_str.to_string());
    }

    NGX_CONF_OK
}

/// Directive handler for `crowdsec_captcha_secret_key <key>;`
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_captcha_secret_key(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut LocConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let value = *args.add(1);

        let value_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => return NGX_CONF_ERROR,
        };

        conf.captcha_secret_key = Some(value_str.to_string());
    }

    NGX_CONF_OK
}

/// Directive handler for `crowdsec_captcha_signing_key <hex-key>;`
/// Key must be 64 hex characters (32 bytes)
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_captcha_signing_key(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut LocConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let value = *args.add(1);

        let value_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => return NGX_CONF_ERROR,
        };

        // Parse hex string to bytes
        let key = match parse_hex_key(value_str) {
            Some(k) => k,
            None => {
                eprintln!(
                    "crowdsec: invalid signing key (expected 64 hex characters, got {} chars)",
                    value_str.len()
                );
                return NGX_CONF_ERROR;
            }
        };

        conf.captcha_signing_key = Some(key);
    }

    NGX_CONF_OK
}

/// Parse a 64-character hex string to a 32-byte key
fn parse_hex_key(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }

    let mut key = [0u8; 32];
    for i in 0..32 {
        let byte_str = &hex[i * 2..i * 2 + 2];
        key[i] = u8::from_str_radix(byte_str, 16).ok()?;
    }
    Some(key)
}

/// Directive handler for `crowdsec_captcha_cookie_name <name>;`
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_captcha_cookie_name(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut LocConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let value = *args.add(1);

        let value_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => return NGX_CONF_ERROR,
        };

        conf.captcha_cookie_name = Some(value_str.to_string());
    }

    NGX_CONF_OK
}

/// Directive handler for `crowdsec_captcha_expiry <seconds>;`
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_captcha_expiry(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut LocConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let value = *args.add(1);

        let value_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => return NGX_CONF_ERROR,
        };

        match value_str.parse::<u64>() {
            Ok(n) if n > 0 && n <= 86400 * 30 => {
                // Max 30 days
                conf.captcha_expiry_secs = Some(n);
            }
            _ => {
                eprintln!("crowdsec: invalid captcha expiry (1-2592000 seconds)");
                return NGX_CONF_ERROR;
            }
        }
    }

    NGX_CONF_OK
}

/// Directive handler for `crowdsec_captcha_fail_open on|off;`
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_captcha_fail_open(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut LocConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let value = *args.add(1);

        let value_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => return NGX_CONF_ERROR,
        };

        conf.captcha_fail_open = Some(value_str.eq_ignore_ascii_case("on"));
    }

    NGX_CONF_OK
}

/// Directive handler for `crowdsec_captcha_bind_ip on|off;`
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_captcha_bind_ip(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut LocConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let value = *args.add(1);

        let value_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => return NGX_CONF_ERROR,
        };

        conf.captcha_bind_ip = Some(value_str.eq_ignore_ascii_case("on"));
    }

    NGX_CONF_OK
}

/// Directive handler for `crowdsec_captcha_cookie_secure auto|on|off;`
///
/// Controls the Secure flag on the captcha session cookie:
/// - `auto` (default): Detect based on connection SSL or X-Forwarded-Proto header
/// - `on`: Always set Secure flag (use when behind TLS-terminating proxy)
/// - `off`: Never set Secure flag (for testing only)
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_captcha_cookie_secure(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut LocConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let value = *args.add(1);

        let value_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => return NGX_CONF_ERROR,
        };

        match CookieSecure::from_str(value_str) {
            Some(secure) => conf.captcha_cookie_secure = Some(secure),
            None => {
                eprintln!(
                    "crowdsec: invalid cookie_secure value '{}', expected auto|on|off",
                    value_str
                );
                return NGX_CONF_ERROR;
            }
        }
    }

    NGX_CONF_OK
}

/// Directive handler for `crowdsec_captcha_template <path>;`
///
/// # Safety
/// This function is called by NGINX and must follow C calling conventions.
#[unsafe(no_mangle)]
pub extern "C" fn ngx_http_crowdsec_set_captcha_template(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    let conf = unsafe { &mut *(conf as *mut LocConfig) };

    unsafe {
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let value = *args.add(1);

        let path_str = match NgxStr::from_ngx_str(value).to_str() {
            Ok(s) => s,
            Err(_) => return NGX_CONF_ERROR,
        };

        // Check cache first (reuse same cache as ban templates)
        let mut cache = TEMPLATE_CACHE.lock().unwrap();

        let template = match cache.get(path_str) {
            Some(cached_template) => Arc::clone(cached_template),
            None => match BanTemplate::from_file(path_str) {
                Ok(template) => {
                    let arc_template = Arc::new(template);
                    cache.insert(path_str.to_string(), Arc::clone(&arc_template));
                    arc_template
                }
                Err(e) => {
                    eprintln!(
                        "crowdsec: failed to load captcha template from {}: {}",
                        path_str, e
                    );
                    return NGX_CONF_ERROR;
                }
            },
        };

        conf.captcha_template = Some(template);
    }

    NGX_CONF_OK
}

/// Generate the commands array for NGINX module registration
///
/// Returns the static commands array for the module.
/// The array is null-terminated with an empty command.
#[rustfmt::skip]
pub static mut NGX_HTTP_CROWDSEC_COMMANDS: [ngx_command_t; 18] = [
    // crowdsec on|off; - enable/disable at location level
    ngx_command_t {
        name: ngx_string!("crowdsec"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | ngx::ffi::NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_enable),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // crowdsec_url <url>; - LAPI URL at main config level
    ngx_command_t {
        name: ngx_string!("crowdsec_url"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_url),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // crowdsec_api_key <key>; - API key at main config level
    ngx_command_t {
        name: ngx_string!("crowdsec_api_key"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_api_key),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // crowdsec_max_retries <number>; - Maximum retries for initial connection (default: 3)
    ngx_command_t {
        name: ngx_string!("crowdsec_max_retries"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_max_retries),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // crowdsec_retry_interval <seconds>; - Retry interval in seconds (default: 5)
    ngx_command_t {
        name: ngx_string!("crowdsec_retry_interval"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_retry_interval),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // crowdsec_shm_size <size>; - Shared memory size (default: 1m)
    ngx_command_t {
        name: ngx_string!("crowdsec_shm_size"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_shm_size),
        conf: NGX_HTTP_MAIN_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // crowdsec_ban_template <path>; - Ban template file path (http, server, location level)
    ngx_command_t {
        name: ngx_string!("crowdsec_ban_template"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | ngx::ffi::NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_ban_template),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // ===== Captcha directives (inheritable at http/server/location levels) =====
    // crowdsec_captcha_provider hcaptcha|turnstile|recaptcha;
    ngx_command_t {
        name: ngx_string!("crowdsec_captcha_provider"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | ngx::ffi::NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_captcha_provider),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // crowdsec_captcha_site_key <key>;
    ngx_command_t {
        name: ngx_string!("crowdsec_captcha_site_key"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | ngx::ffi::NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_captcha_site_key),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // crowdsec_captcha_secret_key <key>;
    ngx_command_t {
        name: ngx_string!("crowdsec_captcha_secret_key"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | ngx::ffi::NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_captcha_secret_key),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // crowdsec_captcha_signing_key <hex-key>;
    ngx_command_t {
        name: ngx_string!("crowdsec_captcha_signing_key"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | ngx::ffi::NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_captcha_signing_key),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // crowdsec_captcha_cookie_name <name>;
    ngx_command_t {
        name: ngx_string!("crowdsec_captcha_cookie_name"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | ngx::ffi::NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_captcha_cookie_name),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // crowdsec_captcha_expiry <seconds>;
    ngx_command_t {
        name: ngx_string!("crowdsec_captcha_expiry"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | ngx::ffi::NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_captcha_expiry),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // crowdsec_captcha_fail_open on|off;
    ngx_command_t {
        name: ngx_string!("crowdsec_captcha_fail_open"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | ngx::ffi::NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_captcha_fail_open),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // crowdsec_captcha_bind_ip on|off;
    ngx_command_t {
        name: ngx_string!("crowdsec_captcha_bind_ip"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | ngx::ffi::NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_captcha_bind_ip),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // crowdsec_captcha_cookie_secure auto|on|off;
    ngx_command_t {
        name: ngx_string!("crowdsec_captcha_cookie_secure"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | ngx::ffi::NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_captcha_cookie_secure),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // crowdsec_captcha_template <path>; (location-level)
    ngx_command_t {
        name: ngx_string!("crowdsec_captcha_template"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | ngx::ffi::NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_crowdsec_set_captcha_template),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    // Null terminator
    ngx_command_t::empty(),
];
