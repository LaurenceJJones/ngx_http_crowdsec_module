use crate::captcha::send_captcha_page;
use crate::lapi;
use crate::config::{AppSecFailureAction, LocConfig, MainConfig};
use crate::handler::{HandlerResult, get_client_ip, send_raw_response};
use crate::request_body::{
    APPSEC_BODY_CTX_MAGIC, BodyExtractResult, extract_request_body_limited, finalize_allow,
    get_content_length, has_request_body, initiate_body_read, request_body_buffered,
};
use ngx::ffi::{ngx_http_finalize_request, ngx_http_request_t, ngx_int_t};
use ngx::http::{HTTPStatus, Request};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::ptr;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

#[derive(Clone)]
pub struct AppSecConfig {
    pub url: String,
    pub api_key: String,
    pub timeout_ms: u64,
    pub max_body_size: usize,
    pub drop_unreadable_body: bool,
}

static CONFIG: Mutex<Option<AppSecConfig>> = Mutex::new(None);
static AGENT: LazyLock<ureq::Agent> = LazyLock::new(lapi::agent);

/// Stored in the module request context while AppSec waits for the body.
#[repr(C)]
pub struct AppSecBodyContext {
    pub magic: u32,
    pub client_ip: [u8; 64],
    pub client_ip_len: usize,
    pub failure_action: u8,
    pub internal_challenge: u8,
    pub bot_challenge: u8,
    /// Set while the ACCESS handler still owns the request (synchronous body read).
    pub defer_finalize: u8,
    /// Result from the body callback when `defer_finalize` is set.
    pub stored_result: u8,
}

#[repr(u8)]
#[derive(PartialEq, Eq, Copy, Clone)]
enum StoredAppSecResult {
    Unset = 0,
    Declined = 1,
    Forbidden = 2,
    Done = 3,
    Error = 4,
}

impl StoredAppSecResult {
    fn from_handler_result(result: HandlerResult) -> Self {
        match result {
            HandlerResult::Declined => Self::Declined,
            HandlerResult::Forbidden => Self::Forbidden,
            HandlerResult::Done => Self::Done,
            HandlerResult::Error => Self::Error,
            HandlerResult::CaptchaPending | HandlerResult::AppSecPending => Self::Error,
        }
    }

    fn into_handler_result(self) -> HandlerResult {
        match self {
            Self::Declined => HandlerResult::Declined,
            Self::Forbidden => HandlerResult::Forbidden,
            Self::Done => HandlerResult::Done,
            Self::Unset | Self::Error => HandlerResult::Error,
        }
    }

    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Unset),
            1 => Some(Self::Declined),
            2 => Some(Self::Forbidden),
            3 => Some(Self::Done),
            4 => Some(Self::Error),
            _ => None,
        }
    }
}

impl AppSecBodyContext {
    fn new(
        ip: &IpAddr,
        failure_action: AppSecFailureAction,
        internal_challenge: bool,
        bot_challenge: bool,
    ) -> Self {
        let ip_str = ip.to_string();
        let ip_bytes = ip_str.as_bytes();
        let mut client_ip = [0u8; 64];
        let ip_len = ip_bytes.len().min(63);
        client_ip[..ip_len].copy_from_slice(&ip_bytes[..ip_len]);
        Self {
            magic: APPSEC_BODY_CTX_MAGIC,
            client_ip,
            client_ip_len: ip_len,
            failure_action: match failure_action {
                AppSecFailureAction::Passthrough => 0,
                AppSecFailureAction::Deny => 1,
            },
            internal_challenge: u8::from(internal_challenge),
            bot_challenge: u8::from(bot_challenge),
            defer_finalize: 1,
            stored_result: StoredAppSecResult::Unset as u8,
        }
    }

    fn failure_action(&self) -> AppSecFailureAction {
        match self.failure_action {
            1 => AppSecFailureAction::Deny,
            _ => AppSecFailureAction::Passthrough,
        }
    }

    fn client_ip(&self) -> Option<IpAddr> {
        std::str::from_utf8(&self.client_ip[..self.client_ip_len])
            .ok()?
            .parse()
            .ok()
    }

    fn store_result(&mut self, result: HandlerResult) {
        self.stored_result = StoredAppSecResult::from_handler_result(result) as u8;
    }

    fn take_result(&self) -> Option<HandlerResult> {
        match StoredAppSecResult::from_u8(self.stored_result)? {
            StoredAppSecResult::Unset => None,
            stored => Some(stored.into_handler_result()),
        }
    }

    /// Sync reads defer to the ACCESS handler; async reads finalize in the callback.
    unsafe fn finish(
        &self,
        main_r: *mut ngx_http_request_t,
        ctx_ptr: *mut *mut std::ffi::c_void,
        result: HandlerResult,
    ) {
        unsafe {
            if self.defer_finalize != 0 {
                let ctx_mut = *ctx_ptr as *mut AppSecBodyContext;
                if !ctx_mut.is_null() {
                    (*ctx_mut).store_result(result);
                }
                return;
            }
            *ctx_ptr = std::ptr::null_mut();
            finalize_precontent_result(main_r, result);
        }
    }
}

pub fn configure(config: Option<AppSecConfig>) {
    *CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = config;
}

#[derive(Debug, Deserialize)]
struct Envelope {
    action: String,
    #[serde(default)]
    http_status: u16,
    #[serde(default)]
    user_body_content: String,
    #[serde(default)]
    user_headers: HashMap<String, Vec<String>>,
    #[serde(default)]
    user_cookies: Vec<String>,
}

fn failure(action: AppSecFailureAction) -> HandlerResult {
    match action {
        AppSecFailureAction::Passthrough => HandlerResult::Declined,
        AppSecFailureAction::Deny => HandlerResult::Forbidden,
    }
}

fn appsec_context(
    request: &Request,
    loc: &LocConfig,
    main_conf: &MainConfig,
) -> Option<(AppSecConfig, IpAddr, AppSecFailureAction, bool)> {
    let uri = request.unparsed_uri().to_str().unwrap_or("/");
    let internal_challenge = uri.starts_with("/crowdsec-internal/challenge/");
    if loc.appsec_enabled != Some(true) {
        return None;
    }
    if internal_challenge && loc.bot_challenge_enabled != Some(true) {
        return None;
    }

    let failure_action = if internal_challenge {
        AppSecFailureAction::Deny
    } else {
        loc.appsec_failure_action.unwrap_or_default()
    };

    let config = CONFIG.lock().unwrap_or_else(|e| e.into_inner()).clone()?;
    let ip = get_client_ip(request, main_conf)?;

    Some((config, ip, failure_action, internal_challenge))
}

/// AppSec in ACCESS phase: headers/URI, or body inspection when the client sent a body.
/// Body reads run here (not PRECONTENT) so proxy_pass keeps the correct content handler.
pub fn inspect_access(
    request: &mut Request,
    loc: &LocConfig,
    main_conf: &MainConfig,
) -> HandlerResult {
    let uri = request.unparsed_uri().to_str().unwrap_or("/");
    let internal_challenge = uri.starts_with("/crowdsec-internal/challenge/");
    if loc.appsec_enabled != Some(true) {
        return if internal_challenge {
            HandlerResult::Forbidden
        } else {
            HandlerResult::Declined
        };
    }
    if internal_challenge && loc.bot_challenge_enabled != Some(true) {
        return HandlerResult::Forbidden;
    }

    let Some((config, ip, failure_action, internal_challenge)) =
        appsec_context(request, loc, main_conf)
    else {
        return failure(loc.appsec_failure_action.unwrap_or_default());
    };

    let r: *mut ngx_http_request_t = request.as_mut() as *mut _;
    if unsafe { has_request_body(r) } {
        return inspect_request_body(
            request,
            loc,
            r,
            &ip,
            &config,
            failure_action,
            internal_challenge,
        );
    }

    inspect_with_body(
        request,
        loc,
        &ip,
        &config,
        failure_action,
        internal_challenge,
        None,
    )
}

/// PRECONTENT is not used for AppSec body reads; kept so older configs behave the same.
pub fn inspect_precontent(
    request: &mut Request,
    loc: &LocConfig,
    main_conf: &MainConfig,
) -> HandlerResult {
    let _ = (request, loc, main_conf);
    HandlerResult::Declined
}

fn inspect_request_body(
    request: &mut Request,
    loc: &LocConfig,
    r: *mut ngx_http_request_t,
    ip: &IpAddr,
    config: &AppSecConfig,
    failure_action: AppSecFailureAction,
    internal_challenge: bool,
) -> HandlerResult {
    if unsafe { request_body_buffered(r) } {
        return HandlerResult::Declined;
    }

    let content_length = unsafe { get_content_length(r) };
    if content_length > config.max_body_size as i64 {
        return failure(failure_action);
    }

    unsafe {
        match initiate_appsec_body_read(
            r,
            ip,
            failure_action,
            internal_challenge,
            loc.bot_challenge_enabled == Some(true),
        ) {
            Ok(()) => HandlerResult::AppSecPending,
            Err(result) => result,
        }
    }
}

unsafe fn initiate_appsec_body_read(
    r: *mut ngx_http_request_t,
    ip: &IpAddr,
    failure_action: AppSecFailureAction,
    internal_challenge: bool,
    bot_challenge: bool,
) -> Result<(), HandlerResult> {
    unsafe {
        let ctx = ngx::ffi::ngx_palloc((*r).pool, std::mem::size_of::<AppSecBodyContext>())
            as *mut AppSecBodyContext;
        if ctx.is_null() {
            return Err(failure(failure_action));
        }

        ptr::write(
            ctx,
            AppSecBodyContext::new(ip, failure_action, internal_challenge, bot_challenge),
        );

        let rc = initiate_body_read(r, ctx.cast(), appsec_body_handler);
        let module = &raw const crate::ngx_http_crowdsec_module;
        let ctx_ptr = (*r).ctx.wrapping_add((*module).ctx_index as usize);

        if rc == ngx::ffi::NGX_OK as ngx_int_t {
            // Body buffered synchronously: the callback ran inside this handler.
            // Return the stored result directly; do not finalize_allow() here.
            let ctx = *ctx_ptr as *mut AppSecBodyContext;
            if ctx.is_null() || (*ctx).magic != APPSEC_BODY_CTX_MAGIC {
                return Err(failure(failure_action));
            }
            let Some(result) = (*ctx).take_result() else {
                return Err(failure(failure_action));
            };
            *ctx_ptr = std::ptr::null_mut();
            return Err(result);
        }

        if rc == ngx::ffi::NGX_AGAIN as ngx_int_t {
            if !(*ctx_ptr).is_null() {
                (*(*ctx_ptr as *mut AppSecBodyContext)).defer_finalize = 0;
            }
            return Ok(());
        }

        if rc >= ngx::ffi::NGX_HTTP_SPECIAL_RESPONSE as ngx_int_t {
            Err(HandlerResult::Forbidden)
        } else {
            Err(failure(failure_action))
        }
    }
}

unsafe extern "C" fn appsec_body_handler(r: *mut ngx_http_request_t) {
    unsafe {
        let main_r = (*r).main;
        let module = &raw const crate::ngx_http_crowdsec_module;
        let ctx_ptr = (*main_r).ctx.wrapping_add((*module).ctx_index as usize);
        let ctx = *ctx_ptr as *const AppSecBodyContext;

        if ctx.is_null() || (*ctx).magic != APPSEC_BODY_CTX_MAGIC {
            ngx_http_finalize_request(r, ngx::ffi::NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
            return;
        }

        let context = &*ctx;
        let failure_action = context.failure_action();
        let finish = |result: HandlerResult| context.finish(main_r, ctx_ptr, result);

        let config = match CONFIG.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            Some(c) => c,
            None => {
                finish(failure(failure_action));
                return;
            }
        };

        let ip = match context.client_ip() {
            Some(ip) => ip,
            None => {
                finish(failure(failure_action));
                return;
            }
        };

        let body = match extract_request_body_limited(
            r,
            config.max_body_size,
            !config.drop_unreadable_body,
        ) {
            BodyExtractResult::Ok(body) => body,
            BodyExtractResult::TooLarge => {
                finish(failure(failure_action));
                return;
            }
            BodyExtractResult::Unreadable => {
                let action = if config.drop_unreadable_body {
                    AppSecFailureAction::Deny
                } else {
                    AppSecFailureAction::Passthrough
                };
                finish(failure(action));
                return;
            }
        };

        // Body callback leaves keepalive in a bad state for later phases (captcha uses the same fix).
        (*main_r).set_keepalive(0);

        let mut request = Request::from_ngx_http_request(main_r);
        let loc = match crate::crowdsec_loc_conf(&request).cloned() {
            Some(c) => c,
            None => {
                finish(failure(failure_action));
                return;
            }
        };

        finish(inspect_with_body(
            &mut request,
            &loc,
            &ip,
            &config,
            failure_action,
            context.internal_challenge != 0,
            Some(body.as_slice()),
        ));
    }
}

fn inspect_with_body(
    request: &mut Request,
    loc: &LocConfig,
    ip: &IpAddr,
    config: &AppSecConfig,
    failure_action: AppSecFailureAction,
    internal_challenge: bool,
    body: Option<&[u8]>,
) -> HandlerResult {
    match call_appsec(request, ip, config, body) {
        Ok(response) | Err(ureq::Error::Status(403, response)) => apply_appsec_response(
            request,
            loc,
            ip,
            response,
            failure_action,
            internal_challenge,
            loc.bot_challenge_enabled == Some(true),
        ),
        Err(_) => failure(failure_action),
    }
}

fn call_appsec(
    request: &Request,
    ip: &IpAddr,
    config: &AppSecConfig,
    body: Option<&[u8]>,
) -> Result<ureq::Response, ureq::Error> {
    let uri = request.unparsed_uri().to_str().unwrap_or("/");
    let user_agent = request
        .user_agent()
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let host = request
        .headers_in_iterator()
        .find_map(|(k, v)| {
            let (Ok(k), Ok(v)) = (k.to_str(), v.to_str()) else {
                return None;
            };
            k.eq_ignore_ascii_case("host").then_some(v)
        })
        .unwrap_or("");

    let mut call = if body.is_some() {
        AGENT.post(&config.url)
    } else {
        AGENT.get(&config.url)
    }
    .set("User-Agent", lapi::BOUNCER_USER_AGENT)
    .set("X-Crowdsec-Appsec-Ip", &ip.to_string())
    .set("X-Crowdsec-Appsec-Uri", uri)
    .set("X-Crowdsec-Appsec-Host", host)
    .set("X-Crowdsec-Appsec-Verb", request.method().as_str())
    .set("X-Crowdsec-Appsec-Api-Key", &config.api_key)
    .set("X-Crowdsec-Appsec-User-Agent", user_agent)
    .set("X-Crowdsec-Appsec-Http-Version", "11")
    .timeout(Duration::from_millis(config.timeout_ms));

    for (name, value) in request.headers_in_iterator() {
        let (Ok(name), Ok(value)) = (name.to_str(), value.to_str()) else {
            continue;
        };
        if !name.to_ascii_lowercase().starts_with("x-crowdsec-appsec-")
            && !matches!(
                name.to_ascii_lowercase().as_str(),
                "connection" | "transfer-encoding" | "upgrade" | "user-agent"
            )
        {
            call = call.set(name, value);
        }
    }

    if let Some(body) = body {
        call.send_bytes(body)
    } else {
        call.call()
    }
}

fn apply_appsec_response(
    request: &mut Request,
    loc: &LocConfig,
    ip: &IpAddr,
    response: ureq::Response,
    failure_action: AppSecFailureAction,
    internal_challenge: bool,
    bot_challenge: bool,
) -> HandlerResult {
    if response.status() == 200 {
        return HandlerResult::Declined;
    }

    if response.status() != 403 {
        return failure(failure_action);
    }

    let Ok(envelope) = response.into_json::<Envelope>() else {
        crate::usage_metrics::record_appsec_dropped(ip);
        return HandlerResult::Forbidden;
    };

    let result = match envelope.action.as_str() {
        "allow" => HandlerResult::Declined,
        "ban" => HandlerResult::Forbidden,
        "captcha" => {
            let captcha_config = match loc.captcha_config() {
                Some(cfg) => cfg,
                None => return failure(failure_action),
            };
            if send_captcha_page(
                request,
                &captcha_config,
                loc.captcha_template.as_ref(),
                ip,
                None,
            )
            .is_ok()
            {
                HandlerResult::Done
            } else {
                HandlerResult::Forbidden
            }
        }
        "challenge" if bot_challenge && !envelope.user_body_content.is_empty() => {
            let status = HTTPStatus::from_u16(if envelope.http_status == 0 {
                200
            } else {
                envelope.http_status
            })
            .unwrap_or(HTTPStatus::FORBIDDEN);
            let headers = envelope
                .user_headers
                .into_iter()
                .flat_map(|(name, values)| {
                    values.into_iter().filter_map(move |value| {
                        safe_header(&name, &value).then(|| (name.clone(), value))
                    })
                })
                .chain(
                    envelope
                        .user_cookies
                        .into_iter()
                        .filter(|v| !v.contains(['\r', '\n']))
                        .map(|v| ("Set-Cookie".to_string(), v)),
                )
                .collect::<Vec<_>>();
            if send_raw_response(request, status, &envelope.user_body_content, &headers).is_ok() {
                HandlerResult::Done
            } else {
                HandlerResult::Forbidden
            }
        }
        _ if internal_challenge => HandlerResult::Forbidden,
        _ => HandlerResult::Forbidden,
    };

    if !matches!(
        result,
        HandlerResult::Declined | HandlerResult::Error | HandlerResult::AppSecPending
    ) {
        crate::usage_metrics::record_appsec_dropped(ip);
    }

    result
}

fn finalize_precontent_result(r: *mut ngx_http_request_t, result: HandlerResult) {
    match result {
        HandlerResult::Declined => unsafe { finalize_allow(r) },
        HandlerResult::Forbidden => unsafe {
            ngx_http_finalize_request(
                r,
                ngx::core::Status::from(HTTPStatus::FORBIDDEN).0,
            );
        },
        HandlerResult::Done | HandlerResult::AppSecPending | HandlerResult::CaptchaPending => {}
        HandlerResult::Error => unsafe { finalize_allow(r) },
    }
}

fn safe_header(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !value.contains(['\r', '\n'])
        && !matches!(
            name.to_ascii_lowercase().as_str(),
            "connection" | "content-length" | "transfer-encoding" | "upgrade"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_envelope_parses_repeated_headers() {
        let value: Envelope = serde_json::from_str(r#"{"action":"challenge","http_status":307,"user_body_content":"ok","user_headers":{"Location":["/"]},"user_cookies":["a=b","c=d"]}"#).unwrap();
        assert_eq!(value.http_status, 307);
        assert_eq!(value.user_cookies.len(), 2);
    }

    #[test]
    fn response_headers_reject_injection_and_hop_by_hop_headers() {
        assert!(safe_header("Location", "/challenge"));
        assert!(!safe_header("X-Test", "ok\r\nInjected: yes"));
        assert!(!safe_header("Content-Length", "1"));
    }

    #[test]
    fn appsec_body_context_roundtrip() {
        let ctx = AppSecBodyContext::new(
            &"203.0.113.10".parse().unwrap(),
            AppSecFailureAction::Deny,
            false,
            true,
        );
        assert_eq!(ctx.client_ip().unwrap().to_string(), "203.0.113.10");
        assert_eq!(ctx.failure_action(), AppSecFailureAction::Deny);
        assert_eq!(ctx.defer_finalize, 1);
    }

    #[test]
    fn stored_appsec_result_roundtrip() {
        let cases = [
            (HandlerResult::Declined, StoredAppSecResult::Declined),
            (HandlerResult::Forbidden, StoredAppSecResult::Forbidden),
            (HandlerResult::Done, StoredAppSecResult::Done),
            (HandlerResult::Error, StoredAppSecResult::Error),
        ];
        for (result, stored) in cases {
            assert_eq!(StoredAppSecResult::from_handler_result(result) as u8, stored as u8);
            assert_eq!(StoredAppSecResult::from_u8(stored as u8).unwrap().into_handler_result(), result);
        }
    }
}
