use crate::lapi;
use crate::config::{AppSecFailureAction, LocConfig, MainConfig};
use crate::handler::{HandlerResult, StoredPhaseResult, get_client_ip, send_raw_response};
use crate::request_body::{
    APPSEC_BODY_CTX_MAGIC, CAPTCHA_POST_CTX_MAGIC, BodyExtractResult, extract_request_body_limited,
    finalize_allow, finish_access_body_read, get_content_length, has_request_body,
    initiate_body_read, module_ctx_slot, request_body_buffered, request_ctx_magic,
};
use crate::shm;
use ngx::ffi::{ngx_http_finalize_request, ngx_http_request_t, ngx_int_t};
use ngx::http::{HTTPStatus, Request};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::ptr;
use std::sync::Arc;
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

static CONFIG: Mutex<Option<Arc<AppSecConfig>>> = Mutex::new(None);
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
    /// Outcome stored so ACCESS re-entry after `finalize_allow` does not re-inspect.
    pub stored_result: u8,
    /// SHM already has a ban for this IP (`appsec_always`); keep ban over captcha/allow.
    pub shm_ban: u8,
}

impl AppSecBodyContext {
    fn new(
        ip: &IpAddr,
        failure_action: AppSecFailureAction,
        internal_challenge: bool,
        bot_challenge: bool,
        shm_ban: bool,
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
            shm_ban: u8::from(shm_ban),
            stored_result: StoredPhaseResult::Unset as u8,
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
        self.stored_result = StoredPhaseResult::encode(result);
    }

    fn take_result(&self) -> Option<HandlerResult> {
        StoredPhaseResult::decode(self.stored_result)
    }

    /// Store the outcome (for ACCESS re-entry) then allow, deny, or leave a sent response.
    unsafe fn finish(
        &self,
        main_r: *mut ngx_http_request_t,
        ctx_ptr: *mut *mut std::ffi::c_void,
        result: HandlerResult,
    ) {
        unsafe {
            let ctx_mut = *ctx_ptr as *mut AppSecBodyContext;
            if !ctx_mut.is_null() {
                (*ctx_mut).store_result(result);
            }
            finalize_async_result(main_r, result);
        }
    }
}

pub fn configure(config: Option<AppSecConfig>) {
    *CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = config.map(Arc::new);
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
) -> Result<(Arc<AppSecConfig>, IpAddr, AppSecFailureAction, bool), HandlerResult> {
    let uri = request.unparsed_uri().to_str().unwrap_or("/");
    let internal_challenge = uri.starts_with("/crowdsec-internal/challenge/");
    if loc.appsec_enabled != Some(true) {
        return Err(if internal_challenge {
            HandlerResult::Forbidden
        } else {
            HandlerResult::Declined
        });
    }
    if internal_challenge && loc.bot_challenge_enabled != Some(true) {
        return Err(HandlerResult::Forbidden);
    }

    let failure_action = if internal_challenge {
        AppSecFailureAction::Deny
    } else {
        loc.appsec_failure_action.unwrap_or_default()
    };

    let Some(config) = CONFIG.lock().unwrap_or_else(|e| e.into_inner()).clone() else {
        return Err(if internal_challenge {
            HandlerResult::Forbidden
        } else {
            failure(failure_action)
        });
    };
    let Some(ip) = get_client_ip(request, main_conf) else {
        return Err(if internal_challenge {
            HandlerResult::Forbidden
        } else {
            failure(failure_action)
        });
    };

    Ok((config, ip, failure_action, internal_challenge))
}

/// AppSec in ACCESS phase: headers/URI, or body inspection when the client sent a body.
/// Body reads run here (not PRECONTENT) so proxy_pass keeps the correct content handler.
pub fn inspect_access(
    request: &mut Request,
    loc: &LocConfig,
    main_conf: &MainConfig,
    shm_ban: bool,
) -> HandlerResult {
    let r: *mut ngx_http_request_t = request.as_mut() as *mut _;
    if let Some(result) = unsafe { resume_body_read(r) } {
        return result;
    }

    let (config, ip, failure_action, internal_challenge) =
        match appsec_context(request, loc, main_conf) {
            Ok(ctx) => ctx,
            Err(result) => return result,
        };

    let is_subrequest = unsafe { !(*r).main.is_null() && (*r).main != r };
    if !is_subrequest && unsafe { has_request_body(r) } {
        return inspect_request_body(
            request,
            loc,
            r,
            &ip,
            &config,
            failure_action,
            internal_challenge,
            shm_ban,
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
        shm_ban,
    )
}

fn unreadable_body_action(config: &AppSecConfig) -> AppSecFailureAction {
    if config.drop_unreadable_body {
        AppSecFailureAction::Deny
    } else {
        AppSecFailureAction::Passthrough
    }
}

fn inspect_request_body(
    _request: &mut Request,
    loc: &LocConfig,
    r: *mut ngx_http_request_t,
    ip: &IpAddr,
    config: &AppSecConfig,
    failure_action: AppSecFailureAction,
    internal_challenge: bool,
    shm_ban: bool,
) -> HandlerResult {
    if unsafe { request_body_buffered(r) } {
        let body = match unsafe {
            extract_request_body_limited(r, config.max_body_size, !config.drop_unreadable_body)
        } {
            BodyExtractResult::Ok(body) => body,
            BodyExtractResult::TooLarge => return failure(failure_action),
            BodyExtractResult::Unreadable => {
                return failure(unreadable_body_action(config));
            }
        };
        return inspect_with_body(
            _request,
            loc,
            ip,
            config,
            failure_action,
            internal_challenge,
            Some(&body),
            shm_ban,
        );
    }

    let content_length = unsafe { get_content_length(r) };
    if content_length > config.max_body_size as i64 {
        return failure(failure_action);
    }

    unsafe {
        initiate_appsec_body_read(
            r,
            ip,
            failure_action,
            internal_challenge,
            loc.bot_challenge_enabled == Some(true),
            shm_ban,
        )
    }
}

/// ACCESS re-entry after a body callback resumed phases (mirror-module pattern).
unsafe fn resume_body_read(r: *mut ngx_http_request_t) -> Option<HandlerResult> {
    unsafe {
        match request_ctx_magic(r)? {
            APPSEC_BODY_CTX_MAGIC => {
                let ctx = *module_ctx_slot(r) as *const AppSecBodyContext;
                match (*ctx).take_result() {
                    Some(result) => Some(result),
                    None => Some(HandlerResult::BodyReadPending),
                }
            }
            // Captcha POST already owns this request (fail-open resume).
            CAPTCHA_POST_CTX_MAGIC => Some(HandlerResult::Declined),
            _ => None,
        }
    }
}

unsafe fn initiate_appsec_body_read(
    r: *mut ngx_http_request_t,
    ip: &IpAddr,
    failure_action: AppSecFailureAction,
    internal_challenge: bool,
    bot_challenge: bool,
    shm_ban: bool,
) -> HandlerResult {
    unsafe {
        let main_r = if (*r).main.is_null() { r } else { (*r).main };
        let ctx = ngx::ffi::ngx_palloc((*main_r).pool, std::mem::size_of::<AppSecBodyContext>())
            as *mut AppSecBodyContext;
        if ctx.is_null() {
            return failure(failure_action);
        }

        ptr::write(
            ctx,
            AppSecBodyContext::new(ip, failure_action, internal_challenge, bot_challenge, shm_ban),
        );

        let rc = initiate_body_read(r, ctx.cast(), appsec_body_handler);
        if finish_access_body_read(r, rc) {
            return HandlerResult::BodyReadPending;
        }

        if rc >= ngx::ffi::NGX_HTTP_SPECIAL_RESPONSE as ngx_int_t {
            HandlerResult::Forbidden
        } else {
            failure(failure_action)
        }
    }
}

unsafe extern "C" fn appsec_body_handler(r: *mut ngx_http_request_t) {
    unsafe {
        let main_r = if (*r).main.is_null() { r } else { (*r).main };
        let ctx_ptr = module_ctx_slot(r);
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
                finish(failure(unreadable_body_action(&config)));
                return;
            }
        };

        // Body callback leaves keepalive in a bad state for later phases (captcha uses the same fix).
        (*main_r).set_keepalive(0);

        let mut request = Request::from_ngx_http_request(main_r);
        let Some(loc) = crate::crowdsec_loc_conf(&request).cloned() else {
            finish(failure(failure_action));
            return;
        };

        finish(inspect_with_body(
            &mut request,
            &loc,
            &ip,
            &config,
            failure_action,
            context.internal_challenge != 0,
            Some(body.as_slice()),
            context.shm_ban != 0,
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
    shm_ban: bool,
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
            shm_ban,
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
    shm_ban: bool,
) -> HandlerResult {
    if response.status() == 200 {
        return HandlerResult::Declined;
    }

    if response.status() != 403 {
        return failure(failure_action);
    }

    let Ok(envelope) = response.into_json::<Envelope>() else {
        crate::usage_metrics::record_appsec_dropped(ip);
        if shm_ban {
            shm::metrics_inc_http_ban();
            return crate::handler::finish_block_ban(request, loc);
        }
        return HandlerResult::Forbidden;
    };

    let mut apply_ban = || {
        shm::metrics_inc_http_ban();
        crate::handler::finish_block_ban(request, loc)
    };

    let result = match envelope.action.as_str() {
        "allow" => HandlerResult::Declined,
        "ban" => apply_ban(),
        "captcha" if shm_ban => apply_ban(),
        "captcha" => {
            let Some(captcha_config) = loc.captcha_config() else {
                return crate::handler::apply_unenforceable_action(request, loc);
            };
            crate::handler::try_send_captcha_page(request, loc, &captcha_config, ip, None)
        }
        "challenge" if shm_ban => apply_ban(),
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

    if !matches!(result, HandlerResult::Declined | HandlerResult::Error) {
        crate::usage_metrics::record_appsec_dropped(ip);
    }

    result
}

fn finalize_async_result(r: *mut ngx_http_request_t, result: HandlerResult) {
    match result {
        HandlerResult::Declined | HandlerResult::Error => unsafe { finalize_allow(r) },
        HandlerResult::Forbidden => unsafe {
            ngx_http_finalize_request(
                r,
                ngx::core::Status::from(HTTPStatus::FORBIDDEN).0,
            );
        },
        HandlerResult::Done | HandlerResult::BodyReadPending => {}
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
            false,
        );
        assert_eq!(ctx.client_ip().unwrap().to_string(), "203.0.113.10");
        assert_eq!(ctx.failure_action(), AppSecFailureAction::Deny);
        assert_eq!(ctx.take_result(), None);
    }

    #[test]
    fn stored_phase_result_roundtrip() {
        let cases = [
            HandlerResult::Declined,
            HandlerResult::Forbidden,
            HandlerResult::Done,
            HandlerResult::Error,
        ];
        for result in cases {
            assert_eq!(StoredPhaseResult::decode(StoredPhaseResult::encode(result)), Some(result));
        }
        assert_eq!(StoredPhaseResult::decode(StoredPhaseResult::Unset as u8), None);
        assert_eq!(
            StoredPhaseResult::decode(StoredPhaseResult::encode(HandlerResult::BodyReadPending)),
            Some(HandlerResult::Error)
        );
    }
}
