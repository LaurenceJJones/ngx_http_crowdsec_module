use crate::captcha::cookie::{
    SameSite, build_clear_cookie_with_attrs, get_cookie, response_has_set_cookie,
    should_cookie_be_secure,
};
use crate::captcha::handler::{
    captcha_return_uri, captcha_session_valid, send_captcha_page, send_see_other_redirect,
};
use crate::captcha;
use crate::config::{BanActionMode, FallbackRemediation, LocConfig, MainConfig, UnenforceableAction};
use crate::realip;
use crate::shm::{self, DecisionType, LookupResult};
use crate::usage_metrics;
use crate::template::{Template, TemplateVariables};
use crate::response::{HeaderFailureAction, body_chain, disable_keepalive, send_chain_and_finalize};
use ngx::core::Status;
use ngx::ffi::ngx_http_request_t;
use ngx::http::{HTTPStatus, Method, Request};
use ngx::ngx_log_debug_http;
use std::net::IpAddr;

/// Access phase handler result
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum HandlerResult {
    /// Allow the request to proceed
    Declined,
    /// Block the request with 403 Forbidden
    Forbidden,
    /// An error occurred, fail-open
    Error,
    /// Request has been fully handled (response sent and finalized)
    Done,
    /// Captcha/AppSec is waiting for an async request-body read
    BodyReadPending,
}

/// Packed into AppSec/captcha request ctx while a body read is in flight.
#[repr(u8)]
#[derive(PartialEq, Eq, Copy, Clone)]
pub(crate) enum StoredPhaseResult {
    Unset = 0,
    Declined = 1,
    Forbidden = 2,
    Done = 3,
    Error = 4,
}

impl StoredPhaseResult {
    pub(crate) fn encode(result: HandlerResult) -> u8 {
        (match result {
            HandlerResult::Declined => Self::Declined,
            HandlerResult::Forbidden => Self::Forbidden,
            HandlerResult::Done => Self::Done,
            HandlerResult::Error | HandlerResult::BodyReadPending => Self::Error,
        }) as u8
    }

    pub(crate) fn decode(value: u8) -> Option<HandlerResult> {
        match value {
            x if x == Self::Declined as u8 => Some(HandlerResult::Declined),
            x if x == Self::Forbidden as u8 => Some(HandlerResult::Forbidden),
            x if x == Self::Done as u8 => Some(HandlerResult::Done),
            x if x == Self::Error as u8 => Some(HandlerResult::Error),
            _ => None,
        }
    }
}

impl From<HandlerResult> for Status {
    fn from(result: HandlerResult) -> Self {
        match result {
            HandlerResult::Declined => Status::NGX_DECLINED,
            HandlerResult::Forbidden => Status::from(HTTPStatus::FORBIDDEN),
            HandlerResult::Error => Status::NGX_DECLINED, // Fail-open
            HandlerResult::Done => Status::NGX_DONE, // Request fully handled and finalized - don't touch it
            HandlerResult::BodyReadPending => Status::NGX_DONE,
        }
    }
}

/// Check if the request is for a static asset that shouldn't receive HTML pages.
fn is_static_asset_request(request: &Request, loc_conf: &LocConfig) -> bool {
    request
        .path()
        .to_str()
        .is_ok_and(|path| loc_conf.is_static_asset_path(path))
}

fn should_run_appsec_access(loc_conf: &LocConfig, lookup: &LookupResult) -> bool {
    loc_conf.appsec_enabled == Some(true) && (!lookup.found || loc_conf.appsec_always == Some(true))
}

fn record_ban_applied(client_ip: &IpAddr, lookup: &LookupResult) {
    usage_metrics::record_dropped(client_ip, lookup.origin, lookup.scenario_id);
    shm::metrics_inc_http_ban();
}

/// Extract the client IP address from the NGINX request (socket peer, then trusted-proxy headers).
pub fn get_client_ip(request: &Request, main_conf: &MainConfig) -> Option<std::net::IpAddr> {
    crate::realip::get_effective_client_ip(
        request,
        &main_conf.trusted_proxies,
        main_conf.real_ip_header.as_deref(),
    )
}

/// Main access phase handler logic
///
/// This function checks if the client IP has decisions according to CrowdSec
/// stored in shared memory, and handles ban or captcha remediations.
///
/// # Arguments
/// * `request` - The NGINX request (mutable for sending responses)
/// * `loc_conf` - The location configuration (already merged with parent, includes captcha settings)
///
/// # Returns
/// * `HandlerResult::Declined` - Allow the request
/// * `HandlerResult::Forbidden` - Block the request (IP is banned)
/// * `HandlerResult::Done` - Response sent (ban page or captcha page)
/// * `HandlerResult::Error` - Error occurred, fail-open
pub fn handle_access(
    request: &mut Request,
    loc_conf: &LocConfig,
    main_conf: &MainConfig,
) -> HandlerResult {
    if let Some(result) = crate::metrics::try_serve_metrics(request, loc_conf) {
        return result;
    }

    // Check if module is enabled
    match loc_conf.enabled {
        Some(true) => {
            // Module is enabled, proceed with IP check
        }
        Some(false) | None => {
            return HandlerResult::Declined;
        }
    }

    // Extract client IP
    let client_ip = match get_client_ip(request, main_conf) {
        Some(ip) => ip,
        None => {
            // Couldn't get IP, fail-open
            return HandlerResult::Error;
        }
    };

    if !main_conf.bypass_cidrs.is_empty()
        && crate::realip::ip_in_cidr_list(&client_ip, &main_conf.bypass_cidrs)
    {
        usage_metrics::record_processed(&client_ip);
        shm::metrics_inc_http_bypass();
        return HandlerResult::Declined;
    }

    usage_metrics::record_processed(&client_ip);
    shm::metrics_inc_http_lookup();

    // Lookup IP in shared memory
    let lookup = shm::lookup_ip(&client_ip);

    if should_run_appsec_access(loc_conf, &lookup) {
        let shm_ban = lookup.found && lookup.decision_type == DecisionType::Ban;
        let appsec = crate::appsec::inspect_access(request, loc_conf, main_conf, shm_ban);
        if !matches!(appsec, HandlerResult::Declined) {
            return appsec;
        }
    }

    if !lookup.found {
        // No remediation - but check if client has a stale captcha cookie to clear
        maybe_clear_stale_captcha_cookie(request, loc_conf);
        return HandlerResult::Declined;
    }

    // Route based on decision type (Ban has priority over Captcha)
    match lookup.decision_type {
        DecisionType::Ban => handle_ban_decision(request, loc_conf, &client_ip, &lookup),
        DecisionType::Captcha => handle_captcha_decision(request, loc_conf, &client_ip, &lookup),
        DecisionType::Unknown => handle_unknown_decision(request, loc_conf, main_conf, &client_ip, &lookup),
    }
}

fn handle_ban_decision(
    request: &mut Request,
    loc_conf: &LocConfig,
    client_ip: &IpAddr,
    lookup: &LookupResult,
) -> HandlerResult {
    if loc_conf.ban_action == Some(BanActionMode::Redirect) {
        if let Some(ref url) = loc_conf.ban_redirect_url {
            let code = loc_conf.ban_redirect_code.unwrap_or(302);
            if send_ban_redirect(request, url, HTTPStatus::from_u16(code).unwrap_or(HTTPStatus::MOVED_TEMPORARILY)).is_ok() {
                record_ban_applied(client_ip, lookup);
                return HandlerResult::Done;
            }
        } else {
            ngx_log_debug_http!(
                request,
                "crowdsec: ban_action redirect but ban_redirect_url not set; using block"
            );
        }
    }
    if is_static_asset_request(request, loc_conf) {
        record_ban_applied(client_ip, lookup);
        return finish_block_ban(request, loc_conf);
    }
    let ban_status = ban_block_status(loc_conf);
    if let Some(ref template) = loc_conf.ban_template {
        if send_ban_response(request, template, ban_status, client_ip, lookup).is_ok() {
            record_ban_applied(client_ip, lookup);
            return HandlerResult::Done;
        }
    } else if send_empty_response(request, ban_status).is_ok() {
        record_ban_applied(client_ip, lookup);
        return HandlerResult::Done;
    }
    apply_unenforceable_action(request, loc_conf)
}

fn handle_unknown_decision(
    request: &mut Request,
    loc_conf: &LocConfig,
    main_conf: &MainConfig,
    client_ip: &IpAddr,
    lookup: &LookupResult,
) -> HandlerResult {
    ngx_log_debug_http!(
        request,
        "crowdsec: unknown decision type for IP {}",
        client_ip
    );
    match main_conf.fallback_remediation_or_default() {
        FallbackRemediation::Allow => HandlerResult::Declined,
        FallbackRemediation::Ban => handle_ban_decision(request, loc_conf, client_ip, lookup),
        FallbackRemediation::Captcha => handle_captcha_decision(request, loc_conf, client_ip, lookup),
    }
}

/// Handle a captcha decision for a client
pub(crate) fn handle_captcha_decision(
    request: &mut Request,
    loc_conf: &LocConfig,
    client_ip: &IpAddr,
    lookup: &LookupResult,
) -> HandlerResult {
    let r: *mut ngx_http_request_t = request.as_mut() as *mut _;
    if let Some(result) = unsafe { captcha::body::resume_body_read(r) } {
        return result;
    }

    // For static assets like .ico, return 200 without body
    // This allows favicon to display on captcha page without sending HTML
    if is_static_asset_request(request, loc_conf) {
        if send_empty_response(request, HTTPStatus::OK).is_ok() {
            shm::metrics_inc_http_captcha();
            return HandlerResult::Done;
        }
        return apply_unenforceable_action(request, loc_conf);
    }

    // Get captcha configuration from location config (inherits from parent levels)
    let captcha_config = match loc_conf.captcha_config() {
        Some(cfg) => cfg,
        None => {
            ngx_log_debug_http!(
                request,
                "crowdsec: captcha decision for {} but captcha not configured",
                client_ip
            );
            return apply_unenforceable_action(request, loc_conf);
        }
    };

    if captcha_session_valid(request, &captcha_config, client_ip) {
        // Static origins often only allow GET — never pass captcha POST through.
        if matches!(
            request.method(),
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        ) {
            let uri = captcha_return_uri(request);
            return if send_see_other_redirect(request, &uri).is_ok() {
                HandlerResult::Done
            } else {
                HandlerResult::Forbidden
            };
        }
        return HandlerResult::Declined; // Valid session, allow GET/HEAD through
    }

    usage_metrics::record_dropped(client_ip, lookup.origin, lookup.scenario_id);

    // Handle based on request method
    match request.method() {
        Method::GET | Method::HEAD => try_send_captcha_page(request, loc_conf, &captcha_config, client_ip, None),
        Method::POST => {
            if loc_conf.captcha_template.is_none() {
                return apply_unenforceable_action(request, loc_conf);
            }
            // Handle captcha verification
            handle_captcha_post(request, loc_conf, &captcha_config, client_ip)
        }
        _ => try_send_captcha_page(request, loc_conf, &captcha_config, client_ip, None),
    }
}

pub(crate) fn try_send_captcha_page(
    request: &mut Request,
    loc_conf: &LocConfig,
    captcha_config: &crate::captcha::CaptchaConfig,
    client_ip: &IpAddr,
    error_message: Option<&str>,
) -> HandlerResult {
    if loc_conf.captcha_template.is_none() {
        return apply_unenforceable_action(request, loc_conf);
    }
    if send_captcha_page(
        request,
        captcha_config,
        loc_conf.captcha_template.as_ref(),
        client_ip,
        error_message,
    )
    .is_ok()
    {
        HandlerResult::Done
    } else {
        apply_unenforceable_action(request, loc_conf)
    }
}

pub(crate) fn apply_unenforceable_action(
    request: &mut Request,
    loc_conf: &LocConfig,
) -> HandlerResult {
    match loc_conf.unenforceable_action_or_default() {
        UnenforceableAction::Allow => HandlerResult::Declined,
        UnenforceableAction::Block => finish_block_ban(request, loc_conf),
    }
}

fn ban_block_status(loc_conf: &LocConfig) -> HTTPStatus {
    HTTPStatus::from_u16(loc_conf.ban_status_code()).unwrap_or(HTTPStatus::FORBIDDEN)
}

pub(crate) fn finish_block_ban(request: &mut Request, loc_conf: &LocConfig) -> HandlerResult {
    let status = ban_block_status(loc_conf);
    if send_empty_response(request, status).is_ok() {
        HandlerResult::Done
    } else if status == HTTPStatus::FORBIDDEN {
        HandlerResult::Forbidden
    } else {
        HandlerResult::Error
    }
}

/// Minimal response for block-mode bans (no template body).
fn send_empty_response(request: &mut Request, status: HTTPStatus) -> Result<(), ()> {
    disable_keepalive(request);
    request.set_status(status);
    request.set_content_length_n(1);
    request.discard_request_body();
    request.add_header_out("Content-Type", "text/plain");
    let cl = body_chain(request, "\n")?;
    send_chain_and_finalize(request, cl, HeaderFailureAction::Finalize)
}

fn handle_captcha_post(
    request: &mut Request,
    loc_conf: &LocConfig,
    captcha_config: &crate::captcha::CaptchaConfig,
    client_ip: &IpAddr,
) -> HandlerResult {
    let r: *mut ngx_http_request_t = request.as_mut() as *mut _;

    // Check content type
    let is_form = unsafe { captcha::body::is_form_urlencoded(r) };
    if !is_form {
        return try_send_captcha_page(
            request,
            loc_conf,
            captcha_config,
            client_ip,
            Some("Invalid request format"),
        );
    }

    // Check body size
    if !unsafe { captcha::body::is_body_size_acceptable(r) } {
        return try_send_captcha_page(
            request,
            loc_conf,
            captcha_config,
            client_ip,
            Some("Request too large"),
        );
    }

    // Initiate body reading. Always return BodyReadPending after starting the
    // read (nginx mirror pattern); the callback applies allow/deny.
    if loc_conf.captcha_template.is_none() {
        ngx_log_debug_http!(
            request,
            "crowdsec: captcha POST requires crowdsec_captcha_template"
        );
        return apply_unenforceable_action(request, loc_conf);
    }

    match unsafe { captcha::body::initiate_body_read(r, captcha_config, client_ip) } {
        HandlerResult::Error => apply_unenforceable_action(request, loc_conf),
        result => result,
    }
}

/// Check for and clear a stale captcha cookie when IP is no longer under remediation
///
/// This adds a Set-Cookie header to the outgoing response to clear the cookie,
/// but does not block the request - it continues normally.
fn maybe_clear_stale_captcha_cookie(request: &mut Request, loc_conf: &LocConfig) {
    if !loc_conf.captcha_is_configured() {
        return;
    }
    let cookie_name = loc_conf.captcha_cookie_name();

    let r: *const ngx_http_request_t = request.as_ref();
    let has_cookie = unsafe { get_cookie(r, cookie_name).is_some() };

    if has_cookie && !response_has_set_cookie(request, cookie_name) {
        let r: *const ngx_http_request_t = request.as_ref();
        let is_secure =
            unsafe { should_cookie_be_secure(r, loc_conf.captcha_cookie_secure.unwrap_or_default()) };
        let clear_cookie = build_clear_cookie_with_attrs(
            cookie_name,
            "/",
            is_secure,
            true,
            SameSite::Lax,
        );
        request.add_header_out("Set-Cookie", &clear_cookie);
    }
}

pub(crate) fn send_raw_response(
    request: &mut Request,
    status: HTTPStatus,
    body: &str,
    headers: &[(String, String)],
) -> Result<(), ()> {
    request.set_status(status);
    request.set_content_length_n(body.len());
    request.discard_request_body();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if !matches!(
            lower.as_str(),
            "connection" | "content-length" | "transfer-encoding" | "upgrade"
        ) {
            request.add_header_out(name, value);
        }
    }
    let cl = body_chain(request, body)?;
    if request.send_header() != Status::NGX_OK {
        return Err(());
    }
    let r: *mut ngx_http_request_t = request.as_mut() as *mut _;
    unsafe {
        let rc = ngx::ffi::ngx_http_output_filter(r, cl);
        ngx::ffi::ngx_http_finalize_request(r, rc);
    }
    Ok(())
}

/// Redirect response for ban remediation (`crowdsec_ban_action redirect`).
fn send_ban_redirect(request: &mut Request, location: &str, status: HTTPStatus) -> Result<(), ()> {
    disable_keepalive(request);
    request.set_status(status);
    request.set_content_length_n(1);
    request.discard_request_body();
    request.add_header_out("Location", location);
    request.add_header_out("Content-Type", "text/plain");
    request.add_header_out(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, max-age=0",
    );
    request.add_header_out("Pragma", "no-cache");
    let cl = body_chain(request, "\n")?;
    send_chain_and_finalize(request, cl, HeaderFailureAction::Finalize)
}

/// Send a ban response with rendered template
fn send_ban_response(
    request: &mut Request,
    template: &Template,
    status: HTTPStatus,
    client_ip: &IpAddr,
    lookup: &LookupResult,
) -> Result<(), ()> {
    // Build template variables
    let mut vars = TemplateVariables::new();
    vars.client_ip = Some(client_ip.to_string());
    vars.scenario = shm::get_scenario(lookup.scenario_id);
    vars.origin = Some(lookup.origin.as_str().to_string());
    if let Some(h) = realip::header_value_ci(request, "Host") {
        let t = h.trim();
        if !t.is_empty() {
            vars.host = Some(t.to_string());
        }
    }

    // Get URI and method using Request API
    if let Ok(uri_str) = request.path().to_str() {
        vars.request_uri = Some(uri_str.to_string());
    }
    vars.request_method = Some(request.method().as_str().to_string());

    // Render the template
    let body = template.render(&vars);

    // Set status code (crowdsec_ban_status / Lua RET_CODE)
    request.set_status(status);

    // Set content length
    request.set_content_length_n(body.len());

    // Discard request body if present (we're sending our own response)
    request.discard_request_body();

    // Set headers - content type auto-detected from template file extension
    request.add_header_out("Content-Type", template.content_type());
    request.add_header_out(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, max-age=0",
    );
    request.add_header_out("Pragma", "no-cache");

    let cl = body_chain(request, &body)?;
    send_chain_and_finalize(request, cl, HeaderFailureAction::HeadOrError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LocConfig;
    use crate::shm::{DecisionType, LookupResult, Origin};

    #[test]
    fn test_handler_result_conversion() {
        // Just verify the conversions don't panic
        let _: Status = HandlerResult::Declined.into();
        let _: Status = HandlerResult::Forbidden.into();
        let _: Status = HandlerResult::Error.into();
    }

    #[test]
    fn test_should_run_appsec_access() {
        let lookup_none = LookupResult {
            found: false,
            decision_type: DecisionType::Unknown,
            origin: Origin::Crowdsec,
            scenario_id: 0,
        };
        let lookup_ban = LookupResult {
            found: true,
            decision_type: DecisionType::Ban,
            origin: Origin::Crowdsec,
            scenario_id: 0,
        };
        let mut loc = LocConfig {
            appsec_enabled: Some(true),
            ..Default::default()
        };

        assert!(should_run_appsec_access(&loc, &lookup_none));
        assert!(!should_run_appsec_access(&loc, &lookup_ban));

        loc.appsec_always = Some(true);
        assert!(should_run_appsec_access(&loc, &lookup_ban));

        loc.appsec_enabled = Some(false);
        assert!(!should_run_appsec_access(&loc, &lookup_ban));
    }

    #[test]
    fn test_static_asset_path_matching() {
        let default_conf = LocConfig::default();
        assert!(default_conf.is_static_asset_path("/favicon.ico"));
        assert!(!default_conf.is_static_asset_path("/style.css"));

        let css_conf = LocConfig {
            static_asset_extensions: Some(vec![".css".to_string(), ".js".to_string()]),
            ..Default::default()
        };
        assert!(css_conf.is_static_asset_path("/assets/app.JS"));
        assert!(!css_conf.is_static_asset_path("/favicon.ico"));

        let off_conf = LocConfig {
            static_asset_extensions: Some(vec![]),
            ..Default::default()
        };
        assert!(!off_conf.is_static_asset_path("/favicon.ico"));
    }
}
