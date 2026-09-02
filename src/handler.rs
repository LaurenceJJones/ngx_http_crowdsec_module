use crate::captcha::cookie::{build_clear_cookie, get_cookie};
use crate::captcha::{self, CaptchaHandler, send_captcha_page};
use crate::config::{BanActionMode, LocConfig, MainConfig};
use crate::realip;
use crate::shm::{self, DecisionType, LookupResult};
use crate::template::{BanTemplate, TemplateVariables};
use ngx::core::{Buffer, Status};
use ngx::ffi::ngx_http_request_t;
use ngx::http::{HTTPStatus, Method, Request};
use ngx::ngx_log_debug_http;
use std::net::IpAddr;

/// Access phase handler result
pub enum HandlerResult {
    /// Allow the request to proceed
    Declined,
    /// Block the request with 403 Forbidden
    Forbidden,
    /// An error occurred, fail-open
    Error,
    /// Request has been fully handled (response sent and finalized)
    Done,
    /// Captcha required - body read initiated (async)
    CaptchaPending,
}

impl From<HandlerResult> for Status {
    fn from(result: HandlerResult) -> Self {
        match result {
            HandlerResult::Declined => Status::NGX_DECLINED,
            HandlerResult::Forbidden => Status::from(HTTPStatus::FORBIDDEN),
            HandlerResult::Error => Status::NGX_DECLINED, // Fail-open
            HandlerResult::Done => Status::NGX_DONE, // Request fully handled and finalized - don't touch it
            HandlerResult::CaptchaPending => Status::NGX_DONE, // Body read in progress
        }
    }
}

/// Check if the request is for a static asset that shouldn't receive HTML pages
///
/// These are typically browser-initiated requests (like favicon.ico) that
/// shouldn't receive full HTML ban/captcha pages.
fn is_static_asset_request(request: &Request) -> bool {
    if let Ok(path) = request.path().to_str() {
        path.as_bytes()
            .get(path.len().saturating_sub(4)..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(b".ico"))
    } else {
        false
    }
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
    if let Some(outcome) = crate::metrics::try_serve_metrics(request, loc_conf) {
        return match outcome {
            crate::metrics::MetricsServeOutcome::Served => HandlerResult::Done,
            crate::metrics::MetricsServeOutcome::Failed => HandlerResult::Error,
        };
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
        shm::metrics_inc_http_bypass();
        return HandlerResult::Declined;
    }

    shm::metrics_inc_http_lookup();

    // Lookup IP in shared memory
    let lookup = shm::lookup_ip(&client_ip);

    if !lookup.found {
        let appsec = crate::appsec::inspect(request, loc_conf, main_conf);
        if !matches!(appsec, HandlerResult::Declined) {
            return appsec;
        }
        // No remediation - but check if client has a stale captcha cookie to clear
        maybe_clear_stale_captcha_cookie(request, loc_conf);
        return HandlerResult::Declined;
    }

    // Route based on decision type (Ban has priority over Captcha)
    match lookup.decision_type {
        DecisionType::Ban => {
            if loc_conf.ban_action == Some(BanActionMode::Redirect) {
                if let Some(ref url) = loc_conf.ban_redirect_url {
                    let code = loc_conf.ban_redirect_code.unwrap_or(302);
                    if send_ban_redirect(request, url, ban_redirect_status(code)).is_ok() {
                        shm::metrics_inc_http_ban();
                        return HandlerResult::Done;
                    }
                } else {
                    ngx_log_debug_http!(
                        request,
                        "crowdsec: ban_action redirect but ban_redirect_url not set; using block"
                    );
                }
            }
            // For static assets like .ico, just return 403 without HTML body
            if is_static_asset_request(request) {
                shm::metrics_inc_http_ban();
                return HandlerResult::Forbidden;
            }
            // Handle ban - send 403 with template
            if let Some(ref template) = loc_conf.ban_template {
                match send_ban_response(request, template, &client_ip, &lookup) {
                    Ok(_) => {
                        shm::metrics_inc_http_ban();
                        return HandlerResult::Done;
                    }
                    Err(_) => {}
                }
            }
            shm::metrics_inc_http_ban();
            HandlerResult::Forbidden
        }
        DecisionType::Captcha => {
            // Handle captcha challenge
            handle_captcha_decision(request, loc_conf, &client_ip)
        }
        DecisionType::Unknown => {
            // Unknown decision type, fail-open
            ngx_log_debug_http!(
                request,
                "crowdsec: unknown decision type for IP {}",
                client_ip
            );
            HandlerResult::Declined
        }
    }
}

/// Handle a captcha decision for a client
pub(crate) fn handle_captcha_decision(
    request: &mut Request,
    loc_conf: &LocConfig,
    client_ip: &IpAddr,
) -> HandlerResult {
    // For static assets like .ico, return 200 without body
    // This allows favicon to display on captcha page without sending HTML
    if is_static_asset_request(request) {
        if send_empty_response(request, HTTPStatus::OK).is_ok() {
            shm::metrics_inc_http_captcha();
            return HandlerResult::Done;
        }
        return HandlerResult::Error;
    }

    // Get captcha configuration from location config (inherits from parent levels)
    let captcha_config = match loc_conf.captcha_config() {
        Some(cfg) => cfg,
        None => {
            // Captcha not configured - fail open with warning
            ngx_log_debug_http!(
                request,
                "crowdsec: captcha decision for {} but captcha not configured, allowing",
                client_ip
            );
            return HandlerResult::Declined;
        }
    };

    // Create captcha handler
    let handler = CaptchaHandler::new(&captcha_config, loc_conf.captcha_template.as_ref());

    // Check for existing valid session cookie
    if handler.has_valid_session(request, client_ip) {
        return HandlerResult::Declined; // Valid session, allow through
    }

    // Handle based on request method
    match request.method() {
        Method::GET | Method::HEAD => {
            // Show captcha page
            if send_captcha_page(
                request,
                &captcha_config,
                loc_conf.captcha_template.as_ref(),
                client_ip,
                None,
            )
            .is_ok()
            {
                HandlerResult::Done
            } else {
                HandlerResult::Error
            }
        }
        Method::POST => {
            // Handle captcha verification
            handle_captcha_post(request, loc_conf, &captcha_config, client_ip)
        }
        _ => {
            // Other methods - show captcha page
            if send_captcha_page(
                request,
                &captcha_config,
                loc_conf.captcha_template.as_ref(),
                client_ip,
                None,
            )
            .is_ok()
            {
                HandlerResult::Done
            } else {
                HandlerResult::Error
            }
        }
    }
}

/// Handle POST request for captcha verification
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
        // Not form data, show captcha page with error
        let _ = send_captcha_page(
            request,
            captcha_config,
            loc_conf.captcha_template.as_ref(),
            client_ip,
            Some("Invalid request format"),
        );
        return HandlerResult::Done;
    }

    // Check body size
    if !unsafe { captcha::body::is_body_size_acceptable(r) } {
        let _ = send_captcha_page(
            request,
            captcha_config,
            loc_conf.captcha_template.as_ref(),
            client_ip,
            Some("Request too large"),
        );
        return HandlerResult::Done;
    }

    // Initiate async body reading - the callback will handle verification
    let rc = unsafe {
        captcha::body::initiate_body_read(
            r,
            captcha_config,
            client_ip,
            loc_conf.captcha_template.as_ref(),
        )
    };

    // Check return code
    if rc == ngx::ffi::NGX_DONE as ngx::ffi::ngx_int_t {
        // Body read initiated or completed, request will be handled by callback
        HandlerResult::CaptchaPending
    } else if rc >= ngx::ffi::NGX_HTTP_SPECIAL_RESPONSE as ngx::ffi::ngx_int_t {
        // Error occurred
        ngx_log_debug_http!(
            request,
            "crowdsec: body read initiation failed with rc={}",
            rc
        );
        HandlerResult::Error
    } else {
        // Body already handled (NGX_OK case - callback was called synchronously)
        HandlerResult::CaptchaPending
    }
}

/// Check for and clear a stale captcha cookie when IP is no longer under remediation
///
/// This adds a Set-Cookie header to the outgoing response to clear the cookie,
/// but does not block the request - it continues normally.
fn maybe_clear_stale_captcha_cookie(request: &mut Request, loc_conf: &LocConfig) {
    // Get captcha config to know the cookie name
    let captcha_config = match loc_conf.captcha_config() {
        Some(cfg) => cfg,
        None => return, // Captcha not configured, nothing to clear
    };

    // Check if the request has the captcha cookie
    let r: *const ngx_http_request_t = request.as_ref();
    let has_cookie = unsafe { get_cookie(r, &captcha_config.cookie_name).is_some() };

    if has_cookie {
        // Client has a stale captcha cookie - add header to clear it
        let clear_cookie = build_clear_cookie(&captcha_config.cookie_name, "/");
        request.add_header_out("Set-Cookie", &clear_cookie);
    }
}

/// Send a minimal response with just a status code (effectively empty)
///
/// Used for static asset requests (.ico) where we don't want to send HTML pages
fn send_empty_response(request: &mut Request, status: HTTPStatus) -> Result<(), ()> {
    let r: *mut ngx_http_request_t = request.as_mut() as *mut _;

    // Disable keepalive to ensure connection closes cleanly
    unsafe {
        (*r).set_keepalive(0);
    }

    // Use a single newline as minimal body - truly empty bodies can cause issues
    let body = b"\n";

    request.set_status(status);
    request.set_content_length_n(body.len());
    request.discard_request_body();
    request.add_header_out("Content-Type", "text/plain");

    // Get pool for buffer allocation
    let pool = request.pool();

    // Create buffer with minimal body
    let mut buffer = match pool.create_buffer_from_str(std::str::from_utf8(body).unwrap()) {
        Some(buf) => buf,
        None => return Err(()),
    };
    buffer.set_last_buf(true);
    buffer.set_last_in_chain(true);

    // Create chain link
    let cl = unsafe {
        let cl = ngx::ffi::ngx_alloc_chain_link(pool.as_ptr());
        if cl.is_null() {
            return Err(());
        }
        (*cl).buf = buffer.as_ngx_buf_mut();
        (*cl).next = std::ptr::null_mut();
        cl
    };

    // Send headers
    let rc = request.send_header();
    if rc != Status::NGX_OK {
        unsafe {
            ngx::ffi::ngx_http_finalize_request(r, rc.into());
        }
        return Ok(());
    }

    // Send body through output filter and finalize
    unsafe {
        let rc = ngx::ffi::ngx_http_output_filter(r, cl);
        ngx::ffi::ngx_http_finalize_request(r, rc);
    }

    Ok(())
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
    let pool = request.pool();
    let mut buffer = pool.create_buffer_from_str(body).ok_or(())?;
    buffer.set_last_buf(true);
    buffer.set_last_in_chain(true);
    let r: *mut ngx_http_request_t = request.as_mut() as *mut _;
    let cl = unsafe {
        let cl = ngx::ffi::ngx_alloc_chain_link(pool.as_ptr());
        if cl.is_null() {
            return Err(());
        }
        (*cl).buf = buffer.as_ngx_buf_mut();
        (*cl).next = std::ptr::null_mut();
        cl
    };
    let rc = request.send_header();
    if rc != Status::NGX_OK {
        return Err(());
    }
    unsafe {
        let rc = ngx::ffi::ngx_http_output_filter(r, cl);
        ngx::ffi::ngx_http_finalize_request(r, rc);
    }
    Ok(())
}

fn ban_redirect_status(code: u16) -> HTTPStatus {
    match code {
        301 => HTTPStatus::MOVED_PERMANENTLY,
        303 => HTTPStatus::SEE_OTHER,
        307 => HTTPStatus::TEMPORARY_REDIRECT,
        308 => HTTPStatus::PERMANENT_REDIRECT,
        _ => HTTPStatus::MOVED_TEMPORARILY,
    }
}

/// Redirect response for ban remediation (`crowdsec_ban_action redirect`).
fn send_ban_redirect(
    request: &mut Request,
    location: &str,
    status: HTTPStatus,
) -> Result<(), ()> {
    let r: *mut ngx_http_request_t = request.as_mut() as *mut _;

    unsafe {
        (*r).set_keepalive(0);
    }

    let body = b"\n";

    request.set_status(status);
    request.set_content_length_n(body.len());
    request.discard_request_body();
    request.add_header_out("Location", location);
    request.add_header_out("Content-Type", "text/plain");
    request.add_header_out(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, max-age=0",
    );
    request.add_header_out("Pragma", "no-cache");

    let pool = request.pool();

    let mut buffer = match pool.create_buffer_from_str(std::str::from_utf8(body).unwrap()) {
        Some(buf) => buf,
        None => return Err(()),
    };
    buffer.set_last_buf(true);
    buffer.set_last_in_chain(true);

    let cl = unsafe {
        let cl = ngx::ffi::ngx_alloc_chain_link(pool.as_ptr());
        if cl.is_null() {
            return Err(());
        }
        (*cl).buf = buffer.as_ngx_buf_mut();
        (*cl).next = std::ptr::null_mut();
        cl
    };

    let rc = request.send_header();
    if rc != Status::NGX_OK {
        unsafe {
            ngx::ffi::ngx_http_finalize_request(r, rc.into());
        }
        return Ok(());
    }

    unsafe {
        let rc = ngx::ffi::ngx_http_output_filter(r, cl);
        ngx::ffi::ngx_http_finalize_request(r, rc);
    }

    Ok(())
}

/// Send a ban response with rendered template
fn send_ban_response(
    request: &mut Request,
    template: &BanTemplate,
    client_ip: &IpAddr,
    lookup: &LookupResult,
) -> Result<(), ()> {
    // Build template variables
    let mut vars = TemplateVariables::new();
    vars.client_ip = Some(client_ip.to_string());
    vars.scenario = shm::get_scenario(lookup.scenario_id);
    vars.reason = shm::get_reason(lookup.reason_id);
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

    // Set status code
    request.set_status(HTTPStatus::FORBIDDEN);

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

    // Get pool and raw request pointer
    let pool = request.pool();
    let r: *mut ngx_http_request_t = request.as_mut() as *mut _;

    // Create buffer from rendered body using Pool's helper method
    let mut buffer = match pool.create_buffer_from_str(&body) {
        Some(buf) => buf,
        None => return Err(()),
    };

    // Mark buffer as last in request and chain
    buffer.set_last_buf(true);
    buffer.set_last_in_chain(true);

    // Create chain link (still needs manual FFI - no SDK wrapper)
    let cl = unsafe {
        let cl = ngx::ffi::ngx_alloc_chain_link(pool.as_ptr());
        if cl.is_null() {
            return Err(());
        }
        (*cl).buf = buffer.as_ngx_buf_mut();
        (*cl).next = std::ptr::null_mut();
        cl
    };

    // Send headers first
    let header_status = request.send_header();
    if header_status != Status::NGX_OK {
        // Header sending failed or was filtered out
        // For HEAD requests, this is normal - just finalize
        if request.header_only() {
            unsafe {
                ngx::ffi::ngx_http_finalize_request(r, header_status.into());
            }
            return Ok(());
        }
        return Err(());
    }

    // Send body using output filter - pass pointer to pool-allocated chain
    let rc = unsafe { ngx::ffi::ngx_http_output_filter(r, cl) };

    // Finalize the request
    unsafe {
        ngx::ffi::ngx_http_finalize_request(r, rc);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_result_conversion() {
        // Just verify the conversions don't panic
        let _: Status = HandlerResult::Declined.into();
        let _: Status = HandlerResult::Forbidden.into();
        let _: Status = HandlerResult::Error.into();
    }
}
