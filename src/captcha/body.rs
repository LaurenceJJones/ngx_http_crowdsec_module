//! POST body reading utilities for NGINX
//!
//! NGINX's access phase runs before the request body is read. This module
//! provides utilities to read the body asynchronously using callbacks.

use crate::captcha::config::CaptchaConfig;
use crate::captcha::cookie::{SameSite, build_set_cookie, should_cookie_be_secure};
use crate::captcha::jwt::JwtManager;
use crate::captcha::verifier::{VerifyResult, parse_captcha_response, verify_captcha};
use crate::request_body::{
    BodyExtractResult, extract_request_body_limited, get_content_length,
    get_request_log, initiate_body_read as start_body_read,
};
use crate::template::{Template, TemplateVariables};
use ngx::ffi::{
    NGX_HTTP_INTERNAL_SERVER_ERROR, ngx_buf_t, ngx_http_finalize_request, ngx_http_request_t,
    ngx_int_t, ngx_palloc,
};
use ngx::ngx_log_debug;
use std::net::IpAddr;
use std::sync::Arc;

/// Context stored in the request for captcha POST handling
#[repr(C)]
pub struct CaptchaPostContext {
    /// Client IP address (stored as string for simplicity)
    pub client_ip: [u8; 64],
    pub client_ip_len: usize,
    /// Captcha provider
    pub provider: crate::captcha::config::CaptchaProvider,
    /// Secret key for verification
    pub secret_key: [u8; 256],
    pub secret_key_len: usize,
    /// Site key
    pub site_key: [u8; 256],
    pub site_key_len: usize,
    /// Signing key for JWT
    pub signing_key: [u8; 32],
    /// Cookie name
    pub cookie_name: [u8; 64],
    pub cookie_name_len: usize,
    /// Session expiry in seconds
    pub expiry_secs: u64,
    /// Whether to bind JWT to client IP
    pub bind_ip: bool,
    /// Whether to fail open on errors
    pub fail_open: bool,
    /// Cookie Secure flag setting
    pub cookie_secure: crate::captcha::config::CookieSecure,
    /// Custom template (null if using default)
    pub template: *const Template,
}

impl CaptchaPostContext {
    /// Create context from captcha config
    pub fn from_config(
        config: &CaptchaConfig,
        client_ip: &IpAddr,
        template: Option<&Arc<Template>>,
    ) -> Self {
        let ip_str = client_ip.to_string();
        let ip_bytes = ip_str.as_bytes();
        let mut client_ip_arr = [0u8; 64];
        let ip_len = ip_bytes.len().min(63);
        client_ip_arr[..ip_len].copy_from_slice(&ip_bytes[..ip_len]);

        let secret_bytes = config.secret_key.as_bytes();
        let mut secret_arr = [0u8; 256];
        let secret_len = secret_bytes.len().min(255);
        secret_arr[..secret_len].copy_from_slice(&secret_bytes[..secret_len]);

        let site_bytes = config.site_key.as_bytes();
        let mut site_arr = [0u8; 256];
        let site_len = site_bytes.len().min(255);
        site_arr[..site_len].copy_from_slice(&site_bytes[..site_len]);

        let cookie_bytes = config.cookie_name.as_bytes();
        let mut cookie_arr = [0u8; 64];
        let cookie_len = cookie_bytes.len().min(63);
        cookie_arr[..cookie_len].copy_from_slice(&cookie_bytes[..cookie_len]);

        Self {
            client_ip: client_ip_arr,
            client_ip_len: ip_len,
            provider: config.provider,
            secret_key: secret_arr,
            secret_key_len: secret_len,
            site_key: site_arr,
            site_key_len: site_len,
            signing_key: config.signing_key,
            cookie_name: cookie_arr,
            cookie_name_len: cookie_len,
            expiry_secs: config.expiry_secs,
            bind_ip: config.bind_ip,
            fail_open: config.fail_open,
            cookie_secure: config.cookie_secure,
            template: template
                .map(|t| t.as_ref() as *const _)
                .unwrap_or(std::ptr::null()),
        }
    }

    fn client_ip_str(&self) -> &str {
        std::str::from_utf8(&self.client_ip[..self.client_ip_len]).unwrap_or("unknown")
    }

    fn secret_key_str(&self) -> &str {
        std::str::from_utf8(&self.secret_key[..self.secret_key_len]).unwrap_or("")
    }

    fn site_key_str(&self) -> &str {
        std::str::from_utf8(&self.site_key[..self.site_key_len]).unwrap_or("")
    }

    fn cookie_name_str(&self) -> &str {
        std::str::from_utf8(&self.cookie_name[..self.cookie_name_len]).unwrap_or("crowdsec_captcha")
    }

    fn to_config(&self) -> CaptchaConfig {
        CaptchaConfig {
            provider: self.provider,
            site_key: self.site_key_str().to_string(),
            secret_key: self.secret_key_str().to_string(),
            signing_key: self.signing_key,
            cookie_name: self.cookie_name_str().to_string(),
            expiry_secs: self.expiry_secs,
            fail_open: self.fail_open,
            bind_ip: self.bind_ip,
            cookie_secure: self.cookie_secure,
        }
    }
}

/// Initiate async body reading for captcha POST
///
/// Returns NGX_DONE if body reading was initiated, or an error status
///
/// # Safety
/// Requires valid NGINX request pointer and module reference
pub unsafe fn initiate_body_read(
    r: *mut ngx_http_request_t,
    config: &CaptchaConfig,
    client_ip: &IpAddr,
    template: Option<&Arc<Template>>,
) -> ngx_int_t {
    unsafe {
        if template.is_none() {
            ngx_log_debug!(
                get_request_log(r),
                "crowdsec: captcha POST requires crowdsec_captcha_template"
            );
            return NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t;
        }

        // Allocate context from request pool
        let ctx = ngx_palloc((*r).pool, std::mem::size_of::<CaptchaPostContext>())
            as *mut CaptchaPostContext;

        if ctx.is_null() {
            ngx_log_debug!(
                get_request_log(r),
                "crowdsec: failed to allocate captcha context"
            );
            return NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t;
        }

        // Initialize context
        let context = CaptchaPostContext::from_config(config, client_ip, template);
        std::ptr::write(ctx, context);

        let rc = start_body_read(r, ctx.cast(), captcha_body_handler);
        if rc == ngx::ffi::NGX_AGAIN as ngx_int_t {
            ngx::ffi::NGX_DONE as ngx_int_t
        } else if rc >= ngx::ffi::NGX_HTTP_SPECIAL_RESPONSE as ngx_int_t {
            rc
        } else {
            ngx::ffi::NGX_DONE as ngx_int_t
        }
    }
}

/// Callback invoked when request body has been read
///
/// # Safety
/// Called by NGINX after body is read
unsafe extern "C" fn captcha_body_handler(r: *mut ngx_http_request_t) {
    unsafe {
        let log = get_request_log(r);
        ngx_log_debug!(log, "crowdsec: captcha body handler called");

        // Get our context from the request
        let main_r = (*r).main;
        let module = &raw const crate::ngx_http_crowdsec_module;
        let ctx_ptr = (*main_r).ctx.wrapping_add((*module).ctx_index as usize);
        let ctx = *ctx_ptr as *const CaptchaPostContext;

        if ctx.is_null() {
            ngx_log_debug!(log, "crowdsec: captcha context is null in body handler");
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
            return;
        }

        let context = &*ctx;

        // Reconstruct config from context
        let config = context.to_config();
        let client_ip_str = context.client_ip_str();

        // Parse client IP
        let client_ip: IpAddr = match client_ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                ngx_log_debug!(log, "crowdsec: failed to parse client IP from context");
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
                return;
            }
        };

        // Extract body (bounded; chunked uploads without Content-Length are rejected)
        let body = match extract_request_body_limited(
            r,
            MAX_CAPTCHA_BODY_SIZE as usize,
            false,
        ) {
            BodyExtractResult::Ok(body) => body,
            _ => {
                send_captcha_error_page(
                    r,
                    context,
                    &config,
                    &client_ip,
                    "Request too large or unreadable.",
                );
                return;
            }
        };
        ngx_log_debug!(log, "crowdsec: extracted body, {} bytes", body.len());

        if body.is_empty() {
            // No body - show error
            send_captcha_error_page(
                r,
                context,
                &config,
                &client_ip,
                "No form data received. Please try again.",
            );
            return;
        }

        // Parse captcha response from body
        let captcha_response = match parse_captcha_response(&body, config.provider) {
            Some(resp) => resp,
            None => {
                send_captcha_error_page(
                    r,
                    context,
                    &config,
                    &client_ip,
                    "Captcha response not found. Please complete the challenge.",
                );
                return;
            }
        };

        // Verify with provider
        let result = verify_captcha(
            config.provider,
            &config.secret_key,
            &captcha_response,
            client_ip_str,
        );

        ngx_log_debug!(log, "crowdsec: verification result: {:?}", result);

        match result {
            VerifyResult::Success => {
                ngx_log_debug!(
                    log,
                    "crowdsec: captcha verified successfully, creating token"
                );
                // Create session token
                let jwt_manager = JwtManager::new(config.signing_key);

                let ip_for_token = if config.bind_ip {
                    Some(client_ip_str.to_string())
                } else {
                    None
                };

                // Get URI for redirect
                let uri = get_request_uri(r);

                let claims = crate::captcha::jwt::CaptchaClaims::new(
                    ip_for_token.as_deref(),
                    config.expiry_secs,
                    Some(&uri),
                );

                match jwt_manager.create_token(&claims) {
                    Ok(token) => {
                        ngx_log_debug!(log, "crowdsec: token created, sending redirect to {}", uri);
                        // Send redirect with cookie
                        send_success_redirect(r, &config, &token, &uri);
                        ngx_log_debug!(log, "crowdsec: redirect sent");
                    }
                    Err(e) => {
                        ngx_log_debug!(log, "crowdsec: failed to create session token: {}", e);
                        send_captcha_error_page(
                            r,
                            context,
                            &config,
                            &client_ip,
                            "Internal error. Please try again.",
                        );
                    }
                }
            }
            VerifyResult::Failed(reason) => {
                ngx_log_debug!(log, "crowdsec: captcha verification failed: {}", reason);
                let error_msg = format!("Verification failed: {}. Please try again.", reason);
                send_captcha_error_page(r, context, &config, &client_ip, &error_msg);
            }
            VerifyResult::Error(err) => {
                if config.fail_open {
                    // Check if it's a network/timeout error
                    if matches!(
                        err,
                        crate::captcha::verifier::VerifyError::NetworkError(_)
                            | crate::captcha::verifier::VerifyError::Timeout
                            | crate::captcha::verifier::VerifyError::ProviderError(_)
                    ) {
                        ngx_log_debug!(
                            log,
                            "crowdsec: captcha verification error for {}, failing open: {}",
                            client_ip,
                            err
                        );
                        // Allow the request - finalize with declined
                        ngx_http_finalize_request(r, ngx::ffi::NGX_DECLINED as ngx_int_t);
                        return;
                    }
                }
                send_captcha_error_page(
                    r,
                    context,
                    &config,
                    &client_ip,
                    "Verification service unavailable. Please try again.",
                );
            }
        }
    }
}

/// Send redirect response after successful captcha verification
///
/// Sends a 302 redirect with the session cookie set. We must disable keepalive
/// because the body callback context leaves the connection in a state that
/// prevents subsequent requests on the same connection from being processed.
///
/// We send a minimal HTML body through the output filter (same as error page)
/// to properly "claim" the response and prevent NGINX's content phase from running.
unsafe fn send_success_redirect(
    r: *mut ngx_http_request_t,
    config: &CaptchaConfig,
    token: &str,
    redirect_uri: &str,
) {
    unsafe {
        // CRITICAL: Disable keepalive to fix body callback context issue
        (*r).set_keepalive(0);

        let is_secure = should_cookie_be_secure(r, config.cookie_secure);
        let cookie = build_set_cookie(
            &config.cookie_name,
            token,
            config.expiry_secs,
            "/",
            is_secure,
            true,
            SameSite::Lax,
        );

        // Minimal redirect body - browsers follow Location header regardless
        let body = b"Redirecting...";

        // Set 303 redirect status with body
        (*r).headers_out.status = 303;
        (*r).headers_out.content_length_n = body.len() as i64;

        add_header(r, "Location", redirect_uri);
        add_header(r, "Set-Cookie", &cookie);
        add_header(r, "Content-Type", "text/plain");
        add_header(r, "Cache-Control", "no-store, no-cache, must-revalidate");

        // Allocate body buffer (same pattern as working error page)
        let body_data = ngx_palloc((*r).pool, body.len()) as *mut u8;
        if body_data.is_null() {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
            return;
        }
        std::ptr::copy_nonoverlapping(body.as_ptr(), body_data, body.len());

        // Create buffer
        let buf = ngx_palloc((*r).pool, std::mem::size_of::<ngx_buf_t>()) as *mut ngx_buf_t;
        if buf.is_null() {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
            return;
        }
        std::ptr::write_bytes(buf, 0, 1);
        (*buf).pos = body_data;
        (*buf).last = body_data.add(body.len());
        (*buf).set_memory(1);
        (*buf).set_last_buf(1);
        (*buf).set_last_in_chain(1);

        // Create chain link
        let cl = ngx::ffi::ngx_alloc_chain_link((*r).pool);
        if cl.is_null() {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
            return;
        }
        (*cl).buf = buf;
        (*cl).next = std::ptr::null_mut();

        // Send headers
        let rc = ngx::ffi::ngx_http_send_header(r);
        if rc == ngx::ffi::NGX_ERROR as ngx_int_t || rc > ngx::ffi::NGX_OK as ngx_int_t {
            ngx_http_finalize_request(r, rc);
            return;
        }

        // Send body through output filter (same as error page)
        let rc = ngx::ffi::ngx_http_output_filter(r, cl);
        ngx_http_finalize_request(r, rc);
    }
}

/// Send a captcha error page using raw FFI
unsafe fn send_captcha_error_page(
    r: *mut ngx_http_request_t,
    context: &CaptchaPostContext,
    config: &CaptchaConfig,
    client_ip: &IpAddr,
    error_message: &str,
) {
    unsafe {
        if context.template.is_null() {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
            return;
        }

        let uri = get_request_uri(r);
        let template = &*context.template;
        let body = render_captcha_page(template, config, client_ip, &uri, Some(error_message));

        // Set status code (200 for captcha challenge)
        (*r).headers_out.status = 200;
        (*r).headers_out.content_length_n = body.len() as i64;

        // Add headers
        add_header(r, "Content-Type", "text/html; charset=utf-8");
        add_header(
            r,
            "Cache-Control",
            "no-store, no-cache, must-revalidate, max-age=0",
        );
        add_header(r, "Pragma", "no-cache");

        // Allocate body buffer
        let body_data = ngx_palloc((*r).pool, body.len()) as *mut u8;
        if body_data.is_null() {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
            return;
        }
        std::ptr::copy_nonoverlapping(body.as_ptr(), body_data, body.len());

        // Create buffer
        let buf = ngx_palloc((*r).pool, std::mem::size_of::<ngx_buf_t>()) as *mut ngx_buf_t;
        if buf.is_null() {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
            return;
        }
        std::ptr::write_bytes(buf, 0, 1);
        (*buf).pos = body_data;
        (*buf).last = body_data.add(body.len());
        (*buf).set_memory(1);
        (*buf).set_last_buf(1);
        (*buf).set_last_in_chain(1);

        // Create chain link
        let cl = ngx::ffi::ngx_alloc_chain_link((*r).pool);
        if cl.is_null() {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
            return;
        }
        (*cl).buf = buf;
        (*cl).next = std::ptr::null_mut();

        // Send headers
        let rc = ngx::ffi::ngx_http_send_header(r);
        if rc == ngx::ffi::NGX_ERROR as ngx_int_t || rc > ngx::ffi::NGX_OK as ngx_int_t {
            ngx_http_finalize_request(r, rc);
            return;
        }

        // Send body
        let rc = ngx::ffi::ngx_http_output_filter(r, cl);
        ngx_http_finalize_request(r, rc);
    }
}

/// Render a captcha page from a configured template file.
fn render_captcha_page(
    template: &Template,
    config: &CaptchaConfig,
    client_ip: &IpAddr,
    form_action: &str,
    error_message: Option<&str>,
) -> Vec<u8> {
    let mut vars = TemplateVariables::new();
    vars.client_ip = Some(client_ip.to_string());
    vars.captcha_site_key = Some(config.site_key.clone());
    vars.captcha_script_url = Some(config.provider.script_url().to_string());
    vars.captcha_div_class = Some(config.provider.div_class().to_string());
    vars.captcha_error = error_message.map(|s| s.to_string());
    vars.form_action = Some(form_action.to_string());
    template.render(&vars).into_bytes()
}

/// Add a header to the response
unsafe fn add_header(r: *mut ngx_http_request_t, name: &str, value: &str) {
    unsafe {
        let h = ngx::ffi::ngx_list_push(&mut (*r).headers_out.headers)
            as *mut ngx::ffi::ngx_table_elt_t;
        if h.is_null() {
            return;
        }

        // Allocate and copy name
        let name_data = ngx_palloc((*r).pool, name.len()) as *mut u8;
        if !name_data.is_null() {
            std::ptr::copy_nonoverlapping(name.as_ptr(), name_data, name.len());
            (*h).key.data = name_data;
            (*h).key.len = name.len();
        }

        // Allocate and copy value
        let value_data = ngx_palloc((*r).pool, value.len()) as *mut u8;
        if !value_data.is_null() {
            std::ptr::copy_nonoverlapping(value.as_ptr(), value_data, value.len());
            (*h).value.data = value_data;
            (*h).value.len = value.len();
        }

        (*h).hash = 1;
    }
}

/// Get the request URI as a string (path + query args).
unsafe fn get_request_uri(r: *mut ngx_http_request_t) -> String {
    unsafe {
        let unparsed = &(*r).unparsed_uri;
        if unparsed.data.is_null() || unparsed.len == 0 {
            return "/".to_string();
        }
        let data = std::slice::from_raw_parts(unparsed.data, unparsed.len);
        std::str::from_utf8(data).unwrap_or("/").to_string()
    }
}

/// Check if the Content-Type is application/x-www-form-urlencoded
///
/// # Safety
/// Requires a valid NGINX request pointer
pub unsafe fn is_form_urlencoded(r: *const ngx_http_request_t) -> bool {
    unsafe {
        if r.is_null() {
            return false;
        }

        let content_type = (*r).headers_in.content_type;
        if content_type.is_null() {
            return false;
        }

        let ct = &(*content_type);
        if ct.value.data.is_null() || ct.value.len == 0 {
            return false;
        }

        let ct_data = std::slice::from_raw_parts(ct.value.data, ct.value.len);
        if let Ok(ct_str) = std::str::from_utf8(ct_data) {
            return ct_str
                .to_lowercase()
                .starts_with("application/x-www-form-urlencoded");
        }

        false
    }
}

/// Maximum body size we'll accept for captcha verification (64KB should be plenty)
pub const MAX_CAPTCHA_BODY_SIZE: i64 = 64 * 1024;

/// Check if the request body size is acceptable for captcha verification
///
/// # Safety
/// Requires a valid NGINX request pointer
pub unsafe fn is_body_size_acceptable(r: *const ngx_http_request_t) -> bool {
    unsafe {
        let content_length = get_content_length(r);

        // Chunked uploads are not buffered in memory for captcha verification.
        if content_length < 0 {
            return false;
        }

        // Check against maximum
        content_length <= MAX_CAPTCHA_BODY_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_body_size() {
        assert_eq!(MAX_CAPTCHA_BODY_SIZE, 65536);
    }
}
