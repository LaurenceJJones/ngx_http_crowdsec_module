//! POST body reading utilities for NGINX
//!
//! NGINX's access phase runs before the request body is read. This module
//! provides utilities to read the body asynchronously using callbacks.

use crate::captcha::config::CaptchaConfig;
use crate::captcha::cookie::{SameSite, build_set_cookie, should_cookie_be_secure};
use crate::captcha::jwt::JwtManager;
use crate::captcha::verifier::{VerifyResult, parse_captcha_response, verify_captcha};
use crate::handler::{HandlerResult, StoredPhaseResult};
use crate::request_body::{
    BodyExtractResult, CAPTCHA_POST_CTX_MAGIC, extract_request_body_limited, finalize_allow,
    finish_access_body_read, get_content_length, get_request_log, initiate_body_read as start_body_read,
    module_ctx_slot, request_ctx_magic,
};
use crate::captcha::handler::{captcha_return_uri, captcha_template_vars};
use crate::template::Template;
use ngx::ffi::{
    NGX_HTTP_INTERNAL_SERVER_ERROR, ngx_buf_t, ngx_http_finalize_request, ngx_http_request_t,
    ngx_int_t, ngx_palloc,
};
use ngx::http::Request;
use ngx::ngx_log_debug;
use std::net::IpAddr;
use std::ptr;

/// Context stored in the request for captcha POST handling
#[repr(C)]
pub struct CaptchaPostContext {
    pub magic: u32,
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
    /// Outcome stored so ACCESS re-entry after `finalize_allow` does not re-read the body.
    pub stored_result: u8,
}

impl CaptchaPostContext {
    /// Create context from captcha config
    pub fn from_config(config: &CaptchaConfig, client_ip: &IpAddr) -> Self {
        let ip_str = client_ip.to_string();
        let ip_bytes = ip_str.as_bytes();
        let mut client_ip_arr = [0u8; 64];
        let ip_len = ip_bytes.len().min(client_ip_arr.len());
        client_ip_arr[..ip_len].copy_from_slice(&ip_bytes[..ip_len]);

        let secret_bytes = config.secret_key.as_bytes();
        let mut secret_arr = [0u8; 256];
        let secret_len = secret_bytes.len().min(secret_arr.len());
        secret_arr[..secret_len].copy_from_slice(&secret_bytes[..secret_len]);

        let site_bytes = config.site_key.as_bytes();
        let mut site_arr = [0u8; 256];
        let site_len = site_bytes.len().min(site_arr.len());
        site_arr[..site_len].copy_from_slice(&site_bytes[..site_len]);

        let cookie_bytes = config.cookie_name.as_bytes();
        let mut cookie_arr = [0u8; 64];
        let cookie_len = cookie_bytes.len().min(cookie_arr.len());
        cookie_arr[..cookie_len].copy_from_slice(&cookie_bytes[..cookie_len]);

        Self {
            magic: CAPTCHA_POST_CTX_MAGIC,
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
            stored_result: StoredPhaseResult::Unset as u8,
        }
    }

    fn bounded_str<'a>(buf: &'a [u8], len: usize, fallback: &'a str) -> &'a str {
        let len = len.min(buf.len());
        std::str::from_utf8(&buf[..len]).unwrap_or(fallback)
    }

    fn client_ip_str(&self) -> &str {
        Self::bounded_str(&self.client_ip, self.client_ip_len, "unknown")
    }

    fn secret_key_str(&self) -> &str {
        Self::bounded_str(&self.secret_key, self.secret_key_len, "")
    }

    fn site_key_str(&self) -> &str {
        Self::bounded_str(&self.site_key, self.site_key_len, "")
    }

    fn cookie_name_str(&self) -> &str {
        Self::bounded_str(&self.cookie_name, self.cookie_name_len, "crowdsec_captcha")
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

    fn store_result(&mut self, result: HandlerResult) {
        self.stored_result = StoredPhaseResult::encode(result);
    }

    fn take_result(&self) -> Option<HandlerResult> {
        StoredPhaseResult::decode(self.stored_result)
    }

    /// Store the outcome (for ACCESS re-entry) then allow, deny, or leave a sent response.
    unsafe fn finish(
        &self,
        r: *mut ngx_http_request_t,
        ctx_ptr: *mut *mut std::ffi::c_void,
        result: HandlerResult,
    ) {
        unsafe {
            let ctx_mut = *ctx_ptr as *mut CaptchaPostContext;
            if !ctx_mut.is_null() {
                (*ctx_mut).store_result(result);
            }
            match result {
                HandlerResult::Declined | HandlerResult::Error => finalize_allow(r),
                HandlerResult::Forbidden => {
                    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
                }
                HandlerResult::Done | HandlerResult::BodyReadPending => {}
            }
        }
    }
}

/// Resume ACCESS after a captcha body callback (stored result or still waiting).
///
/// # Safety
/// Valid NGINX request pointer.
pub unsafe fn resume_body_read(r: *mut ngx_http_request_t) -> Option<HandlerResult> {
    unsafe {
        if request_ctx_magic(r) != Some(CAPTCHA_POST_CTX_MAGIC) {
            return None;
        }
        let ctx = *module_ctx_slot(r) as *const CaptchaPostContext;
        match (*ctx).take_result() {
            Some(result) => Some(result),
            None => Some(HandlerResult::BodyReadPending),
        }
    }
}

/// Initiate ACCESS-phase body reading for captcha POST.
///
/// After OK/AGAIN, balance the extra request count (`finish_access_body_read`) and
/// return `BodyReadPending`. The callback applies the outcome (same as nginx mirror).
///
/// # Safety
/// Requires valid NGINX request pointer and module reference
pub unsafe fn initiate_body_read(
    r: *mut ngx_http_request_t,
    config: &CaptchaConfig,
    client_ip: &IpAddr,
) -> HandlerResult {
    unsafe {
        // Allocate context from the main request pool (ctx is stored on main->ctx).
        let main_r = if (*r).main.is_null() { r } else { (*r).main };
        let ctx = ngx_palloc((*main_r).pool, std::mem::size_of::<CaptchaPostContext>())
            as *mut CaptchaPostContext;

        if ctx.is_null() {
            ngx_log_debug!(
                get_request_log(r),
                "crowdsec: failed to allocate captcha context"
            );
            return HandlerResult::Error;
        }

        std::ptr::write(ctx, CaptchaPostContext::from_config(config, client_ip));

        let rc = start_body_read(r, ctx.cast(), captcha_body_handler);
        if finish_access_body_read(r, rc) {
            return HandlerResult::BodyReadPending;
        }

        HandlerResult::Error
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

        let main_r = if (*r).main.is_null() { r } else { (*r).main };
        let ctx_ptr = module_ctx_slot(r);
        let ctx = *ctx_ptr as *const CaptchaPostContext;

        if ctx.is_null() || (*ctx).magic != CAPTCHA_POST_CTX_MAGIC {
            ngx_log_debug!(log, "crowdsec: captcha context is invalid in body handler");
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
            return;
        }

        let context = &*ctx;
        let finish = |result: HandlerResult| context.finish(r, ctx_ptr, result);

        let config = context.to_config();
        let client_ip_str = context.client_ip_str();

        let client_ip: IpAddr = match client_ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                ngx_log_debug!(log, "crowdsec: failed to parse client IP from context");
                finish(HandlerResult::Error);
                return;
            }
        };

        let request = Request::from_ngx_http_request(main_r);
        let uri = captcha_return_uri(&request);
        let template = match crate::crowdsec_loc_conf(&request).and_then(|l| l.captcha_template.as_ref())
        {
            Some(t) => t.clone(),
            None => {
                ngx_log_debug!(log, "crowdsec: captcha template missing in body handler");
                finish(HandlerResult::Error);
                return;
            }
        };

        let send_error = |msg: &str| {
            send_captcha_error_page(r, &template, &config, &client_ip, &uri, msg);
            finish(HandlerResult::Done);
        };

        let body = match extract_request_body_limited(
            r,
            MAX_CAPTCHA_BODY_SIZE as usize,
            false,
        ) {
            BodyExtractResult::Ok(body) => body,
            _ => {
                send_error("Request too large or unreadable.");
                return;
            }
        };
        ngx_log_debug!(log, "crowdsec: extracted body, {} bytes", body.len());

        if body.is_empty() {
            send_error("No form data received. Please try again.");
            return;
        }

        let captcha_response = match parse_captcha_response(&body, config.provider) {
            Some(resp) => resp,
            None => {
                send_error("Captcha response not found. Please complete the challenge.");
                return;
            }
        };

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
                let jwt_manager = JwtManager::new(config.signing_key);

                let ip_for_token = if config.bind_ip {
                    Some(client_ip_str.to_string())
                } else {
                    None
                };

                let claims = crate::captcha::jwt::CaptchaClaims::new(
                    ip_for_token.as_deref(),
                    config.expiry_secs,
                    Some(&uri),
                );

                match jwt_manager.create_token(&claims) {
                    Ok(token) => {
                        ngx_log_debug!(log, "crowdsec: token created, sending redirect to {}", uri);
                        send_success_redirect(r, &config, &token, &uri);
                        ngx_log_debug!(log, "crowdsec: redirect sent");
                        finish(HandlerResult::Done);
                    }
                    Err(e) => {
                        ngx_log_debug!(log, "crowdsec: failed to create session token: {}", e);
                        send_error("Internal error. Please try again.");
                    }
                }
            }
            VerifyResult::Failed(reason) => {
                ngx_log_debug!(log, "crowdsec: captcha verification failed: {}", reason);
                let error_msg = format!("Verification failed: {}. Please try again.", reason);
                send_error(&error_msg);
            }
            VerifyResult::Error(err) => {
                if config.fail_open {
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
                        finish(HandlerResult::Declined);
                        return;
                    }
                }
                send_error("Verification service unavailable. Please try again.");
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
unsafe fn send_buffered_response(
    r: *mut ngx_http_request_t,
    status: usize,
    headers: &[(&str, &str)],
    body: &[u8],
) {
    unsafe {
        (*r).set_keepalive(0);
        (*r).headers_out.status = status as ngx::ffi::ngx_uint_t;
        (*r).headers_out.content_length_n = body.len() as i64;
        for (name, value) in headers {
            add_header(r, name, value);
        }

        let body_data = ngx_palloc((*r).pool, body.len()) as *mut u8;
        if body_data.is_null() {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
            return;
        }
        std::ptr::copy_nonoverlapping(body.as_ptr(), body_data, body.len());

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

        let cl = ngx::ffi::ngx_alloc_chain_link((*r).pool);
        if cl.is_null() {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t);
            return;
        }
        (*cl).buf = buf;
        (*cl).next = std::ptr::null_mut();

        let rc = ngx::ffi::ngx_http_send_header(r);
        if rc == ngx::ffi::NGX_ERROR as ngx_int_t || rc > ngx::ffi::NGX_OK as ngx_int_t {
            ngx_http_finalize_request(r, rc);
            return;
        }
        let rc = ngx::ffi::ngx_http_output_filter(r, cl);
        ngx_http_finalize_request(r, rc);
    }
}

unsafe fn send_success_redirect(
    r: *mut ngx_http_request_t,
    config: &CaptchaConfig,
    token: &str,
    redirect_uri: &str,
) {
    unsafe {
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
        send_buffered_response(
            r,
            303,
            &[
                ("Location", redirect_uri),
                ("Set-Cookie", &cookie),
                ("Content-Type", "text/plain"),
                ("Cache-Control", "no-store, no-cache, must-revalidate"),
            ],
            b"Redirecting...",
        );
    }
}

unsafe fn send_captcha_error_page(
    r: *mut ngx_http_request_t,
    template: &Template,
    config: &CaptchaConfig,
    client_ip: &IpAddr,
    form_action: &str,
    error_message: &str,
) {
    unsafe {
        let vars = captcha_template_vars(config, client_ip, form_action.to_string(), Some(error_message));
        let body = template.render(&vars).into_bytes();
        send_buffered_response(
            r,
            200,
            &[
                ("Content-Type", "text/html; charset=utf-8"),
                (
                    "Cache-Control",
                    "no-store, no-cache, must-revalidate, max-age=0",
                ),
                ("Pragma", "no-cache"),
            ],
            &body,
        );
    }
}

/// Add a header to the response
unsafe fn add_header(r: *mut ngx_http_request_t, name: &str, value: &str) {
    unsafe {
        let h = ngx::ffi::ngx_list_push(&mut (*r).headers_out.headers)
            as *mut ngx::ffi::ngx_table_elt_t;
        if h.is_null() {
            return;
        }
        ptr::write_bytes(h, 0, 1);

        let name_data = ngx_palloc((*r).pool, name.len()) as *mut u8;
        let value_data = ngx_palloc((*r).pool, value.len()) as *mut u8;
        if name_data.is_null() || value_data.is_null() {
            return;
        }
        std::ptr::copy_nonoverlapping(name.as_ptr(), name_data, name.len());
        std::ptr::copy_nonoverlapping(value.as_ptr(), value_data, value.len());
        (*h).key.data = name_data;
        (*h).key.len = name.len();
        (*h).value.data = value_data;
        (*h).value.len = value.len();
        (*h).hash = 1;
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
    use crate::captcha::config::{CaptchaProvider, CookieSecure};
    use crate::request_body::CAPTCHA_POST_CTX_MAGIC;

    #[test]
    fn test_max_body_size() {
        assert_eq!(MAX_CAPTCHA_BODY_SIZE, 65536);
    }

    fn sample_config() -> CaptchaConfig {
        CaptchaConfig {
            provider: CaptchaProvider::Turnstile,
            site_key: "site".into(),
            secret_key: "secret".into(),
            signing_key: [7u8; 32],
            cookie_name: "crowdsec_captcha".into(),
            expiry_secs: 1800,
            fail_open: true,
            bind_ip: false,
            cookie_secure: CookieSecure::Auto,
        }
    }

    #[test]
    fn captcha_post_context_magic_and_bounds() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let ctx = CaptchaPostContext::from_config(&sample_config(), &ip);
        assert_eq!(ctx.magic, CAPTCHA_POST_CTX_MAGIC);
        assert_eq!(ctx.client_ip_str(), "2001:db8::1");
        assert_eq!(ctx.secret_key_str(), "secret");
        assert_eq!(ctx.take_result(), None);

        let mut ctx = ctx;
        ctx.client_ip_len = 10_000;
        assert_eq!(ctx.client_ip_str().len(), ctx.client_ip.len());
        ctx.store_result(HandlerResult::Done);
        assert_eq!(ctx.take_result(), Some(HandlerResult::Done));
    }
}
