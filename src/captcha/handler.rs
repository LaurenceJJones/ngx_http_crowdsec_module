//! Captcha request handler
//!
//! This module combines JWT, cookie, and verification logic to handle
//! captcha challenges and session management.

use crate::captcha::config::CaptchaConfig;
use crate::captcha::cookie::{SameSite, build_set_cookie, get_cookie, is_https};
use crate::captcha::jwt::{CaptchaClaims, JwtManager};
use crate::captcha::verifier::{VerifyError, VerifyResult, verify_captcha};
use crate::shm;
use crate::template::{Template, TemplateVariables};
use ngx::core::{Buffer, Status};
use ngx::ffi::ngx_http_request_t;
use ngx::http::{HTTPStatus, Request};
use ngx::ngx_log_debug_http;
use std::net::IpAddr;
use std::sync::Arc;

/// Result of captcha handling
#[derive(Debug)]
pub enum CaptchaHandlerResult {
    /// Request should be allowed (valid session or verification passed)
    Allow,
    /// Captcha page was shown (response sent)
    PageShown,
    /// Body read initiated, waiting for callback
    BodyReadPending,
    /// Error occurred
    Error(String),
}

/// Captcha handler combining all captcha logic
pub struct CaptchaHandler<'a> {
    config: &'a CaptchaConfig,
    jwt_manager: JwtManager,
    template: Option<&'a Arc<Template>>,
}

impl<'a> CaptchaHandler<'a> {
    /// Create a new captcha handler
    pub fn new(config: &'a CaptchaConfig, template: Option<&'a Arc<Template>>) -> Self {
        Self {
            config,
            jwt_manager: JwtManager::new(config.signing_key),
            template,
        }
    }

    /// Check if the request has a valid captcha session cookie
    pub fn has_valid_session(&self, request: &mut Request, client_ip: &IpAddr) -> bool {
        let r: *mut ngx_http_request_t = request.as_mut() as *mut _;

        // Try to get the captcha cookie
        let cookie_value = unsafe { get_cookie(r, &self.config.cookie_name) };

        let token = match cookie_value {
            Some(t) => t,
            None => return false,
        };

        // Determine IP to check based on bind_ip setting
        let ip_to_check = if self.config.bind_ip {
            Some(client_ip.to_string())
        } else {
            None
        };

        // Verify the JWT token
        match self
            .jwt_manager
            .verify_and_validate(&token, ip_to_check.as_deref())
        {
            Ok(_claims) => true,
            Err(e) => {
                ngx_log_debug_http!(request, "crowdsec: invalid captcha session token: {}", e);
                false
            }
        }
    }

    /// Create a new session token for a client
    pub fn create_session_token(
        &self,
        client_ip: &IpAddr,
        request_uri: Option<&str>,
    ) -> Result<String, String> {
        let ip_for_token = if self.config.bind_ip {
            Some(client_ip.to_string())
        } else {
            None
        };

        let claims = CaptchaClaims::new(
            ip_for_token.as_deref(),
            self.config.expiry_secs,
            request_uri,
        );

        self.jwt_manager
            .create_token(&claims)
            .map_err(|e| format!("failed to create token: {}", e))
    }

    /// Build the Set-Cookie header value for a session token
    pub fn build_session_cookie(&self, token: &str, is_secure: bool) -> String {
        build_set_cookie(
            &self.config.cookie_name,
            token,
            self.config.expiry_secs,
            "/",
            is_secure,
            true, // HttpOnly
            SameSite::Lax,
        )
    }

    /// Verify a captcha response with the provider
    pub fn verify_response(&self, response: &str, client_ip: &IpAddr) -> VerifyResult {
        verify_captcha(
            self.config.provider,
            &self.config.secret_key,
            response,
            &client_ip.to_string(),
        )
    }

    /// Check if we should fail open on a verification error
    pub fn should_fail_open(&self, error: &VerifyError) -> bool {
        if !self.config.fail_open {
            return false;
        }

        // Only fail open for network/provider errors, not for invalid responses
        matches!(
            error,
            VerifyError::NetworkError(_) | VerifyError::Timeout | VerifyError::ProviderError(_)
        )
    }

    /// Get the captcha provider configuration for templates
    pub fn get_provider_config(&self) -> (&'static str, &'static str, String) {
        (
            self.config.provider.script_url(),
            self.config.provider.div_class(),
            self.config.site_key.clone(),
        )
    }
}

/// Send a captcha challenge page
pub fn send_captcha_page(
    request: &mut Request,
    config: &CaptchaConfig,
    template: Option<&Arc<Template>>,
    client_ip: &IpAddr,
    error_message: Option<&str>,
) -> Result<(), ()> {
    // Build template variables
    let mut vars = TemplateVariables::new();
    vars.client_ip = Some(client_ip.to_string());

    // Get URI and method
    if let Ok(uri_str) = request.path().to_str() {
        vars.request_uri = Some(uri_str.to_string());
    }
    vars.request_method = Some(request.method().as_str().to_string());

    // Add captcha-specific variables
    vars.captcha_site_key = Some(config.site_key.clone());
    vars.captcha_script_url = Some(config.provider.script_url().to_string());
    vars.captcha_div_class = Some(config.provider.div_class().to_string());
    vars.captcha_error = error_message.map(|s| s.to_string());

    // Form action is the current URI (include query string)
    vars.form_action = Some(captcha_return_uri(request));

    // Render captcha page from the configured template file (required at config time).
    let tpl = template.ok_or(())?;
    let body = tpl.render(&vars);

    // Set status code (200 for captcha page)
    request.set_status(HTTPStatus::OK);

    // Set content length
    request.set_content_length_n(body.len());

    // Discard any request body
    request.discard_request_body();

    // Set headers
    request.add_header_out("Content-Type", "text/html; charset=utf-8");
    request.add_header_out(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, max-age=0",
    );
    request.add_header_out("Pragma", "no-cache");

    // Get pool and raw request pointer
    let pool = request.pool();
    let r: *mut ngx_http_request_t = request.as_mut() as *mut _;

    // Create buffer from rendered body
    let mut buffer = match pool.create_buffer_from_str(&body) {
        Some(buf) => buf,
        None => return Err(()),
    };

    // Mark buffer as last
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
    let header_status = request.send_header();
    if header_status != Status::NGX_OK {
        if request.header_only() {
            unsafe {
                ngx::ffi::ngx_http_finalize_request(r, header_status.into());
            }
            return Ok(());
        }
        return Err(());
    }

    // Send body
    let rc = unsafe { ngx::ffi::ngx_http_output_filter(r, cl) };

    // Finalize request
    unsafe {
        ngx::ffi::ngx_http_finalize_request(r, rc);
    }

    shm::metrics_inc_http_captcha();
    Ok(())
}

/// URI the client should return to after captcha (path + query string).
pub fn captcha_return_uri(request: &Request) -> String {
    request
        .unparsed_uri()
        .to_str()
        .unwrap_or("/")
        .to_string()
}

/// 303 redirect so the client repeats the request as GET (for static origins that reject POST).
pub fn send_see_other_redirect(request: &mut Request, redirect_uri: &str) -> Result<(), ()> {
    let r: *mut ngx_http_request_t = request.as_mut() as *mut _;
    request.set_status(HTTPStatus::SEE_OTHER);
    request.set_content_length_n(0);
    request.discard_request_body();
    request.add_header_out("Location", redirect_uri);
    request.add_header_out("Cache-Control", "no-store, no-cache, must-revalidate");
    let header_status = request.send_header();
    unsafe {
        ngx::ffi::ngx_http_finalize_request(r, header_status.into());
    }
    Ok(())
}

/// Send a redirect response after successful captcha verification
pub fn send_captcha_success_redirect(
    request: &mut Request,
    config: &CaptchaConfig,
    token: &str,
    redirect_uri: &str,
) -> Result<(), ()> {
    let r: *mut ngx_http_request_t = request.as_mut() as *mut _;

    // Determine if HTTPS
    let is_secure = unsafe { is_https(r) };

    // Build cookie header
    let cookie = build_set_cookie(
        &config.cookie_name,
        token,
        config.expiry_secs,
        "/",
        is_secure,
        true,
        SameSite::Lax,
    );

    // 303 See Other — follow-up must be GET (static sites often reject POST)
    request.set_status(HTTPStatus::SEE_OTHER);
    request.set_content_length_n(0);

    // Discard request body
    request.discard_request_body();

    // Set headers
    request.add_header_out("Location", redirect_uri);
    request.add_header_out("Set-Cookie", &cookie);
    request.add_header_out("Cache-Control", "no-store, no-cache, must-revalidate");

    // Send headers only (no body for redirect)
    let header_status = request.send_header();

    // Finalize
    unsafe {
        ngx::ffi::ngx_http_finalize_request(r, header_status.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_captcha_template_renders_site_key() {
        let tpl = Template::parse(
            r#"<form action="{{form_action}}"><div class="{{captcha_div_class}}" data-sitekey="{{captcha_site_key}}"></div></form>"#,
        );
        let mut vars = TemplateVariables::new();
        vars.captcha_site_key = Some("test-site-key".to_string());
        vars.captcha_div_class = Some("h-captcha".to_string());
        vars.form_action = Some("/test".to_string());

        let page = tpl.render(&vars);

        assert!(page.contains("test-site-key"));
        assert!(page.contains("/test"));
    }

    #[test]
    fn test_captcha_template_renders_error_variable() {
        let tpl = Template::parse(r#"{{captcha_error}}"#);
        let mut vars = TemplateVariables::new();
        vars.captcha_error = Some("Verification failed".to_string());

        let page = tpl.render(&vars);

        assert!(page.contains("Verification failed"));
    }
}
