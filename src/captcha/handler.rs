//! Captcha request handler
//!
//! This module combines JWT, cookie, and verification logic to handle
//! captcha challenges and session management.

use crate::captcha::config::CaptchaConfig;
use crate::captcha::cookie::get_cookie;
use crate::captcha::jwt::JwtManager;
use crate::shm;
use crate::template::{Template, TemplateVariables};
use crate::response::{HeaderFailureAction, body_chain, send_chain_and_finalize};
use ngx::core::Status;
use ngx::ffi::ngx_http_request_t;
use ngx::http::{HTTPStatus, Request};
use ngx::ngx_log_debug_http;
use std::net::IpAddr;
use std::sync::Arc;

/// Captcha handler combining session validation logic
pub struct CaptchaHandler<'a> {
    config: &'a CaptchaConfig,
    jwt_manager: JwtManager,
}

impl<'a> CaptchaHandler<'a> {
    /// Create a new captcha handler
    pub fn new(config: &'a CaptchaConfig) -> Self {
        Self {
            config,
            jwt_manager: JwtManager::new(config.signing_key),
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

    let cl = body_chain(request, &body)?;
    send_chain_and_finalize(request, cl, HeaderFailureAction::HeadOrError)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_captcha_template_renders_site_key() {
        let tpl = Template::parse_with_content_type(
            r#"<form action="{{form_action}}"><div class="{{captcha_div_class}}" data-sitekey="{{captcha_site_key}}"></div></form>"#,
            "text/html; charset=utf-8",
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
        let tpl = Template::parse_with_content_type(
            r#"{{captcha_error}}"#,
            "text/html; charset=utf-8",
        );
        let mut vars = TemplateVariables::new();
        vars.captcha_error = Some("Verification failed".to_string());

        let page = tpl.render(&vars);

        assert!(page.contains("Verification failed"));
    }
}
