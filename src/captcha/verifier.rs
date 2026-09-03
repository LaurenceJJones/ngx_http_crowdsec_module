//! Captcha verification with provider APIs
//!
//! Handles verification requests to hCaptcha, Turnstile, and reCAPTCHA APIs.

use crate::captcha::config::CaptchaProvider;
use serde::Deserialize;
use std::time::Duration;

/// Result of captcha verification
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyResult {
    /// Verification succeeded
    Success,
    /// Verification failed (user did not pass challenge)
    Failed(String),
    /// Error occurred during verification
    Error(VerifyError),
}

/// Errors that can occur during verification
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyError {
    /// Network error (connection failed, DNS error, etc.)
    NetworkError(String),
    /// Request timed out
    Timeout,
    /// Invalid response from provider
    InvalidResponse(String),
    /// Provider returned an error status
    ProviderError(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "network error: {}", msg),
            Self::Timeout => write!(f, "request timed out"),
            Self::InvalidResponse(msg) => write!(f, "invalid response: {}", msg),
            Self::ProviderError(msg) => write!(f, "provider error: {}", msg),
        }
    }
}

/// Provider verification response structure
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VerifyResponse {
    success: bool,
    #[serde(default)]
    challenge_ts: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(rename = "error-codes")]
    #[serde(default)]
    error_codes: Option<Vec<String>>,
}

/// Verify a captcha response with the provider
///
/// # Arguments
/// * `provider` - The captcha provider to verify with
/// * `secret_key` - The secret key for the provider
/// * `response` - The captcha response token from the form
/// * `remote_ip` - The client's IP address
///
/// # Returns
/// * `VerifyResult::Success` if the captcha was solved correctly
/// * `VerifyResult::Failed` if the captcha was not solved correctly
/// * `VerifyResult::Error` if an error occurred during verification
pub fn verify_captcha(
    provider: CaptchaProvider,
    secret_key: &str,
    response: &str,
    remote_ip: &str,
) -> VerifyResult {
    let url = provider.verify_url();

    // Build form data
    let form_body = format!(
        "secret={}&response={}&remoteip={}",
        url_encode(secret_key),
        url_encode(response),
        url_encode(remote_ip),
    );

    // Make HTTP request (blocking - runs in NGINX worker)
    // Use a short timeout since this blocks the worker
    let result = ureq::post(url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .timeout(Duration::from_secs(5))
        .send_string(&form_body);

    match result {
        Ok(resp) => {
            // Parse JSON response
            match resp.into_json::<VerifyResponse>() {
                Ok(verify_response) => {
                    if verify_response.success {
                        VerifyResult::Success
                    } else {
                        let errors = verify_response.error_codes.unwrap_or_default().join(", ");
                        if errors.is_empty() {
                            VerifyResult::Failed("verification failed".to_string())
                        } else {
                            VerifyResult::Failed(errors)
                        }
                    }
                }
                Err(e) => VerifyResult::Error(VerifyError::InvalidResponse(e.to_string())),
            }
        }
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            VerifyResult::Error(VerifyError::ProviderError(format!(
                "HTTP {}: {}",
                code,
                body.chars().take(100).collect::<String>()
            )))
        }
        Err(ureq::Error::Transport(e)) => {
            // Check if it's a timeout by examining the error message
            let err_str = e.to_string().to_lowercase();
            if err_str.contains("timeout") || err_str.contains("timed out") {
                VerifyResult::Error(VerifyError::Timeout)
            } else {
                VerifyResult::Error(VerifyError::NetworkError(e.to_string()))
            }
        }
    }
}

/// URL-encode a string for form data
fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(c);
            }
            _ => {
                for byte in c.to_string().as_bytes() {
                    result.push('%');
                    result.push_str(&format!("{:02X}", byte));
                }
            }
        }
    }
    result
}

/// Parse the captcha response from form-urlencoded POST body
pub fn parse_captcha_response(body: &[u8], provider: CaptchaProvider) -> Option<String> {
    let body_str = std::str::from_utf8(body).ok()?;

    // Look for the provider-specific field
    let field_name = provider.response_field();

    for pair in body_str.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let decoded_key = url_decode(key);
            if decoded_key == field_name {
                return Some(url_decode(value));
            }
        }
    }

    // Also try generic field names that might be used
    let generic_fields = ["captcha-response", "captcha_response", "response"];
    for pair in body_str.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let decoded_key = url_decode(key);
            if generic_fields.contains(&decoded_key.as_str()) {
                return Some(url_decode(value));
            }
        }
    }

    None
}

/// URL-decode a string
fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            // Try to parse hex escape
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            // Failed to parse, keep original
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("hello"), "hello");
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("a=b&c=d"), "a%3Db%26c%3Dd");
        assert_eq!(url_encode("test@example.com"), "test%40example.com");
    }

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("hello"), "hello");
        assert_eq!(url_decode("hello%20world"), "hello world");
        assert_eq!(url_decode("hello+world"), "hello world");
        assert_eq!(url_decode("a%3Db%26c%3Dd"), "a=b&c=d");
    }

    #[test]
    fn test_parse_captcha_response_hcaptcha() {
        let body = b"h-captcha-response=test-token-123&other=value";
        let result = parse_captcha_response(body, CaptchaProvider::HCaptcha);
        assert_eq!(result, Some("test-token-123".to_string()));
    }

    #[test]
    fn test_parse_captcha_response_turnstile() {
        let body = b"cf-turnstile-response=turnstile-token&submit=1";
        let result = parse_captcha_response(body, CaptchaProvider::Turnstile);
        assert_eq!(result, Some("turnstile-token".to_string()));
    }

    #[test]
    fn test_parse_captcha_response_recaptcha() {
        let body = b"g-recaptcha-response=recaptcha-token";
        let result = parse_captcha_response(body, CaptchaProvider::ReCaptcha);
        assert_eq!(result, Some("recaptcha-token".to_string()));
    }

    #[test]
    fn test_parse_captcha_response_not_found() {
        let body = b"other=value&another=thing";
        let result = parse_captcha_response(body, CaptchaProvider::HCaptcha);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_captcha_response_encoded() {
        let body = b"h-captcha-response=token%20with%20spaces";
        let result = parse_captcha_response(body, CaptchaProvider::HCaptcha);
        assert_eq!(result, Some("token with spaces".to_string()));
    }
}
