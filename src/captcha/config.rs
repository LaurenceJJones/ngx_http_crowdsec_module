//! Captcha configuration types and provider definitions

use crate::template::BanTemplate;
use std::sync::Arc;

/// Cookie secure flag setting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CookieSecure {
    /// Auto-detect based on connection SSL or X-Forwarded-Proto header
    #[default]
    Auto,
    /// Always set Secure flag (use when behind TLS-terminating proxy)
    On,
    /// Never set Secure flag (for testing only)
    Off,
}

impl CookieSecure {
    /// Parse from configuration string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "on" | "true" | "yes" => Some(Self::On),
            "off" | "false" | "no" => Some(Self::Off),
            _ => None,
        }
    }
}

/// Supported captcha providers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaProvider {
    /// hCaptcha (https://www.hcaptcha.com/)
    HCaptcha,
    /// Cloudflare Turnstile (https://www.cloudflare.com/products/turnstile/)
    Turnstile,
    /// Google reCAPTCHA v2 (https://www.google.com/recaptcha/)
    ReCaptcha,
}

impl CaptchaProvider {
    /// Parse provider from configuration string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "hcaptcha" => Some(Self::HCaptcha),
            "turnstile" => Some(Self::Turnstile),
            "recaptcha" => Some(Self::ReCaptcha),
            _ => None,
        }
    }

    /// Get the verification API endpoint for this provider
    pub fn verify_url(&self) -> &'static str {
        match self {
            Self::HCaptcha => "https://api.hcaptcha.com/siteverify",
            Self::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            Self::ReCaptcha => "https://www.google.com/recaptcha/api/siteverify",
        }
    }

    /// Get the form field name that contains the captcha response
    pub fn response_field(&self) -> &'static str {
        match self {
            Self::HCaptcha => "h-captcha-response",
            Self::Turnstile => "cf-turnstile-response",
            Self::ReCaptcha => "g-recaptcha-response",
        }
    }

    /// Get the JavaScript widget URL for this provider
    pub fn script_url(&self) -> &'static str {
        match self {
            Self::HCaptcha => "https://js.hcaptcha.com/1/api.js",
            Self::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/api.js",
            Self::ReCaptcha => "https://www.google.com/recaptcha/api.js",
        }
    }

    /// Get the CSS class for the captcha widget div
    pub fn div_class(&self) -> &'static str {
        match self {
            Self::HCaptcha => "h-captcha",
            Self::Turnstile => "cf-turnstile",
            Self::ReCaptcha => "g-recaptcha",
        }
    }

    /// Get the sitekey attribute name for the widget
    pub fn sitekey_attr(&self) -> &'static str {
        match self {
            Self::HCaptcha => "data-sitekey",
            Self::Turnstile => "data-sitekey",
            Self::ReCaptcha => "data-sitekey",
        }
    }
}

/// Captcha configuration stored at main config level
#[derive(Debug, Clone)]
pub struct CaptchaConfig {
    /// The captcha provider to use
    pub provider: CaptchaProvider,
    /// Public site key for the captcha widget
    pub site_key: String,
    /// Secret key for server-side verification
    pub secret_key: String,
    /// HMAC signing key for JWT tokens (32 bytes)
    pub signing_key: [u8; 32],
    /// Cookie name for storing the captcha session
    pub cookie_name: String,
    /// Session expiry in seconds
    pub expiry_secs: u64,
    /// Whether to fail open when provider is unreachable
    pub fail_open: bool,
    /// Whether to bind JWT to client IP
    pub bind_ip: bool,
    /// Cookie Secure flag setting (auto/on/off)
    pub cookie_secure: CookieSecure,
}

impl Default for CaptchaConfig {
    fn default() -> Self {
        Self {
            // Tests only — nginx config must set crowdsec_captcha_provider explicitly.
            provider: CaptchaProvider::HCaptcha,
            site_key: String::new(),
            secret_key: String::new(),
            signing_key: [0u8; 32],
            cookie_name: "crowdsec_captcha".to_string(),
            expiry_secs: 3600,                 // 1 hour default
            fail_open: true,                   // Default to fail-open for availability
            bind_ip: true,                     // Default to binding JWT to IP for security
            cookie_secure: CookieSecure::Auto, // Auto-detect by default
        }
    }
}

impl CaptchaConfig {
    /// Check if captcha is fully configured
    pub fn is_configured(&self) -> bool {
        !self.site_key.is_empty() && !self.secret_key.is_empty() && self.signing_key != [0u8; 32]
    }
}

/// Location-level captcha configuration (can override template)
#[derive(Debug, Default, Clone)]
pub struct CaptchaLocConfig {
    /// Custom captcha template for this location
    pub template: Option<Arc<BanTemplate>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_from_str() {
        assert_eq!(
            CaptchaProvider::from_str("hcaptcha"),
            Some(CaptchaProvider::HCaptcha)
        );
        assert_eq!(
            CaptchaProvider::from_str("HCAPTCHA"),
            Some(CaptchaProvider::HCaptcha)
        );
        assert_eq!(
            CaptchaProvider::from_str("turnstile"),
            Some(CaptchaProvider::Turnstile)
        );
        assert_eq!(
            CaptchaProvider::from_str("recaptcha"),
            Some(CaptchaProvider::ReCaptcha)
        );
        assert_eq!(CaptchaProvider::from_str("invalid"), None);
    }

    #[test]
    fn test_provider_urls() {
        assert!(CaptchaProvider::HCaptcha.verify_url().contains("hcaptcha"));
        assert!(
            CaptchaProvider::Turnstile
                .verify_url()
                .contains("cloudflare")
        );
        assert!(CaptchaProvider::ReCaptcha.verify_url().contains("google"));
    }

    #[test]
    fn test_provider_response_fields() {
        assert_eq!(
            CaptchaProvider::HCaptcha.response_field(),
            "h-captcha-response"
        );
        assert_eq!(
            CaptchaProvider::Turnstile.response_field(),
            "cf-turnstile-response"
        );
        assert_eq!(
            CaptchaProvider::ReCaptcha.response_field(),
            "g-recaptcha-response"
        );
    }

    #[test]
    fn test_config_is_configured() {
        let mut config = CaptchaConfig::default();
        assert!(!config.is_configured());

        config.site_key = "test-site-key".to_string();
        assert!(!config.is_configured());

        config.secret_key = "test-secret-key".to_string();
        assert!(!config.is_configured());

        config.signing_key = [1u8; 32];
        assert!(config.is_configured());
    }
}
