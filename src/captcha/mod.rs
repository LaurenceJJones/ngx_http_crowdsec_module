//! Captcha remediation module for CrowdSec NGINX integration
//!
//! This module provides captcha challenge handling including:
//! - Multiple provider support (hCaptcha, Turnstile, reCAPTCHA)
//! - JWT-based session management
//! - Secure cookie handling
//! - Provider API verification

pub mod body;
pub mod config;
pub mod cookie;
pub mod handler;
pub mod jwt;
pub mod verifier;

// Public API - only export what's used externally
pub use config::{CaptchaConfig, CaptchaProvider, CookieSecure};
pub use handler::{CaptchaHandler, send_captcha_page};
