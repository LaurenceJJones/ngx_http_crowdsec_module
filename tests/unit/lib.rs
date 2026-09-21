//! Execute production code's pure Rust tests without linking an nginx executable.
#![allow(dead_code)]

#[path = "../../src/captcha/config.rs"]
pub mod captcha_config;
mod captcha {
    pub use crate::captcha_config as config;
}
#[path = "../../src/expiry.rs"]
mod expiry;
#[path = "../../src/captcha/jwt.rs"]
mod jwt;
#[path = "../../src/lapi.rs"]
mod lapi;
#[path = "../../src/captcha/redirect.rs"]
mod redirect;
#[path = "../../src/template.rs"]
mod template;
#[path = "../../src/types.rs"]
mod types;
#[path = "../../src/captcha/verifier.rs"]
mod verifier;
