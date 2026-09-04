//! NGINX configuration helpers.

pub mod ext;

use core::error::Error;
use core::fmt;

pub use ext::NgxConfExt;

/// Static configuration validation message for [`NgxConfExt::error`].
#[derive(Debug, Clone, Copy)]
pub struct ConfValueError(pub &'static str);

impl fmt::Display for ConfValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Error for ConfValueError {}
