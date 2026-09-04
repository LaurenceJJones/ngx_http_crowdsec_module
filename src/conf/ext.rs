//! Extension traits for nginx-sys types.

use core::error::Error as StdError;
use core::ffi::c_char;
use core::ptr;

use ngx::ffi::{ngx_conf_t, ngx_str_t, NGX_LOG_EMERG};
use ngx::core::NGX_CONF_ERROR;
use ngx::ngx_conf_log_error;

pub trait NgxConfExt {
    fn args(&self) -> &[ngx_str_t];
    fn args_mut(&mut self) -> &mut [ngx_str_t];
    fn error(&self, dir: impl AsRef<[u8]>, err: &dyn StdError) -> *mut c_char;
    fn pool(&self) -> ngx::core::Pool;
}

impl NgxConfExt for ngx_conf_t {
    fn args(&self) -> &[ngx_str_t] {
        // SAFETY: cf.args is an ngx_array_t of ngx_str_t when populated by the parser.
        unsafe {
            self.args
                .as_ref()
                .map(|x| x.as_slice())
                .unwrap_or_default()
        }
    }

    fn args_mut(&mut self) -> &mut [ngx_str_t] {
        // SAFETY: cf.args is an ngx_array_t of ngx_str_t when populated by the parser.
        unsafe {
            self.args
                .as_mut()
                .map(|x| x.as_slice_mut())
                .unwrap_or_default()
        }
    }

    fn error(&self, dir: impl AsRef<[u8]>, err: &dyn StdError) -> *mut c_char {
        // ngx_conf_log_error does not modify cf; log is mutable as a pointer.
        let cfp = ptr::from_ref(self).cast_mut();
        let dir = ngx::core::NgxStr::from_bytes(dir.as_ref());
        ngx_conf_log_error!(NGX_LOG_EMERG, cfp, "{}: {}", dir, err);
        NGX_CONF_ERROR
    }

    fn pool(&self) -> ngx::core::Pool {
        // SAFETY: cf always has a valid pool during configuration parsing.
        unsafe { ngx::core::Pool::from_ngx_pool(self.pool) }
    }
}
