use core::ptr::NonNull;
use ngx::ffi::ngx_log_t;

pub trait AsLogPtr {
    fn as_log_ptr(&self) -> *mut ngx_log_t;
}

impl<T: AsLogPtr + ?Sized> AsLogPtr for &T {
    fn as_log_ptr(&self) -> *mut ngx_log_t {
        T::as_log_ptr(self)
    }
}

impl<T: AsLogPtr + ?Sized> AsLogPtr for &mut T {
    fn as_log_ptr(&self) -> *mut ngx_log_t {
        T::as_log_ptr(self)
    }
}

impl AsLogPtr for *mut ngx_log_t {
    fn as_log_ptr(&self) -> *mut ngx_log_t {
        *self
    }
}

impl AsLogPtr for NonNull<ngx_log_t> {
    fn as_log_ptr(&self) -> *mut ngx_log_t {
        self.as_ptr()
    }
}

impl AsLogPtr for ngx::ffi::ngx_conf_t {
    fn as_log_ptr(&self) -> *mut ngx_log_t {
        self.log
    }
}

impl AsLogPtr for ngx::ffi::ngx_cycle_t {
    fn as_log_ptr(&self) -> *mut ngx_log_t {
        self.log
    }
}

impl AsLogPtr for ngx::ffi::ngx_connection_t {
    fn as_log_ptr(&self) -> *mut ngx_log_t {
        self.log
    }
}

#[inline(always)]
pub fn as_log_ptr(x: impl AsLogPtr) -> *mut ngx_log_t {
    x.as_log_ptr()
}

/// Global (cycle) log when the NGINX cycle is initialized.
#[inline(always)]
pub fn cycle_log() -> NonNull<ngx_log_t> {
    ngx::log::ngx_cycle_log()
}

#[macro_export]
macro_rules! crowdsec_error {
    ( $log:expr, $($arg:tt)+ ) => ({
        ngx::ngx_log_error!(ngx::ffi::NGX_LOG_ERR, $crate::log::as_log_ptr(&$log), $($arg)+);
    });
}

#[macro_export]
macro_rules! crowdsec_warn {
    ( $log:expr, $($arg:tt)+ ) => ({
        ngx::ngx_log_error!(ngx::ffi::NGX_LOG_WARN, $crate::log::as_log_ptr(&$log), $($arg)+);
    });
}

#[macro_export]
macro_rules! crowdsec_notice {
    ( $log:expr, $($arg:tt)+ ) => ({
        ngx::ngx_log_error!(ngx::ffi::NGX_LOG_NOTICE, $crate::log::as_log_ptr(&$log), $($arg)+);
    });
}

#[macro_export]
macro_rules! crowdsec_info {
    ( $log:expr, $($arg:tt)+ ) => ({
        ngx::ngx_log_error!(ngx::ffi::NGX_LOG_INFO, $crate::log::as_log_ptr(&$log), $($arg)+);
    });
}

#[macro_export]
macro_rules! crowdsec_debug {
    ( $log:expr, $($arg:tt)+ ) => ({
        ngx::ngx_log_debug!($crate::log::as_log_ptr(&$log), $($arg)+);
    });
}
