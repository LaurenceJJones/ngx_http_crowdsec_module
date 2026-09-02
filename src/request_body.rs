//! Shared helpers for reading client request bodies before the upstream handler runs.
//!
//! NGINX's access phase executes before the body is buffered. Callers use
//! [`initiate_body_read`] and handle the result in a post-read callback.

use ngx::ffi::{
    NGX_AGAIN, NGX_HTTP_INTERNAL_SERVER_ERROR, ngx_buf_t, ngx_chain_t, ngx_http_finalize_request,
    ngx_http_read_client_request_body, ngx_http_request_t, ngx_int_t, ngx_palloc,
};
use ngx::ngx_log_debug;
use std::ffi::CStr;
use std::fs::File;
use std::io::Read;

/// Magic stored in [`super::appsec::AppSecBodyContext`].
pub const APPSEC_BODY_CTX_MAGIC: u32 = 0xA990_5EC1;

/// Result of extracting a request body after NGINX has read it.
#[derive(Debug, PartialEq, Eq)]
pub enum BodyExtractResult {
    Ok(Vec<u8>),
    /// Body was spooled to disk and could not be read (or reading is disabled).
    Unreadable,
    TooLarge,
}

/// # Safety
/// Valid NGINX request pointer.
pub unsafe fn get_request_log(r: *const ngx_http_request_t) -> *mut ngx::ffi::ngx_log_t {
    unsafe { (*(*r).connection).log }
}

/// # Safety
/// Valid NGINX request pointer.
pub unsafe fn has_request_body(r: *const ngx_http_request_t) -> bool {
    unsafe {
        if r.is_null() {
            return false;
        }
        if (*r).headers_in.content_length_n > 0 {
            return true;
        }
        (*r).headers_in.chunked() != 0
    }
}

/// # Safety
/// Valid NGINX request pointer.
pub unsafe fn get_content_length(r: *const ngx_http_request_t) -> i64 {
    unsafe {
        if r.is_null() {
            return -1;
        }
        (*r).headers_in.content_length_n
    }
}

/// Read the buffered request body, optionally loading from the temp file NGINX created.
///
/// # Safety
/// The body must already have been read via [`initiate_body_read`].
pub unsafe fn extract_request_body_limited(
    r: *const ngx_http_request_t,
    max_bytes: usize,
    read_temp_file: bool,
) -> BodyExtractResult {
    unsafe {
        if r.is_null() {
            return BodyExtractResult::Ok(Vec::new());
        }

        let body = (*r).request_body;
        if body.is_null() {
            return BodyExtractResult::Ok(Vec::new());
        }

        let temp_file = (*body).temp_file;
        if !temp_file.is_null() {
            if !read_temp_file {
                ngx_log_debug!(
                    get_request_log(r),
                    "crowdsec: request body in temp file and temp-file read disabled"
                );
                return BodyExtractResult::Unreadable;
            }
            return read_temp_file_body(r, temp_file, max_bytes);
        }

        let mut result = Vec::new();
        let mut chain: *mut ngx_chain_t = (*body).bufs;

        while !chain.is_null() {
            let buf: *mut ngx_buf_t = (*chain).buf;
            if !buf.is_null() {
                let pos = (*buf).pos;
                let last = (*buf).last;
                if !pos.is_null() && !last.is_null() && last > pos {
                    let len = last.offset_from(pos) as usize;
                    if result.len().saturating_add(len) > max_bytes {
                        return BodyExtractResult::TooLarge;
                    }
                    let data = std::slice::from_raw_parts(pos, len);
                    result.extend_from_slice(data);
                }
            }
            chain = (*chain).next;
        }

        BodyExtractResult::Ok(result)
    }
}

/// Convenience wrapper used by captcha verification (small in-memory bodies only).
///
/// # Safety
/// Valid NGINX request pointer with body already read.
pub unsafe fn extract_request_body(r: *const ngx_http_request_t) -> Vec<u8> {
    match extract_request_body_limited(r, usize::MAX, false) {
        BodyExtractResult::Ok(body) => body,
        _ => Vec::new(),
    }
}

/// Start asynchronous client body reading; invokes `callback` when complete.
///
/// # Safety
/// Valid NGINX request pointer. `ctx` is stored in the module request context slot.
pub unsafe fn initiate_body_read(
    r: *mut ngx_http_request_t,
    ctx: *mut std::ffi::c_void,
    callback: unsafe extern "C" fn(*mut ngx_http_request_t),
) -> ngx_int_t {
    unsafe {
        let main_r = (*r).main;
        let module = &raw const crate::ngx_http_crowdsec_module;
        let ctx_ptr = (*main_r).ctx.wrapping_add((*module).ctx_index as usize);
        *ctx_ptr = ctx;

        let rc = ngx_http_read_client_request_body(r, Some(callback));

        if rc == NGX_AGAIN as ngx_int_t {
            return ngx::ffi::NGX_DONE as ngx_int_t;
        }

        if rc >= ngx::ffi::NGX_HTTP_SPECIAL_RESPONSE as ngx_int_t {
            return rc;
        }

        ngx::ffi::NGX_DONE as ngx_int_t
    }
}

/// Finalize the request after AppSec allows it to continue.
///
/// # Safety
/// Valid NGINX request pointer.
pub unsafe fn finalize_allow(r: *mut ngx_http_request_t) {
    unsafe {
        ngx_http_finalize_request(r, ngx::ffi::NGX_DECLINED as ngx_int_t);
    }
}

/// # Safety
/// Valid temp file pointer from NGINX's request body.
unsafe fn read_temp_file_body(
    r: *const ngx_http_request_t,
    temp_file: *mut ngx::ffi::ngx_temp_file_t,
    max_bytes: usize,
) -> BodyExtractResult {
    unsafe {
        let name = (*temp_file).file.name;
        if name.data.is_null() || name.len == 0 {
            return BodyExtractResult::Unreadable;
        }

        let path = match CStr::from_ptr(name.data.cast()).to_str() {
            Ok(p) => p,
            Err(_) => return BodyExtractResult::Unreadable,
        };

        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(_) => {
                ngx_log_debug!(
                    get_request_log(r),
                    "crowdsec: failed to open request body temp file"
                );
                return BodyExtractResult::Unreadable;
            }
        };

        let mut buf = vec![0u8; max_bytes.saturating_add(1)];
        let n = match file.read(&mut buf) {
            Ok(n) => n,
            Err(_) => return BodyExtractResult::Unreadable,
        };

        if n > max_bytes {
            return BodyExtractResult::TooLarge;
        }

        buf.truncate(n);
        BodyExtractResult::Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_extract_result_variants() {
        assert_eq!(BodyExtractResult::Ok(vec![1]), BodyExtractResult::Ok(vec![1]));
        assert_ne!(BodyExtractResult::Ok(vec![]), BodyExtractResult::Unreadable);
    }
}
