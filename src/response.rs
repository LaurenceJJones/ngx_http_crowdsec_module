//! Shared helpers for sending HTTP responses and finalizing requests.

use ngx::core::{Buffer, Status};
use ngx::ffi::{ngx_alloc_chain_link, ngx_chain_t, ngx_http_finalize_request, ngx_http_request_t};
use ngx::http::Request;

/// How to handle a non-OK result from [`Request::send_header`].
pub enum HeaderFailureAction {
    /// Finalize with the header status and return `Ok(())`.
    Finalize,
    /// Return `Err(())` without finalizing.
    Error,
    /// For HEAD requests, finalize and return `Ok(())`; otherwise return `Err(())`.
    HeadOrError,
}

/// Disable keepalive on the underlying request so the connection closes cleanly.
pub fn disable_keepalive(request: &mut Request) {
    let r: *mut ngx_http_request_t = request.as_mut() as *mut _;
    unsafe {
        (*r).set_keepalive(0);
    }
}

/// Allocate a single-buffer output chain from `body` in the request pool.
pub fn body_chain(request: &Request, body: &str) -> Result<*mut ngx_chain_t, ()> {
    let pool = request.pool();
    let mut buffer = pool.create_buffer_from_str(body).ok_or(())?;
    buffer.set_last_buf(true);
    buffer.set_last_in_chain(true);

    unsafe {
        let cl = ngx_alloc_chain_link(pool.as_ptr());
        if cl.is_null() {
            return Err(());
        }
        (*cl).buf = buffer.as_ngx_buf_mut();
        (*cl).next = std::ptr::null_mut();
        Ok(cl)
    }
}

/// Send headers, body via [`Request::output_filter`], and finalize the request.
pub fn send_chain_and_finalize(
    request: &mut Request,
    cl: *mut ngx_chain_t,
    header_failure: HeaderFailureAction,
) -> Result<(), ()> {
    let header_status = request.send_header();
    if header_status != Status::NGX_OK {
        return match header_failure {
            HeaderFailureAction::Finalize => {
                finalize_request(request, header_status);
                Ok(())
            }
            HeaderFailureAction::Error => Err(()),
            HeaderFailureAction::HeadOrError => {
                if request.header_only() {
                    finalize_request(request, header_status);
                    Ok(())
                } else {
                    Err(())
                }
            }
        };
    }

    let out_status = request.output_filter(unsafe { &mut *cl });
    finalize_request(request, out_status);
    Ok(())
}

/// Build a body chain, send it, and finalize the request.
pub fn send_body_and_finalize(
    request: &mut Request,
    body: &str,
    header_failure: HeaderFailureAction,
) -> Result<(), ()> {
    let cl = body_chain(request, body)?;
    send_chain_and_finalize(request, cl, header_failure)
}

fn finalize_request(request: &mut Request, status: Status) {
    let r: *mut ngx_http_request_t = request.as_mut() as *mut _;
    unsafe {
        ngx_http_finalize_request(r, status.into());
    }
}
