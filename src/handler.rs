use crate::config::LocConfig;
use crate::shm;
use crate::template::{BanTemplate, TemplateVariables};
use ngx::core::{Buffer, Status};
use ngx::ffi::ngx_http_request_t;
use ngx::http::{HTTPStatus, Request};
use std::net::IpAddr;

/// Access phase handler result
pub enum HandlerResult {
    /// Allow the request to proceed
    Declined,
    /// Block the request with 403 Forbidden
    Forbidden,
    /// An error occurred, fail-open
    Error,
    /// Request has been fully handled (response sent and finalized)
    Done,
}

impl From<HandlerResult> for Status {
    fn from(result: HandlerResult) -> Self {
        match result {
            HandlerResult::Declined => Status::NGX_DECLINED,
            HandlerResult::Forbidden => Status::from(HTTPStatus::FORBIDDEN),
            HandlerResult::Error => Status::NGX_DECLINED, // Fail-open
            HandlerResult::Done => Status::NGX_DONE, // Request fully handled and finalized - don't touch it
        }
    }
}

/// Extract the client IP address from the NGINX request
pub fn get_client_ip(request: &Request) -> Option<IpAddr> {
    // Get the connection from the request
    let connection = request.connection();
    if connection.is_null() {
        return None;
    }

    // Get the sockaddr from the connection
    let sockaddr = unsafe { (*connection).sockaddr };
    if sockaddr.is_null() {
        return None;
    }

    // Parse based on address family
    let family = unsafe { (*sockaddr).sa_family };

    #[cfg(target_family = "unix")]
    {
        use std::net::{Ipv4Addr, Ipv6Addr};

        // AF_INET = 2, AF_INET6 = 10 on Linux
        if family == 2 {
            // IPv4
            let addr_in = sockaddr as *const libc::sockaddr_in;
            let ip_bytes = unsafe { (*addr_in).sin_addr.s_addr.to_ne_bytes() };
            return Some(IpAddr::V4(Ipv4Addr::from(ip_bytes)));
        } else if family == 10 {
            // IPv6
            let addr_in6 = sockaddr as *const libc::sockaddr_in6;
            let ip_bytes = unsafe { (*addr_in6).sin6_addr.s6_addr };
            return Some(IpAddr::V6(Ipv6Addr::from(ip_bytes)));
        }
    }

    None
}

/// Main access phase handler logic
///
/// This function checks if the client IP is banned according to CrowdSec decisions
/// stored in shared memory.
///
/// # Arguments
/// * `request` - The NGINX request (mutable for sending responses)
/// * `loc_conf` - The location configuration (already merged with parent)
///
/// # Returns
/// * `HandlerResult::Declined` - Allow the request
/// * `HandlerResult::Forbidden` - Block the request (IP is banned)
/// * `HandlerResult::Error` - Error occurred, fail-open
pub fn handle_access(request: &mut Request, loc_conf: &LocConfig) -> HandlerResult {
    // Check if module is enabled
    match loc_conf.enabled {
        Some(true) => {
            // Module is enabled, proceed with IP check
        }
        Some(false) | None => {
            return HandlerResult::Declined;
        }
    }

    // Extract client IP
    let client_ip = match get_client_ip(request) {
        Some(ip) => ip,
        None => {
            // Couldn't get IP, fail-open
            return HandlerResult::Error;
        }
    };

    // Check if IP is banned using shared memory
    if shm::is_banned(&client_ip) {
        // If we have a ban template, send it
        if let Some(ref template) = loc_conf.ban_template {
            match send_ban_response(request, template, &client_ip) {
                Ok(_) => {
                    return HandlerResult::Done;
                }
                Err(_) => {
                    // Failed to send template response, fall through to default 403
                }
            }
        }
        return HandlerResult::Forbidden;
    }

    HandlerResult::Declined
}

/// Send a ban response with rendered template
fn send_ban_response(
    request: &mut Request,
    template: &BanTemplate,
    client_ip: &IpAddr,
) -> Result<(), ()> {
    // Build template variables
    let mut vars = TemplateVariables::new();
    vars.client_ip = Some(client_ip.to_string());

    // Get URI and method using Request API
    if let Ok(uri_str) = request.path().to_str() {
        vars.request_uri = Some(uri_str.to_string());
    }
    vars.request_method = Some(request.method().as_str().to_string());

    // Render the template
    let body = template.render(&vars);

    // Set status code
    request.set_status(HTTPStatus::FORBIDDEN);

    // Set content length
    request.set_content_length_n(body.len());

    // Discard request body if present (we're sending our own response)
    request.discard_request_body();

    // Set headers - content type auto-detected from template file extension
    request.add_header_out("Content-Type", template.content_type());
    request.add_header_out("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    request.add_header_out("Pragma", "no-cache");

    // Get pool and raw request pointer
    let pool = request.pool();
    let r: *mut ngx_http_request_t = request.as_mut() as *mut _;

    // Create buffer from rendered body using Pool's helper method
    let mut buffer = match pool.create_buffer_from_str(&body) {
        Some(buf) => buf,
        None => return Err(()),
    };

    // Mark buffer as last in request and chain
    buffer.set_last_buf(true);
    buffer.set_last_in_chain(true);

    // Create chain link (still needs manual FFI - no SDK wrapper)
    let cl = unsafe {
        let cl = ngx::ffi::ngx_alloc_chain_link(pool.as_ptr());
        if cl.is_null() {
            return Err(());
        }
        (*cl).buf = buffer.as_ngx_buf_mut();
        (*cl).next = std::ptr::null_mut();
        cl
    };

    // Send headers first
    let header_status = request.send_header();
    if header_status != Status::NGX_OK {
        // Header sending failed or was filtered out
        // For HEAD requests, this is normal - just finalize
        if request.header_only() {
            unsafe {
                ngx::ffi::ngx_http_finalize_request(r, header_status.into());
            }
            return Ok(());
        }
        return Err(());
    }

    // Send body using output filter - pass pointer to pool-allocated chain
    let rc = unsafe { ngx::ffi::ngx_http_output_filter(r, cl) };

    // Finalize the request
    unsafe {
        ngx::ffi::ngx_http_finalize_request(r, rc);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_result_conversion() {
        // Just verify the conversions don't panic
        let _: Status = HandlerResult::Declined.into();
        let _: Status = HandlerResult::Forbidden.into();
        let _: Status = HandlerResult::Error.into();
    }
}
