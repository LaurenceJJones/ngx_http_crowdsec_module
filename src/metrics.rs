//! Prometheus text exposition for CrowdSec module counters.
//!
//! Configure a dedicated location with `crowdsec_metrics on;` (and typically `crowdsec off;`).
//! Protect this endpoint with `allow` / `internal` / auth in production.
//! Exposed series include HTTP/captcha counters, LAPI poll counters, `crowdsec_lapi_stream_last_success_unixtime`, and cache entry gauge.

use crate::config::LocConfig;
use crate::shm;
use ngx::core::{Buffer, Status};
use ngx::ffi::ngx_http_request_t;
use ngx::http::{HTTPStatus, Method, Request};

/// Result of attempting to serve `/metrics`-style Prometheus text.
pub enum MetricsServeOutcome {
    Served,
    Failed,
}

/// If `crowdsec_metrics` is enabled for this location, send `text/plain` Prometheus metrics and
/// return [`MetricsServeOutcome::Served`]. Otherwise return `None` so normal CrowdSec handling runs.
pub fn try_serve_metrics(
    request: &mut Request,
    loc_conf: &LocConfig,
) -> Option<MetricsServeOutcome> {
    if loc_conf.metrics_enabled != Some(true) {
        return None;
    }

    match request.method() {
        Method::GET | Method::HEAD => {}
        _ => {
            let _ = send_method_not_allowed(request);
            return Some(MetricsServeOutcome::Served);
        }
    }

    let (lookups, bans, captcha, bypass, poll_ok, poll_err, lapi_last_ok_unix, entries) =
        shm::metrics_prometheus_snapshot();

    let body = format!(
        "# HELP crowdsec_http_remediation_lookups_total Requests evaluated against the CrowdSec decision cache (crowdsec on).\n\
         # TYPE crowdsec_http_remediation_lookups_total counter\n\
         crowdsec_http_remediation_lookups_total {}\n\
         # HELP crowdsec_http_ban_remediations_total Ban remediations applied (403, template body, or redirect).\n\
         # TYPE crowdsec_http_ban_remediations_total counter\n\
         crowdsec_http_ban_remediations_total {}\n\
         # HELP crowdsec_http_captcha_challenges_total Captcha challenge pages sent.\n\
         # TYPE crowdsec_http_captcha_challenges_total counter\n\
         crowdsec_http_captcha_challenges_total {}\n\
         # HELP crowdsec_http_bypass_total Requests skipped by crowdsec_bypass (resolved client IP in listed CIDRs).\n\
         # TYPE crowdsec_http_bypass_total counter\n\
         crowdsec_http_bypass_total {}\n\
         # HELP crowdsec_lapi_stream_polls_success_total Successful LAPI stream polls.\n\
         # TYPE crowdsec_lapi_stream_polls_success_total counter\n\
         crowdsec_lapi_stream_polls_success_total {}\n\
         # HELP crowdsec_lapi_stream_polls_error_total Failed LAPI stream poll attempts.\n\
         # TYPE crowdsec_lapi_stream_polls_error_total counter\n\
         crowdsec_lapi_stream_polls_error_total {}\n\
         # HELP crowdsec_lapi_stream_last_success_unixtime Unix time in seconds of the last successful LAPI stream poll (0 if none yet).\n\
         # TYPE crowdsec_lapi_stream_last_success_unixtime gauge\n\
         crowdsec_lapi_stream_last_success_unixtime {}\n\
         # HELP crowdsec_decision_cache_entries Current IP/CIDR rows in the decision shared-memory cache.\n\
         # TYPE crowdsec_decision_cache_entries gauge\n\
         crowdsec_decision_cache_entries {}\n",
        lookups, bans, captcha, bypass, poll_ok, poll_err, lapi_last_ok_unix, entries
    );

    if send_text_response(
        request,
        HTTPStatus::OK,
        "text/plain; version=0.0.4; charset=utf-8",
        &body,
    )
    .is_ok()
    {
        Some(MetricsServeOutcome::Served)
    } else {
        Some(MetricsServeOutcome::Failed)
    }
}

fn send_method_not_allowed(request: &mut Request) -> Result<(), ()> {
    send_text_response(
        request,
        HTTPStatus::NOT_ALLOWED,
        "text/plain",
        "method not allowed\n",
    )
}

fn send_text_response(
    request: &mut Request,
    status: HTTPStatus,
    content_type: &str,
    body: &str,
) -> Result<(), ()> {
    let r: *mut ngx_http_request_t = request.as_mut() as *mut _;

    unsafe {
        (*r).set_keepalive(0);
    }

    request.set_status(status);
    request.set_content_length_n(body.len());
    request.discard_request_body();
    request.add_header_out("Content-Type", content_type);
    request.add_header_out("Cache-Control", "no-store");

    let pool = request.pool();

    let mut buffer = match pool.create_buffer_from_str(body) {
        Some(buf) => buf,
        None => return Err(()),
    };
    buffer.set_last_buf(true);
    buffer.set_last_in_chain(true);

    let cl = unsafe {
        let cl = ngx::ffi::ngx_alloc_chain_link(pool.as_ptr());
        if cl.is_null() {
            return Err(());
        }
        (*cl).buf = buffer.as_ngx_buf_mut();
        (*cl).next = std::ptr::null_mut();
        cl
    };

    let rc = request.send_header();
    if rc != Status::NGX_OK {
        unsafe {
            ngx::ffi::ngx_http_finalize_request(r, rc.into());
        }
        return Ok(());
    }

    unsafe {
        let out_rc = ngx::ffi::ngx_http_output_filter(r, cl);
        ngx::ffi::ngx_http_finalize_request(r, out_rc);
    }

    Ok(())
}
