//! Prometheus text exposition for CrowdSec module counters.
//!
//! Configure a dedicated location with `crowdsec_metrics on;` (and typically `crowdsec off;`).
//! Protect this endpoint with `allow` / `internal` / auth in production.
//! Exposed series include HTTP/captcha counters, LAPI poll counters, `crowdsec_lapi_stream_last_success_unixtime`, and cache entry gauge.

use crate::config::LocConfig;
use crate::handler::HandlerResult;
use crate::shm;
use crate::response::{HeaderFailureAction, body_chain, disable_keepalive, send_chain_and_finalize};
use ngx::http::{HTTPStatus, Method, Request};

/// If `crowdsec_metrics` is enabled for this location, send Prometheus text and
/// return a terminal [`HandlerResult`]. Otherwise return `None`.
pub fn try_serve_metrics(request: &mut Request, loc_conf: &LocConfig) -> Option<HandlerResult> {
    if loc_conf.metrics_enabled != Some(true) {
        return None;
    }

    if !matches!(request.method(), Method::GET | Method::HEAD) {
        let _ = send_text_response(
            request,
            HTTPStatus::NOT_ALLOWED,
            "text/plain",
            "method not allowed\n",
        );
        return Some(HandlerResult::Done);
    }

    let (lookups, bans, captcha, bypass, poll_ok, poll_err, lapi_last_ok_unix, entries, evictions) =
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
         # HELP crowdsec_decision_cache_entries Non-expired IP/CIDR rows in the decision shared-memory cache.\n\
         # TYPE crowdsec_decision_cache_entries gauge\n\
         crowdsec_decision_cache_entries {}\n\
         # HELP crowdsec_decision_cache_evictions_total Clock-hand evictions from the decision cache.\n\
         # TYPE crowdsec_decision_cache_evictions_total counter\n\
         crowdsec_decision_cache_evictions_total {}\n",
        lookups, bans, captcha, bypass, poll_ok, poll_err, lapi_last_ok_unix, entries, evictions
    );

    if send_text_response(
        request,
        HTTPStatus::OK,
        "text/plain; version=0.0.4; charset=utf-8",
        &body,
    )
    .is_ok()
    {
        Some(HandlerResult::Done)
    } else {
        Some(HandlerResult::Error)
    }
}

fn send_text_response(
    request: &mut Request,
    status: HTTPStatus,
    content_type: &str,
    body: &str,
) -> Result<(), ()> {
    disable_keepalive(request);

    request.set_status(status);
    request.set_content_length_n(body.len());
    request.discard_request_body();
    request.add_header_out("Content-Type", content_type);
    request.add_header_out("Cache-Control", "no-store");

    let cl = body_chain(request, body)?;
    send_chain_and_finalize(request, cl, HeaderFailureAction::Finalize)
}
