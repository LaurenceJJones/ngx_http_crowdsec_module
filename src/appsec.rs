use crate::config::{AppSecFailureAction, LocConfig};
use crate::handler::{HandlerResult, get_client_ip, handle_captcha_decision, send_raw_response};
use ngx::http::{HTTPStatus, Method, Request};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

#[derive(Clone)]
pub struct AppSecConfig {
    pub url: String,
    pub api_key: String,
    pub timeout_ms: u64,
    pub max_body_size: usize,
}

static CONFIG: Mutex<Option<AppSecConfig>> = Mutex::new(None);
static AGENT: LazyLock<ureq::Agent> = LazyLock::new(ureq::Agent::new);

pub fn configure(config: Option<AppSecConfig>) {
    *CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = config;
}

#[derive(Debug, Deserialize)]
struct Envelope {
    action: String,
    #[serde(default)]
    http_status: u16,
    #[serde(default)]
    user_body_content: String,
    #[serde(default)]
    user_headers: HashMap<String, Vec<String>>,
    #[serde(default)]
    user_cookies: Vec<String>,
}

fn failure(action: AppSecFailureAction) -> HandlerResult {
    match action {
        AppSecFailureAction::Passthrough => HandlerResult::Declined,
        AppSecFailureAction::Deny => HandlerResult::Forbidden,
    }
}

pub fn inspect(request: &mut Request, loc: &LocConfig) -> HandlerResult {
    let uri = request.unparsed_uri().to_str().unwrap_or("/");
    let internal_challenge = uri.starts_with("/crowdsec-internal/challenge/");
    if loc.appsec_enabled != Some(true) {
        return if internal_challenge {
            HandlerResult::Forbidden
        } else {
            HandlerResult::Declined
        };
    }
    if internal_challenge && loc.bot_challenge_enabled != Some(true) {
        return HandlerResult::Forbidden;
    }
    let failure_action = if internal_challenge {
        AppSecFailureAction::Deny
    } else {
        loc.appsec_failure_action.unwrap_or_default()
    };
    let config = CONFIG.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let Some(config) = config else {
        return failure(failure_action);
    };
    let Some(ip) = get_client_ip(request) else {
        return failure(failure_action);
    };
    let content_length = request
        .headers_in_iterator()
        .find_map(|(k, v)| {
            let (Ok(k), Ok(v)) = (k.to_str(), v.to_str()) else {
                return None;
            };
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    if content_length > config.max_body_size {
        return failure(failure_action);
    }
    let user_agent = request
        .user_agent()
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let host = request
        .headers_in_iterator()
        .find_map(|(k, v)| {
            let (Ok(k), Ok(v)) = (k.to_str(), v.to_str()) else {
                return None;
            };
            k.eq_ignore_ascii_case("host").then_some(v)
        })
        .unwrap_or("");

    let mut call = AGENT
        .get(&config.url)
        .set("X-Crowdsec-Appsec-Ip", &ip.to_string())
        .set("X-Crowdsec-Appsec-Uri", uri)
        .set("X-Crowdsec-Appsec-Host", host)
        .set("X-Crowdsec-Appsec-Verb", request.method().as_str())
        .set("X-Crowdsec-Appsec-Api-Key", &config.api_key)
        .set("X-Crowdsec-Appsec-User-Agent", user_agent)
        .set("X-Crowdsec-Appsec-Http-Version", "11")
        .timeout(Duration::from_millis(config.timeout_ms));

    for (name, value) in request.headers_in_iterator() {
        let (Ok(name), Ok(value)) = (name.to_str(), value.to_str()) else {
            continue;
        };
        if !name.to_ascii_lowercase().starts_with("x-crowdsec-appsec-")
            && !matches!(
                name.to_ascii_lowercase().as_str(),
                "connection" | "transfer-encoding" | "upgrade"
            )
        {
            call = call.set(name, value);
        }
    }

    // NGINX has not read ordinary request bodies at access phase yet. Internal
    // challenge submissions are still routed to AppSec and fail safely if the
    // engine requires a body that is not available.
    // ponytail: this bounded local call blocks a worker; replace it with an
    // NGINX subrequest/event client if production profiling shows contention.
    let response = if request.method() == Method::POST {
        call.send_bytes(&[])
    } else {
        call.call()
    };

    match response {
        Ok(response) if response.status() == 200 => HandlerResult::Declined,
        Ok(_) => failure(failure_action),
        Err(ureq::Error::Status(403, response)) => {
            let Ok(envelope) = response.into_json::<Envelope>() else {
                return HandlerResult::Forbidden;
            };
            match envelope.action.as_str() {
                "allow" => HandlerResult::Declined,
                "ban" => HandlerResult::Forbidden,
                "captcha" => handle_captcha_decision(request, loc, &ip),
                "challenge"
                    if loc.bot_challenge_enabled == Some(true)
                        && !envelope.user_body_content.is_empty() =>
                {
                    let status = HTTPStatus::from_u16(if envelope.http_status == 0 {
                        200
                    } else {
                        envelope.http_status
                    })
                    .unwrap_or(HTTPStatus::FORBIDDEN);
                    let headers = envelope
                        .user_headers
                        .into_iter()
                        .flat_map(|(name, values)| {
                            values.into_iter().filter_map(move |value| {
                                safe_header(&name, &value).then(|| (name.clone(), value))
                            })
                        })
                        .chain(
                            envelope
                                .user_cookies
                                .into_iter()
                                .filter(|v| !v.contains(['\r', '\n']))
                                .map(|v| ("Set-Cookie".to_string(), v)),
                        )
                        .collect::<Vec<_>>();
                    if send_raw_response(request, status, &envelope.user_body_content, &headers)
                        .is_ok()
                    {
                        HandlerResult::Done
                    } else {
                        HandlerResult::Forbidden
                    }
                }
                _ => HandlerResult::Forbidden,
            }
        }
        Err(_) => failure(failure_action),
    }
}

fn safe_header(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !value.contains(['\r', '\n'])
        && !matches!(
            name.to_ascii_lowercase().as_str(),
            "connection" | "content-length" | "transfer-encoding" | "upgrade"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_envelope_parses_repeated_headers() {
        let value: Envelope = serde_json::from_str(r#"{"action":"challenge","http_status":307,"user_body_content":"ok","user_headers":{"Location":["/"]},"user_cookies":["a=b","c=d"]}"#).unwrap();
        assert_eq!(value.http_status, 307);
        assert_eq!(value.user_cookies.len(), 2);
    }

    #[test]
    fn response_headers_reject_injection_and_hop_by_hop_headers() {
        assert!(safe_header("Location", "/challenge"));
        assert!(!safe_header("X-Test", "ok\r\nInjected: yes"));
        assert!(!safe_header("Content-Length", "1"));
    }
}
