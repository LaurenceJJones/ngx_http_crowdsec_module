//! CrowdSec LAPI stream client
//!
//! This module handles polling the CrowdSec LAPI decisions stream and
//! updating the shared memory decision store.

use crate::lapi;
use crate::log::cycle_log;
use crate::shm::{self, CidrDecisionInfo, DecisionInfo, DecisionType, Origin};
use crate::types::StreamResponse;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Error type for stream client operations
#[derive(Debug)]
pub enum StreamError {
    Http(String),
    Json(String),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::Http(msg) => write!(f, "HTTP error: {}", msg),
            StreamError::Json(msg) => write!(f, "JSON parse error: {}", msg),
        }
    }
}

impl std::error::Error for StreamError {}

/// Configuration for the stream client
#[derive(Debug, Clone)]
pub struct StreamClientConfig {
    /// LAPI URL (e.g., http://127.0.0.1:8080)
    pub url: String,
    /// Bouncer API key
    pub api_key: String,
    /// Polling interval in seconds
    pub poll_interval_secs: u64,
    /// HTTP request timeout in seconds
    pub timeout_secs: u64,
    /// Maximum number of retries for initial connection
    pub max_retries: u32,
    /// Retry interval in seconds between retry attempts
    pub retry_interval_secs: u64,
    /// LAPI usage-metrics push interval (`0` = disabled). Default 900.
    pub usage_metrics_interval_secs: u64,
}

impl Default for StreamClientConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8080".to_string(),
            api_key: String::new(),
            poll_interval_secs: 10,
            timeout_secs: 30,
            max_retries: 3,
            retry_interval_secs: 5,
            usage_metrics_interval_secs: 900,
        }
    }
}

/// Client for polling the CrowdSec LAPI decisions stream
pub struct StreamClient {
    config: StreamClientConfig,
    agent: ureq::Agent,
    running: Arc<AtomicBool>,
}

impl StreamClient {
    /// Create a new stream client
    pub fn new(config: StreamClientConfig) -> Self {
        Self {
            config,
            agent: lapi::agent(),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Build the stream endpoint URL
    fn build_url(&self, startup: bool) -> String {
        format!(
            "{}/v1/decisions/stream?startup={}",
            self.config.url.trim_end_matches('/'),
            startup
        )
    }

    /// Poll the stream endpoint once
    pub fn poll(&self, startup: bool) -> Result<(usize, usize), StreamError> {
        let url = self.build_url(startup);

        let response = lapi::with_api_key(self.agent.get(&url), &self.config.api_key)
            .timeout(Duration::from_secs(self.config.timeout_secs))
            .call()
            .map_err(|e| StreamError::Http(e.to_string()))?;

        let stream_response: StreamResponse = response
            .into_json()
            .map_err(|e| StreamError::Json(e.to_string()))?;

        let new_decisions = stream_response.new.unwrap_or_default();
        let deleted_decisions = stream_response.deleted.unwrap_or_default();

        let new_count = new_decisions.len();
        let deleted_count = deleted_decisions.len();

        // Apply to shared memory
        self.apply_to_shm(&new_decisions, &deleted_decisions);

        Ok((new_count, deleted_count))
    }

    /// Apply decisions to shared memory
    ///
    /// Handles all decision types by trying to parse the value as:
    /// 1. A single IP address (e.g., "192.168.1.1" or "2001:db8::1")
    /// 2. A CIDR range (e.g., "192.168.1.0/24" or "2001:db8::/32")
    fn apply_to_shm(
        &self,
        new_decisions: &[crate::types::Decision],
        deleted_decisions: &[crate::types::Decision],
    ) {
        // Remove deleted decisions
        for decision in deleted_decisions {
            if let Some(ref value) = decision.value {
                let decision_type = DecisionType::from_str(&decision.decision_type);

                // Try to parse as single IP first
                if let Ok(ip) = value.parse::<IpAddr>() {
                    shm::remove_decision_type(&ip, decision_type);
                }
                // Then try as CIDR range
                else if let Some((network, family, prefix_len)) = shm::parse_cidr(value) {
                    shm::remove_cidr_decision_type(family, prefix_len, &network, decision_type);
                }
                // If neither works, log and skip
                else {
                    crowdsec_warn!(
                        cycle_log(),
                        "crowdsec: cannot parse decision value '{}' (scope: {:?})",
                        value,
                        decision.scope
                    );
                }
            }
        }

        // Add new decisions
        for decision in new_decisions {
            if let Some(ref value) = decision.value {
                let duration_secs = decision.duration.as_ref().and_then(|d| parse_duration(d));
                let decision_type = DecisionType::from_str(&decision.decision_type);
                let origin = decision
                    .origin
                    .as_deref()
                    .map(Origin::from_str)
                    .unwrap_or(Origin::Unknown);
                let scenario = decision.scenario.as_deref();

                // Try to parse as single IP first
                if let Ok(ip) = value.parse::<IpAddr>() {
                    shm::add_decision(&DecisionInfo {
                        ip: &ip,
                        decision_type,
                        origin,
                        scenario,
                        duration_secs,
                    });
                }
                // Then try as CIDR range (e.g., "192.168.1.0/24")
                else if let Some((network, family, prefix_len)) = shm::parse_cidr(value) {
                    shm::add_cidr_decision(&CidrDecisionInfo {
                        network: &network,
                        family,
                        prefix_len,
                        decision_type,
                        origin,
                        scenario,
                        duration_secs,
                    });
                }
                // If neither works, log and skip
                else {
                    crowdsec_warn!(
                        cycle_log(),
                        "crowdsec: cannot parse decision value '{}' (scope: {:?}, type: {})",
                        value,
                        decision.scope,
                        decision.decision_type
                    );
                }
            }
        }
    }

    /// Check if the polling thread is running
    #[cfg(test)]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Signal the polling thread to stop
    #[cfg(test)]
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Spawn a background thread that continuously polls the stream
    pub fn spawn_polling_thread(self) -> (JoinHandle<()>, Arc<AtomicBool>) {
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        let handle = thread::spawn(move || {
            self.run_polling_loop();
        });

        (handle, running)
    }

    /// Poll with retry logic for initial connection
    fn poll_with_retry(&self, startup: bool) -> Result<(usize, usize), StreamError> {
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            match self.poll(startup) {
                Ok(result) => {
                    shm::metrics_inc_lapi_poll_ok();
                    if attempt > 0 {
                        crowdsec_notice!(
                            cycle_log(),
                            "crowdsec: initial sync succeeded after {} retry attempt(s)",
                            attempt
                        );
                    }
                    return Ok(result);
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.config.max_retries {
                        let retry_delay = Duration::from_secs(self.config.retry_interval_secs);
                        crowdsec_warn!(
                            cycle_log(),
                            "crowdsec: initial sync attempt {} failed, retrying in {}s: {}",
                            attempt + 1,
                            retry_delay.as_secs(),
                            last_error.as_ref().unwrap()
                        );
                        thread::sleep(retry_delay);
                    }
                }
            }
        }

        // All retries exhausted
        shm::metrics_inc_lapi_poll_err();
        Err(last_error.expect("retry loop should have at least one error"))
    }

    /// Internal polling loop
    fn run_polling_loop(self) {
        crowdsec_notice!(
            cycle_log(),
            "crowdsec: starting polling thread for LAPI at {}",
            self.config.url
        );

        // Initial startup poll to get full decision state with retry logic
        match self.poll_with_retry(true) {
            Ok((new, deleted)) => {
                crowdsec_notice!(
                    cycle_log(),
                    "crowdsec: initial sync complete - {} new, {} deleted, {} total banned IPs",
                    new,
                    deleted,
                    shm::get_count()
                );
            }
            Err(e) => {
                crowdsec_warn!(
                    cycle_log(),
                    "crowdsec: initial sync failed after {} retries (fail-open): {}",
                    self.config.max_retries + 1,
                    e
                );
            }
        }

        let poll_duration = Duration::from_secs(self.config.poll_interval_secs);
        let metrics_interval = Duration::from_secs(self.config.usage_metrics_interval_secs);
        let mut last_metrics_push = std::time::Instant::now();

        // Main polling loop
        while self.running.load(Ordering::SeqCst) {
            thread::sleep(poll_duration);

            if !self.running.load(Ordering::SeqCst) {
                break;
            }

            match self.poll(false) {
                Ok((new, deleted)) => {
                    shm::metrics_inc_lapi_poll_ok();
                    if new > 0 || deleted > 0 {
                        crowdsec_notice!(
                            cycle_log(),
                            "crowdsec: stream update - {} new, {} deleted, {} total banned IPs",
                            new,
                            deleted,
                            shm::get_count()
                        );
                    }
                }
                Err(e) => {
                    shm::metrics_inc_lapi_poll_err();
                    crowdsec_warn!(
                        cycle_log(),
                        "crowdsec: stream poll failed (fail-open): {}",
                        e
                    );
                }
            }

            if metrics_interval.as_secs() > 0 && last_metrics_push.elapsed() >= metrics_interval {
                if let Err(e) = crate::usage_metrics::push_to_lapi(
                    &self.config.url,
                    &self.config.api_key,
                    self.config.timeout_secs,
                    metrics_interval.as_secs(),
                ) {
                    crowdsec_warn!(cycle_log(), "crowdsec: usage-metrics push failed: {e}");
                }
                last_metrics_push = std::time::Instant::now();
            }
        }

        crowdsec_notice!(cycle_log(), "crowdsec: polling thread stopped");
    }
}

/// Parse a duration string like "1h", "30m", "3600s" to seconds
fn parse_duration(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Handle Go-style durations like "1h30m" or simple ones like "3600s"
    let mut total_secs: i64 = 0;
    let mut number = 0i64;
    let mut has_number = false;

    for byte in s.bytes() {
        if byte.is_ascii_digit() {
            number = number.checked_mul(10)?.checked_add((byte - b'0') as i64)?;
            has_number = true;
        } else {
            if !has_number {
                return None;
            }

            let multiplier = match byte {
                b'h' => 3600,
                b'm' => 60,
                b's' => 1,
                _ => return None,
            };
            total_secs = total_secs.checked_add(number.checked_mul(multiplier)?)?;
            number = 0;
            has_number = false;
        }
    }

    // Handle case where duration is just a number (assume seconds)
    if has_number {
        total_secs = total_secs.checked_add(number)?;
    }

    if total_secs > 0 {
        Some(total_secs)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_url() {
        let config = StreamClientConfig {
            url: "http://localhost:8080".to_string(),
            api_key: "test-key".to_string(),
            ..Default::default()
        };
        let client = StreamClient::new(config);

        assert_eq!(
            client.build_url(true),
            "http://localhost:8080/v1/decisions/stream?startup=true"
        );
        assert_eq!(
            client.build_url(false),
            "http://localhost:8080/v1/decisions/stream?startup=false"
        );
    }

    #[test]
    fn test_build_url_trailing_slash() {
        let config = StreamClientConfig {
            url: "http://localhost:8080/".to_string(),
            api_key: "test-key".to_string(),
            ..Default::default()
        };
        let client = StreamClient::new(config);

        assert_eq!(
            client.build_url(true),
            "http://localhost:8080/v1/decisions/stream?startup=true"
        );
    }

    #[test]
    fn test_stop_flag() {
        let config = StreamClientConfig::default();
        let client = StreamClient::new(config);

        assert!(!client.is_running());
        client.running.store(true, Ordering::SeqCst);
        assert!(client.is_running());
        client.stop();
        assert!(!client.is_running());
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("3600s"), Some(3600));
        assert_eq!(parse_duration("1h"), Some(3600));
        assert_eq!(parse_duration("30m"), Some(1800));
        assert_eq!(parse_duration("1h30m"), Some(5400));
        assert_eq!(parse_duration("1h30m30s"), Some(5430));
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("abc"), None);
    }
}
