//! Shared CrowdSec LAPI HTTP client settings.

/// User-Agent sent on all CrowdSec LAPI requests (`<module>/<version>`).
pub const BOUNCER_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION")
);

/// ureq agent configured with the bouncer User-Agent.
pub fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .user_agent(BOUNCER_USER_AGENT)
        .build()
}

/// Attach headers required for authenticated LAPI calls.
pub fn with_api_key<'a>(req: ureq::Request, api_key: &'a str) -> ureq::Request {
    req.set("X-Api-Key", api_key)
        .set("User-Agent", BOUNCER_USER_AGENT)
}
