use serde::Deserialize;
use std::net::IpAddr;

/// A CrowdSec decision from the LAPI
#[derive(Debug, Clone, Deserialize)]
pub struct Decision {
    pub id: Option<i64>,
    pub origin: Option<String>,
    #[serde(rename = "type")]
    pub decision_type: String,
    pub scope: Option<String>,
    pub value: Option<String>,
    pub duration: Option<String>,
    pub scenario: Option<String>,
    pub until: Option<String>,
    pub simulated: Option<bool>,
    pub uuid: Option<String>,
}

impl Decision {
    /// Check if this decision is a ban
    pub fn is_ban(&self) -> bool {
        self.decision_type.eq_ignore_ascii_case("ban")
    }

    /// Get the IP address if the scope is "ip" or "Ip"
    pub fn get_ip(&self) -> Option<IpAddr> {
        if let Some(scope) = &self.scope {
            if scope.eq_ignore_ascii_case("ip") {
                if let Some(value) = &self.value {
                    return value.parse().ok();
                }
            }
        }
        None
    }

    /// Get the decision ID for deletion matching
    pub fn get_id(&self) -> Option<i64> {
        self.id
    }
}

/// Response from the /v1/decisions/stream endpoint
#[derive(Debug, Deserialize)]
pub struct StreamResponse {
    #[serde(default)]
    pub new: Option<Vec<Decision>>,
    #[serde(default)]
    pub deleted: Option<Vec<Decision>>,
}

impl StreamResponse {
    /// Get new decisions, returning empty vec if None
    pub fn new_decisions(&self) -> Vec<Decision> {
        self.new.clone().unwrap_or_default()
    }

    /// Get deleted decisions, returning empty vec if None
    pub fn deleted_decisions(&self) -> Vec<Decision> {
        self.deleted.clone().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_is_ban() {
        let decision = Decision {
            id: Some(1),
            origin: Some("crowdsec".to_string()),
            decision_type: "ban".to_string(),
            scope: Some("ip".to_string()),
            value: Some("192.168.1.1".to_string()),
            duration: Some("1h".to_string()),
            scenario: Some("test".to_string()),
            until: None,
            simulated: Some(false),
            uuid: None,
        };
        assert!(decision.is_ban());

        let captcha = Decision {
            decision_type: "captcha".to_string(),
            ..decision.clone()
        };
        assert!(!captcha.is_ban());
    }

    #[test]
    fn test_decision_get_ip() {
        let decision = Decision {
            id: Some(1),
            origin: None,
            decision_type: "ban".to_string(),
            scope: Some("ip".to_string()),
            value: Some("192.168.1.100".to_string()),
            duration: None,
            scenario: None,
            until: None,
            simulated: None,
            uuid: None,
        };
        assert_eq!(
            decision.get_ip(),
            Some("192.168.1.100".parse().unwrap())
        );
    }

    #[test]
    fn test_stream_response_parsing() {
        let json = r#"{
            "new": [{"id": 1, "type": "ban", "scope": "ip", "value": "1.2.3.4"}],
            "deleted": [{"id": 2, "type": "ban", "scope": "ip", "value": "5.6.7.8"}]
        }"#;
        let response: StreamResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.new_decisions().len(), 1);
        assert_eq!(response.deleted_decisions().len(), 1);
    }

    #[test]
    fn test_stream_response_empty() {
        let json = r#"{"new": null, "deleted": null}"#;
        let response: StreamResponse = serde_json::from_str(json).unwrap();
        assert!(response.new_decisions().is_empty());
        assert!(response.deleted_decisions().is_empty());
    }
}
