//! JWT token creation and validation for captcha sessions
//!
//! Uses HMAC-SHA256 for signing tokens. Tokens include:
//! - Subject (client IP if bind_ip is enabled)
//! - Issued at timestamp
//! - Expiration timestamp
//! - Nonce for uniqueness

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// JWT claims for captcha session
#[derive(Debug, Clone, PartialEq)]
pub struct CaptchaClaims {
    /// Subject - the client IP address (if bind_ip enabled) or "anonymous"
    pub sub: String,
    /// Issued at timestamp (Unix epoch seconds)
    pub iat: i64,
    /// Expiration timestamp (Unix epoch seconds)
    pub exp: i64,
    /// Token type identifier
    pub typ: String,
    /// Original request URI (for redirect after captcha)
    pub uri: Option<String>,
    /// Random nonce for uniqueness
    pub nonce: String,
}

impl CaptchaClaims {
    /// Create new claims for a captcha session
    pub fn new(client_ip: Option<&str>, expiry_secs: u64, request_uri: Option<&str>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Self {
            sub: client_ip.unwrap_or("anonymous").to_string(),
            iat: now,
            exp: now + expiry_secs as i64,
            typ: "captcha_pass".to_string(),
            uri: request_uri.map(|s| s.to_string()),
            nonce: generate_nonce(),
        }
    }

    /// Check if the claims are valid for the given client IP
    pub fn is_valid(&self, client_ip: Option<&str>) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // Check expiration
        if now > self.exp {
            return false;
        }

        // Check token type
        if self.typ != "captcha_pass" {
            return false;
        }

        // Check IP binding if required
        if let Some(ip) = client_ip {
            if self.sub != "anonymous" && self.sub != ip {
                return false;
            }
        }

        true
    }

    /// Serialize claims to JSON
    fn to_json(&self) -> String {
        // Manual JSON serialization to avoid serde dependency overhead
        let uri_part = match &self.uri {
            Some(u) => format!(r#","uri":"{}""#, escape_json_string(u)),
            None => String::new(),
        };
        format!(
            r#"{{"sub":"{}","iat":{},"exp":{},"typ":"{}","nonce":"{}"{}}}"#,
            escape_json_string(&self.sub),
            self.iat,
            self.exp,
            self.typ,
            self.nonce,
            uri_part
        )
    }

    /// Parse claims from JSON
    fn from_json(json: &str) -> Option<Self> {
        // Simple JSON parsing without full serde
        let sub = extract_json_string(json, "sub")?;
        let iat = extract_json_number(json, "iat")?;
        let exp = extract_json_number(json, "exp")?;
        let typ = extract_json_string(json, "typ")?;
        let nonce = extract_json_string(json, "nonce")?;
        let uri = extract_json_string(json, "uri");

        Some(Self {
            sub,
            iat,
            exp,
            typ,
            uri,
            nonce,
        })
    }
}

/// Generate a random 16-byte nonce as hex string
fn generate_nonce() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    hex_encode(&bytes)
}

/// Encode bytes as lowercase hex string
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Escape a string for JSON (handles quotes and backslashes)
fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => result.push_str(&format!("\\u{:04x}", c as u32)),
            _ => result.push(c),
        }
    }
    result
}

/// Extract a string value from JSON by key (simple parser)
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!(r#""{}":""#, key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];

    // Find closing quote, handling escapes
    let mut end = 0;
    let mut escaped = false;
    for (i, c) in rest.chars().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == '"' {
            end = i;
            break;
        }
    }

    let value = &rest[..end];
    Some(unescape_json_string(value))
}

/// Extract a number value from JSON by key
fn extract_json_number(json: &str, key: &str) -> Option<i64> {
    let pattern = format!(r#""{}":"#, key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];

    // Find end of number
    let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-')?;
    rest[..end].parse().ok()
}

/// Unescape a JSON string value
fn unescape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('u') => {
                    // Parse \uXXXX
                    let hex: String = chars.by_ref().take(4).collect();
                    if let Ok(code) = u32::from_str_radix(&hex, 16) {
                        if let Some(c) = char::from_u32(code) {
                            result.push(c);
                        }
                    }
                }
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// JWT error types
#[derive(Debug, Clone, PartialEq)]
pub enum JwtError {
    /// Token format is invalid (not 3 parts)
    InvalidFormat,
    /// Signature verification failed
    InvalidSignature,
    /// Payload decoding or parsing failed
    InvalidPayload,
    /// HMAC key is invalid
    InvalidKey,
    /// Token has expired
    Expired,
    /// IP address mismatch
    IpMismatch,
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid token format"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::InvalidPayload => write!(f, "invalid payload"),
            Self::InvalidKey => write!(f, "invalid signing key"),
            Self::Expired => write!(f, "token expired"),
            Self::IpMismatch => write!(f, "IP address mismatch"),
        }
    }
}

/// JWT manager for creating and verifying captcha session tokens
pub struct JwtManager {
    signing_key: [u8; 32],
}

impl JwtManager {
    /// Create a new JWT manager with the given signing key
    pub fn new(signing_key: [u8; 32]) -> Self {
        Self { signing_key }
    }

    /// Create a signed JWT token from claims
    pub fn create_token(&self, claims: &CaptchaClaims) -> Result<String, JwtError> {
        // Header: {"alg":"HS256","typ":"JWT"}
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header);

        // Payload
        let payload = claims.to_json();
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);

        // Signature
        let message = format!("{}.{}", header_b64, payload_b64);
        let mut mac =
            HmacSha256::new_from_slice(&self.signing_key).map_err(|_| JwtError::InvalidKey)?;
        mac.update(message.as_bytes());
        let signature = mac.finalize().into_bytes();
        let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
    }

    /// Verify and decode a JWT token
    pub fn verify_token(&self, token: &str) -> Result<CaptchaClaims, JwtError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::InvalidFormat);
        }

        // Verify signature first
        let message = format!("{}.{}", parts[0], parts[1]);
        let signature = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| JwtError::InvalidSignature)?;

        let mut mac =
            HmacSha256::new_from_slice(&self.signing_key).map_err(|_| JwtError::InvalidKey)?;
        mac.update(message.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| JwtError::InvalidSignature)?;

        // Decode payload
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| JwtError::InvalidPayload)?;
        let payload_str =
            std::str::from_utf8(&payload_bytes).map_err(|_| JwtError::InvalidPayload)?;

        // Parse claims
        let claims =
            CaptchaClaims::from_json(payload_str).ok_or(JwtError::InvalidPayload)?;

        Ok(claims)
    }

    /// Verify token and check if it's valid for the given client IP
    pub fn verify_and_validate(
        &self,
        token: &str,
        client_ip: Option<&str>,
    ) -> Result<CaptchaClaims, JwtError> {
        let claims = self.verify_token(token)?;

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        if now > claims.exp {
            return Err(JwtError::Expired);
        }

        // Check IP binding if client_ip is provided and claims have a specific IP
        if let Some(ip) = client_ip {
            if claims.sub != "anonymous" && claims.sub != ip {
                return Err(JwtError::IpMismatch);
            }
        }

        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claims_creation() {
        let claims = CaptchaClaims::new(Some("192.168.1.1"), 3600, Some("/test"));
        assert_eq!(claims.sub, "192.168.1.1");
        assert_eq!(claims.typ, "captcha_pass");
        assert_eq!(claims.uri, Some("/test".to_string()));
        assert!(claims.exp > claims.iat);
        assert!(!claims.nonce.is_empty());
    }

    #[test]
    fn test_claims_anonymous() {
        let claims = CaptchaClaims::new(None, 3600, None);
        assert_eq!(claims.sub, "anonymous");
        assert_eq!(claims.uri, None);
    }

    #[test]
    fn test_jwt_roundtrip() {
        let key = [1u8; 32];
        let manager = JwtManager::new(key);

        let claims = CaptchaClaims::new(Some("192.168.1.1"), 3600, Some("/path"));
        let token = manager.create_token(&claims).unwrap();

        // Token should have 3 parts
        assert_eq!(token.split('.').count(), 3);

        // Verify and decode
        let decoded = manager.verify_token(&token).unwrap();
        assert_eq!(decoded.sub, claims.sub);
        assert_eq!(decoded.iat, claims.iat);
        assert_eq!(decoded.exp, claims.exp);
        assert_eq!(decoded.typ, claims.typ);
        assert_eq!(decoded.nonce, claims.nonce);
        assert_eq!(decoded.uri, claims.uri);
    }

    #[test]
    fn test_jwt_invalid_signature() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let manager1 = JwtManager::new(key1);
        let manager2 = JwtManager::new(key2);

        let claims = CaptchaClaims::new(Some("192.168.1.1"), 3600, None);
        let token = manager1.create_token(&claims).unwrap();

        // Should fail with different key
        let result = manager2.verify_token(&token);
        assert_eq!(result, Err(JwtError::InvalidSignature));
    }

    #[test]
    fn test_jwt_tampered_payload() {
        let key = [1u8; 32];
        let manager = JwtManager::new(key);

        let claims = CaptchaClaims::new(Some("192.168.1.1"), 3600, None);
        let token = manager.create_token(&claims).unwrap();

        // Tamper with payload (change middle part)
        let parts: Vec<&str> = token.split('.').collect();
        let tampered = format!("{}.{}.{}", parts[0], "dGFtcGVyZWQ", parts[2]);

        let result = manager.verify_token(&tampered);
        assert_eq!(result, Err(JwtError::InvalidSignature));
    }

    #[test]
    fn test_jwt_ip_validation() {
        let key = [1u8; 32];
        let manager = JwtManager::new(key);

        let claims = CaptchaClaims::new(Some("192.168.1.1"), 3600, None);
        let token = manager.create_token(&claims).unwrap();

        // Same IP should pass
        let result = manager.verify_and_validate(&token, Some("192.168.1.1"));
        assert!(result.is_ok());

        // Different IP should fail
        let result = manager.verify_and_validate(&token, Some("192.168.1.2"));
        assert_eq!(result, Err(JwtError::IpMismatch));

        // No IP check should pass
        let result = manager.verify_and_validate(&token, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_jwt_anonymous_ip() {
        let key = [1u8; 32];
        let manager = JwtManager::new(key);

        // Create token without IP binding
        let claims = CaptchaClaims::new(None, 3600, None);
        let token = manager.create_token(&claims).unwrap();

        // Any IP should pass for anonymous tokens
        let result = manager.verify_and_validate(&token, Some("192.168.1.1"));
        assert!(result.is_ok());

        let result = manager.verify_and_validate(&token, Some("10.0.0.1"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_json_string_escape() {
        assert_eq!(escape_json_string("hello"), "hello");
        assert_eq!(escape_json_string("say \"hi\""), "say \\\"hi\\\"");
        assert_eq!(escape_json_string("back\\slash"), "back\\\\slash");
        assert_eq!(escape_json_string("line\nbreak"), "line\\nbreak");
    }

    #[test]
    fn test_claims_json_roundtrip() {
        let claims = CaptchaClaims::new(Some("192.168.1.1"), 3600, Some("/test?a=1&b=2"));
        let json = claims.to_json();
        let parsed = CaptchaClaims::from_json(&json).unwrap();

        assert_eq!(parsed.sub, claims.sub);
        assert_eq!(parsed.iat, claims.iat);
        assert_eq!(parsed.exp, claims.exp);
        assert_eq!(parsed.typ, claims.typ);
        assert_eq!(parsed.nonce, claims.nonce);
        assert_eq!(parsed.uri, claims.uri);
    }
}
