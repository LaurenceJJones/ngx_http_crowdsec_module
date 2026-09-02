//! Cookie parsing and building utilities for captcha sessions

use ngx::ffi::ngx_http_request_t;

/// SameSite cookie attribute values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    /// Cookie is only sent in first-party context
    Strict,
    /// Cookie is sent with top-level navigations and GET from third-party sites
    Lax,
    /// Cookie is sent in all contexts (requires Secure)
    None,
}

impl SameSite {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }
}

/// Parse a specific cookie from the request headers
///
/// # Safety
/// Requires a valid NGINX request pointer
pub unsafe fn get_cookie(request: *const ngx_http_request_t, name: &str) -> Option<String> {
    unsafe {
        if request.is_null() {
            return None;
        }

        // Access the headers_in structure
        let headers_in = &(*request).headers_in;

        // Get the cookie header - it's stored as a table entry
        // The cookies field in headers_in is actually ngx_table_elt_t* (linked list)
        let cookie_header = headers_in.cookie;
        if cookie_header.is_null() {
            return None;
        }

        let header = &*cookie_header;
        if header.hash != 0 && !header.value.data.is_null() && header.value.len > 0 {
            let cookie_data = std::slice::from_raw_parts(header.value.data, header.value.len);
            if let Ok(cookie_str) = std::str::from_utf8(cookie_data) {
                return parse_cookie_value(cookie_str, name);
            }
        }

        None
    }
}

/// Parse a cookie value from a cookie string
/// Cookie format: "name1=value1; name2=value2"
fn parse_cookie_value(cookie_str: &str, name: &str) -> Option<String> {
    for cookie in cookie_str.split(';') {
        let cookie = cookie.trim();
        if let Some((key, value)) = cookie.split_once('=') {
            if key.trim() == name {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Build a Set-Cookie header value
pub fn build_set_cookie(
    name: &str,
    value: &str,
    max_age: u64,
    path: &str,
    secure: bool,
    http_only: bool,
    same_site: SameSite,
) -> String {
    let mut cookie = format!("{}={}; Max-Age={}; Path={}", name, value, max_age, path);

    if secure {
        cookie.push_str("; Secure");
    }

    if http_only {
        cookie.push_str("; HttpOnly");
    }

    cookie.push_str("; SameSite=");
    cookie.push_str(same_site.as_str());

    cookie
}

/// Build a Set-Cookie header to clear/expire a cookie
pub fn build_clear_cookie(name: &str, path: &str) -> String {
    format!(
        "{}=; Max-Age=0; Path={}; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        name, path
    )
}

/// Check if the request appears to be over HTTPS (auto-detection)
///
/// This checks both:
/// 1. Direct TLS connection (connection->ssl is set)
/// 2. X-Forwarded-Proto header (for requests behind TLS-terminating proxies)
///
/// # Safety
/// Requires a valid NGINX request pointer
pub unsafe fn is_https(request: *const ngx_http_request_t) -> bool {
    unsafe {
        if request.is_null() {
            return false;
        }

        // First check direct TLS connection
        let connection = (*request).connection;
        if !connection.is_null() && !(*connection).ssl.is_null() {
            return true;
        }

        // Check X-Forwarded-Proto header (common when behind reverse proxy)
        if let Some(proto) = get_header(request, "X-Forwarded-Proto") {
            if proto.eq_ignore_ascii_case("https") {
                return true;
            }
        }

        // Check X-Forwarded-Ssl header (alternative)
        if let Some(ssl) = get_header(request, "X-Forwarded-Ssl") {
            if ssl.eq_ignore_ascii_case("on") {
                return true;
            }
        }

        false
    }
}

/// Determine if cookie should have Secure flag based on config and request
///
/// # Safety
/// Requires a valid NGINX request pointer
pub unsafe fn should_cookie_be_secure(
    request: *const ngx_http_request_t,
    cookie_secure: crate::captcha::config::CookieSecure,
) -> bool {
    unsafe {
        use crate::captcha::config::CookieSecure;

        match cookie_secure {
            CookieSecure::Auto => is_https(request),
            CookieSecure::On => true,
            CookieSecure::Off => false,
        }
    }
}

/// Get a request header value by name
///
/// # Safety
/// Requires a valid NGINX request pointer
unsafe fn get_header(request: *const ngx_http_request_t, name: &str) -> Option<String> {
    unsafe {
        if request.is_null() {
            return None;
        }

        let headers = &(*request).headers_in.headers;
        let mut part = &headers.part;

        loop {
            let elements = part.elts as *const ngx::ffi::ngx_table_elt_t;
            let nelts = part.nelts;

            for i in 0..nelts {
                let header = &*elements.add(i);

                if header.key.len == 0 || header.key.data.is_null() {
                    continue;
                }

                let key_data = std::slice::from_raw_parts(header.key.data, header.key.len);
                if let Ok(key_str) = std::str::from_utf8(key_data) {
                    if key_str.eq_ignore_ascii_case(name) {
                        if header.value.len > 0 && !header.value.data.is_null() {
                            let value_data =
                                std::slice::from_raw_parts(header.value.data, header.value.len);
                            if let Ok(value_str) = std::str::from_utf8(value_data) {
                                return Some(value_str.to_string());
                            }
                        }
                    }
                }
            }

            if part.next.is_null() {
                break;
            }
            part = &*part.next;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cookie_value() {
        let cookie_str = "session=abc123; user=john; token=xyz789";

        assert_eq!(
            parse_cookie_value(cookie_str, "session"),
            Some("abc123".to_string())
        );
        assert_eq!(
            parse_cookie_value(cookie_str, "user"),
            Some("john".to_string())
        );
        assert_eq!(
            parse_cookie_value(cookie_str, "token"),
            Some("xyz789".to_string())
        );
        assert_eq!(parse_cookie_value(cookie_str, "missing"), None);
    }

    #[test]
    fn test_parse_cookie_value_with_spaces() {
        let cookie_str = "  name = value ; other = data  ";
        assert_eq!(
            parse_cookie_value(cookie_str, "name"),
            Some("value".to_string())
        );
        assert_eq!(
            parse_cookie_value(cookie_str, "other"),
            Some("data".to_string())
        );
    }

    #[test]
    fn test_build_set_cookie_basic() {
        let cookie = build_set_cookie("session", "abc123", 3600, "/", false, false, SameSite::Lax);
        assert!(cookie.contains("session=abc123"));
        assert!(cookie.contains("Max-Age=3600"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(!cookie.contains("Secure"));
        assert!(!cookie.contains("HttpOnly"));
    }

    #[test]
    fn test_build_set_cookie_full() {
        let cookie = build_set_cookie("token", "xyz", 7200, "/api", true, true, SameSite::Strict);
        assert!(cookie.contains("token=xyz"));
        assert!(cookie.contains("Max-Age=7200"));
        assert!(cookie.contains("Path=/api"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
    }

    #[test]
    fn test_build_clear_cookie() {
        let cookie = build_clear_cookie("session", "/");
        assert!(cookie.contains("session="));
        assert!(cookie.contains("Max-Age=0"));
        assert!(cookie.contains("Expires="));
    }

    #[test]
    fn test_same_site_values() {
        assert_eq!(SameSite::Strict.as_str(), "Strict");
        assert_eq!(SameSite::Lax.as_str(), "Lax");
        assert_eq!(SameSite::None.as_str(), "None");
    }
}
