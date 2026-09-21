//! Sanitize the URI used as captcha form action and post-solve Location.

/// Only same-origin relative paths. Reject protocol-relative (`//host`) and
/// absolute URLs so a signed-in client cannot be sent off-site.
pub fn sanitize_return_uri(raw: &str) -> String {
    let uri = raw.trim();
    if uri.starts_with('/')
        && !uri.starts_with("//")
        && !uri.contains(['\\', '\r', '\n'])
        && !uri.contains("://")
    {
        uri.to_string()
    } else {
        "/".to_string()
    }
}

pub fn is_safe_header_value(value: &str) -> bool {
    !value.is_empty() && !value.contains(['\r', '\n'])
}

pub fn is_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_path_and_query() {
        assert_eq!(sanitize_return_uri("/login?next=1"), "/login?next=1");
        assert_eq!(sanitize_return_uri("  /ok  "), "/ok");
    }

    #[test]
    fn rejects_open_redirects() {
        assert_eq!(sanitize_return_uri("//evil.example/"), "/");
        assert_eq!(sanitize_return_uri("https://evil.example/"), "/");
        assert_eq!(sanitize_return_uri("/\\evil"), "/");
        assert_eq!(sanitize_return_uri("/ok\r\nLocation: //x"), "/");
        assert_eq!(sanitize_return_uri(""), "/");
        assert_eq!(sanitize_return_uri("relative"), "/");
    }

    #[test]
    fn cookie_name_and_header_value_guards() {
        assert!(is_cookie_name("crowdsec_captcha"));
        assert!(is_cookie_name("a-b_1"));
        assert!(!is_cookie_name(""));
        assert!(!is_cookie_name("bad name"));
        assert!(!is_cookie_name("bad;name"));
        assert!(!is_cookie_name(&"x".repeat(65)));
        assert!(is_safe_header_value("ok"));
        assert!(!is_safe_header_value(""));
        assert!(!is_safe_header_value("a\r\nb"));
    }
}
