use std::fs;
use std::path::Path;

/// Escape a string for safe inclusion in HTML content
/// Prevents XSS attacks by escaping characters that have special meaning in HTML
fn escape_html(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#x27;"),
            _ => result.push(c),
        }
    }
    result
}

/// Escape a string for safe inclusion in JSON string values
/// Escapes quotes, backslashes, and control characters
fn escape_json(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                // Escape other control characters as \uXXXX
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            _ => result.push(c),
        }
    }
    result
}

/// Escape a string for safe inclusion in XML content
/// Similar to HTML escaping
fn escape_xml(s: &str) -> String {
    // XML escaping is the same as HTML for our purposes
    escape_html(s)
}

/// Escape mode for variable substitution
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EscapeMode {
    /// HTML escaping (< > & " ')
    Html,
    /// JSON string escaping (quotes, backslashes, control chars)
    Json,
    /// XML escaping (same as HTML)
    Xml,
    /// No escaping (plain text)
    None,
}

/// Template segment - either static text or a variable placeholder
#[derive(Debug, Clone, PartialEq)]
pub enum TemplateSegment {
    /// Static text content
    Text(String),
    /// Variable placeholder (e.g., "client_ip", "scenario")
    Variable(String),
}

/// Parsed response template with `{{variable}}` substitution (ban pages, captcha pages, JSON APIs).
#[derive(Debug, Clone)]
pub struct Template {
    segments: Vec<TemplateSegment>,
    /// Content-Type header value (auto-detected from file extension)
    content_type: String,
    /// Escape mode for variable values (auto-detected from content type)
    escape_mode: EscapeMode,
}

impl Template {
    /// Parse a template string into segments with default HTML content type
    /// Supports variables in the format {{variable_name}}
    #[cfg(test)]
    pub fn parse(content: &str) -> Self {
        Self::parse_with_content_type(content, "text/html; charset=utf-8")
    }

    /// Detect escape mode from content type string
    fn escape_mode_from_content_type(content_type: &str) -> EscapeMode {
        let ct_lower = content_type.to_lowercase();
        if ct_lower.contains("text/html") || ct_lower.contains("application/xhtml") {
            EscapeMode::Html
        } else if ct_lower.contains("application/json") {
            EscapeMode::Json
        } else if ct_lower.contains("application/xml") || ct_lower.contains("text/xml") {
            EscapeMode::Xml
        } else if ct_lower.contains("text/plain") {
            EscapeMode::None
        } else {
            // Default to HTML escaping for safety
            EscapeMode::Html
        }
    }

    /// Parse a template string with a specific content type
    pub fn parse_with_content_type(content: &str, content_type: &str) -> Self {
        let mut segments = Vec::new();
        let mut current_text = String::new();
        let mut chars = content.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '{' && chars.peek() == Some(&'{') {
                // Found opening {{
                chars.next(); // consume second {

                // Save current text if any
                if !current_text.is_empty() {
                    segments.push(TemplateSegment::Text(current_text.clone()));
                    current_text.clear();
                }

                // Read variable name until }}
                let mut var_name = String::new();
                let mut found_closing = false;

                while let Some(ch) = chars.next() {
                    if ch == '}' && chars.peek() == Some(&'}') {
                        chars.next(); // consume second }
                        found_closing = true;
                        break;
                    }
                    var_name.push(ch);
                }

                if found_closing && !var_name.trim().is_empty() {
                    segments.push(TemplateSegment::Variable(var_name.trim().to_string()));
                } else {
                    // Invalid syntax, treat as literal text
                    current_text.push_str("{{");
                    current_text.push_str(&var_name);
                    if !found_closing {
                        current_text.push('}');
                    }
                }
            } else {
                current_text.push(ch);
            }
        }

        // Add remaining text
        if !current_text.is_empty() {
            segments.push(TemplateSegment::Text(current_text));
        }

        let escape_mode = Self::escape_mode_from_content_type(content_type);

        Self {
            segments,
            content_type: content_type.to_string(),
            escape_mode,
        }
    }

    /// Detect content type from file extension
    fn content_type_from_extension(path: &Path) -> &'static str {
        match path.extension().and_then(|e| e.to_str()) {
            Some("json") => "application/json; charset=utf-8",
            Some("xml") => "application/xml; charset=utf-8",
            Some("txt") => "text/plain; charset=utf-8",
            Some("htm") | Some("html") | _ => "text/html; charset=utf-8",
        }
    }

    /// Load and parse a template from a file path
    /// Content type is auto-detected from file extension
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        let content =
            fs::read_to_string(path).map_err(|e| format!("Failed to read template file: {}", e))?;
        let content_type = Self::content_type_from_extension(path);
        Ok(Self::parse_with_content_type(&content, content_type))
    }

    /// Get the content type for this template
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// Render the template with variable substitutions
    /// Variables are automatically escaped based on the template's content type
    pub fn render(&self, variables: &TemplateVariables) -> String {
        let mut result = String::new();

        for segment in &self.segments {
            match segment {
                TemplateSegment::Text(text) => {
                    result.push_str(text);
                }
                TemplateSegment::Variable(var_name) => {
                    let value = variables.get(var_name).unwrap_or("");
                    // Escape the value based on content type
                    let escaped = match self.escape_mode {
                        EscapeMode::Html => escape_html(value),
                        EscapeMode::Json => escape_json(value),
                        EscapeMode::Xml => escape_xml(value),
                        EscapeMode::None => value.to_string(),
                    };
                    result.push_str(&escaped);
                }
            }
        }

        result
    }
}

/// Available template variables
#[derive(Debug, Default)]
pub struct TemplateVariables {
    /// Client IP address
    pub client_ip: Option<String>,
    /// Request URI
    pub request_uri: Option<String>,
    /// Request method
    pub request_method: Option<String>,
    /// CrowdSec scenario name when present on the cached decision (`{{scenario}}`)
    pub scenario: Option<String>,
    /// Decision origin label, e.g. `cscli` (`{{origin}}`)
    pub origin: Option<String>,
    /// HTTP `Host` header from the request (`{{host}}`)
    pub host: Option<String>,
    /// Captcha site key (public key for widget)
    pub captcha_site_key: Option<String>,
    /// Captcha provider script URL
    pub captcha_script_url: Option<String>,
    /// Captcha widget div class
    pub captcha_div_class: Option<String>,
    /// Captcha error message (if verification failed)
    pub captcha_error: Option<String>,
    /// Form action URL for captcha submission
    pub form_action: Option<String>,
}

impl TemplateVariables {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a variable value by name
    pub fn get(&self, name: &str) -> Option<&str> {
        match name {
            "client_ip" => self.client_ip.as_deref(),
            "request_uri" => self.request_uri.as_deref(),
            "request_method" => self.request_method.as_deref(),
            "scenario" => self.scenario.as_deref(),
            "origin" => self.origin.as_deref(),
            "host" => self.host.as_deref(),
            "captcha_site_key" => self.captcha_site_key.as_deref(),
            "captcha_script_url" => self.captcha_script_url.as_deref(),
            "captcha_div_class" => self.captcha_div_class.as_deref(),
            "captcha_error" => self.captcha_error.as_deref(),
            "form_action" => self.form_action.as_deref(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_scenario_origin_host() {
        let template = Template::parse("{{origin}}|{{scenario}}|{{host}}");
        let mut vars = TemplateVariables::new();
        vars.origin = Some("cscli".to_string());
        vars.scenario = Some("ssh-bf".to_string());
        vars.host = Some("example.com".to_string());
        assert_eq!(template.render(&vars), "cscli|ssh-bf|example.com");
    }

    #[test]
    fn test_parse_simple_text() {
        let template = Template::parse("Hello World");
        assert_eq!(template.segments.len(), 1);
        assert_eq!(
            template.segments[0],
            TemplateSegment::Text("Hello World".to_string())
        );
    }

    #[test]
    fn test_parse_with_variable() {
        let template = Template::parse("Your IP is {{client_ip}}");
        assert_eq!(template.segments.len(), 2);
        assert_eq!(
            template.segments[0],
            TemplateSegment::Text("Your IP is ".to_string())
        );
        assert_eq!(
            template.segments[1],
            TemplateSegment::Variable("client_ip".to_string())
        );
    }

    #[test]
    fn test_parse_multiple_variables() {
        let template = Template::parse("IP: {{client_ip}}, Scenario: {{scenario}}");
        assert_eq!(template.segments.len(), 4);
        assert_eq!(
            template.segments[0],
            TemplateSegment::Text("IP: ".to_string())
        );
        assert_eq!(
            template.segments[1],
            TemplateSegment::Variable("client_ip".to_string())
        );
        assert_eq!(
            template.segments[2],
            TemplateSegment::Text(", Scenario: ".to_string())
        );
        assert_eq!(
            template.segments[3],
            TemplateSegment::Variable("scenario".to_string())
        );
    }

    #[test]
    fn test_render() {
        let template = Template::parse("IP: {{client_ip}}");
        let mut vars = TemplateVariables::new();
        vars.client_ip = Some("192.168.1.1".to_string());

        let result = template.render(&vars);
        assert_eq!(result, "IP: 192.168.1.1");
    }

    #[test]
    fn test_render_unknown_variable() {
        let template = Template::parse("IP: {{client_ip}}, Unknown: {{unknown}}");
        let mut vars = TemplateVariables::new();
        vars.client_ip = Some("192.168.1.1".to_string());

        let result = template.render(&vars);
        assert_eq!(result, "IP: 192.168.1.1, Unknown: ");
    }

    #[test]
    fn test_content_type_detection() {
        use std::path::Path;

        assert_eq!(
            Template::content_type_from_extension(Path::new("/etc/nginx/ban.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            Template::content_type_from_extension(Path::new("/etc/nginx/ban.json")),
            "application/json; charset=utf-8"
        );
        assert_eq!(
            Template::content_type_from_extension(Path::new("/etc/nginx/ban.xml")),
            "application/xml; charset=utf-8"
        );
        assert_eq!(
            Template::content_type_from_extension(Path::new("/etc/nginx/ban.txt")),
            "text/plain; charset=utf-8"
        );
        // Unknown extension defaults to HTML
        assert_eq!(
            Template::content_type_from_extension(Path::new("/etc/nginx/ban.foo")),
            "text/html; charset=utf-8"
        );
    }

    #[test]
    fn test_default_content_type() {
        let template = Template::parse("test");
        assert_eq!(template.content_type(), "text/html; charset=utf-8");
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
        assert_eq!(escape_html("a & b"), "a &amp; b");
        assert_eq!(escape_html("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(escape_html("it's"), "it&#x27;s");
        assert_eq!(escape_html("normal text"), "normal text");
        assert_eq!(
            escape_html("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
        );
    }

    #[test]
    fn test_escape_json() {
        assert_eq!(escape_json("hello"), "hello");
        assert_eq!(escape_json("say \"hi\""), "say \\\"hi\\\"");
        assert_eq!(escape_json("back\\slash"), "back\\\\slash");
        assert_eq!(escape_json("line\nbreak"), "line\\nbreak");
        assert_eq!(escape_json("tab\there"), "tab\\there");
    }

    #[test]
    fn test_html_template_escapes_xss() {
        let template = Template::parse("<p>Path: {{request_uri}}</p>");
        let mut vars = TemplateVariables::new();
        vars.request_uri = Some("/<script>alert('xss')</script>".to_string());

        let result = template.render(&vars);
        assert_eq!(
            result,
            "<p>Path: /&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;</p>"
        );
        // Verify the script tag is NOT executable
        assert!(!result.contains("<script>"));
    }

    #[test]
    fn test_json_template_escapes() {
        let template = Template::parse_with_content_type(
            r#"{"uri": "{{request_uri}}"}"#,
            "application/json",
        );
        let mut vars = TemplateVariables::new();
        vars.request_uri = Some("/path\"with\"quotes".to_string());

        let result = template.render(&vars);
        assert_eq!(result, r#"{"uri": "/path\"with\"quotes"}"#);
    }

    #[test]
    fn test_plain_text_no_escape() {
        let template = Template::parse_with_content_type("Path: {{request_uri}}", "text/plain");
        let mut vars = TemplateVariables::new();
        vars.request_uri = Some("/<script>".to_string());

        let result = template.render(&vars);
        // Plain text should NOT escape
        assert_eq!(result, "Path: /<script>");
    }

    #[test]
    fn test_escape_mode_detection() {
        assert_eq!(
            Template::escape_mode_from_content_type("text/html; charset=utf-8"),
            EscapeMode::Html
        );
        assert_eq!(
            Template::escape_mode_from_content_type("application/json"),
            EscapeMode::Json
        );
        assert_eq!(
            Template::escape_mode_from_content_type("application/xml"),
            EscapeMode::Xml
        );
        assert_eq!(
            Template::escape_mode_from_content_type("text/plain"),
            EscapeMode::None
        );
        // Unknown defaults to HTML for safety
        assert_eq!(
            Template::escape_mode_from_content_type("application/octet-stream"),
            EscapeMode::Html
        );
    }
}
