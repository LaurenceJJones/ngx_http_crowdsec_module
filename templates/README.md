# Ban Templates

This directory contains example ban templates that can be used with the `crowdsec_ban_template` directive.

## Template files

Example pages for `crowdsec_ban_template` and `crowdsec_captcha_template`. Both are **optional**:

- **Ban** — without a template, block mode returns `crowdsec_ban_status` (default 403) with a minimal body. Set `crowdsec_ban_action redirect` to redirect instead.
- **Captcha** — without a template, `crowdsec_unenforceable_action allow` (default) passes the request through when a captcha decision cannot be shown; use `block` to return `crowdsec_ban_status` instead. With `unenforceable_action block`, a template is required at `nginx -t`.

Copy and customize the examples in this directory, then point nginx at them:

```nginx
crowdsec_ban_template /etc/nginx/templates/default.html;
crowdsec_captcha_template /etc/nginx/templates/captcha.html;  # when using captcha
```

To upload templates to a remote host for testing, copy `scripts/deploy-templates.example.sh` to `scripts/deploy-templates.local.sh` (gitignored), set your host, and run it.

## Available Templates

- **default.html** - Corporate ban page (light card layout, structured request details)
- **captcha.html** - Corporate captcha challenge page (matches built-in fallback styling)
- **simple.html** - Lightweight corporate HTML for quick overrides
- **minimal.html** - The simplest possible template
- **api.json** - A JSON response template (useful for API endpoints)

## Template Variables

All templates support the following variables using `{{variable_name}}` syntax:

- `{{client_ip}}` - The client's IP address that was blocked
- `{{request_method}}` - The HTTP method (GET, POST, etc.)
- `{{request_uri}}` - The requested URI path
- `{{scenario}}` - CrowdSec scenario (includes cscli `--reason` text; stored in SHM, truncated to 127 bytes)
- `{{origin}}` - Where the decision came from (`crowdsec`, `cscli`, `capi`, `console`, `lists`, `appsec`, `unknown`). AppSec bans use `appsec`; `{{scenario}}` is empty because the AppSec protocol does not include the matched rule.
- `{{host}}` - The request's `Host` header (useful behind reverse proxies)

## Usage

In your NGINX configuration:

```nginx
http {
    # Set default template at http level
    crowdsec_ban_template /path/to/templates/default.html;
    
    server {
        listen 8080;
        
        # Can override at server level
        # crowdsec_ban_template /path/to/templates/simple.html;
        
        location / {
            # Inherits template from http/server level
        }
        
        location /api {
            # Use JSON template for API endpoints
            crowdsec_ban_template /path/to/templates/api.json;
        }
    }
}
```

## Template Caching

The module caches parsed templates by file path, so if the same template file is referenced multiple times (e.g., at http, server, and location levels), it will only be parsed once during configuration loading.

## Creating Custom Templates

You can create your own templates by:

1. Creating a new file in this directory (or anywhere accessible to NGINX)
2. Using the `{{variable_name}}` syntax for dynamic content
3. Setting the path in your NGINX configuration

Example custom template:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Blocked</title>
</head>
<body>
    <h1>Your access has been restricted</h1>
    <p>IP: {{client_ip}}</p>
    <p>URI: {{request_uri}}</p>
</body>
</html>
```
