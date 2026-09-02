# Ban Templates

This directory contains example ban templates that can be used with the `crowdsec_ban_template` directive.

## Available Templates

- **default.html** - A modern, styled HTML page with gradient background and card layout
- **simple.html** - A basic HTML template with minimal styling
- **minimal.html** - The simplest possible template
- **api.json** - A JSON response template (useful for API endpoints)

## Template Variables

All templates support the following variables using `{{variable_name}}` syntax:

- `{{client_ip}}` - The client's IP address that was blocked
- `{{request_method}}` - The HTTP method (GET, POST, etc.)
- `{{request_uri}}` - The requested URI path
- `{{reason}}` - Ban reason from CrowdSec when the stream includes it (stored in SHM; long reasons are truncated to 127 bytes)
- `{{scenario}}` - CrowdSec scenario name when the stream provided one
- `{{origin}}` - Where the decision came from (`crowdsec`, `cscli`, `capi`, `console`, `lists`, `unknown`)
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
