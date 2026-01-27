# NGINX Makefile integration for ngx_http_crowdsec_module
# This script is included during NGINX build process

ngx_addon_name="ngx_http_crowdsec_module"
ngx_cargo_manifest="$ngx_addon_dir/Cargo.toml"

ngx_rust_make_modules
