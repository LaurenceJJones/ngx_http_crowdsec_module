#!/bin/sh
set -e

# Enable core dumps
ulimit -c unlimited
echo '/tmp/core.%e.%p' > /proc/sys/kernel/core_pattern 2>/dev/null || true

# Substitute environment variables in nginx.conf
envsubst '${CROWDSEC_BOUNCER_KEY} ${CAPTCHA_SITE_KEY} ${CAPTCHA_SECRET_KEY} ${CAPTCHA_SIGNING_KEY}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

# Start nginx
exec nginx -g 'daemon off;'
