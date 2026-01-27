# Multi-stage build for CrowdSec NGINX module
# Build NGINX and the Rust module together to ensure binary compatibility

# Stage 1: Build NGINX and the Rust module
FROM rust:1.83-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libpcre2-dev \
    zlib1g-dev \
    clang \
    llvm \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Download and build NGINX first
WORKDIR /nginx
ENV NGINX_VERSION=1.26.2
RUN wget -q https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
    && tar xzf nginx-${NGINX_VERSION}.tar.gz \
    && cd nginx-${NGINX_VERSION} \
    && ./configure \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --modules-path=/etc/nginx/modules \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --pid-path=/var/run/nginx.pid \
        --lock-path=/var/run/nginx.lock \
        --with-compat \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-http_realip_module \
        --with-http_stub_status_module \
        --with-pcre \
    && make \
    && make install

# Set up environment for nginx-sys to find NGINX
ENV NGINX_SOURCE_DIR=/nginx/nginx-1.26.2
ENV NGINX_BUILD_DIR=/nginx/nginx-1.26.2/objs

WORKDIR /build

# Copy the source code
COPY Cargo.toml Cargo.lock* ./
COPY src ./src

# Build the module WITHOUT vendored feature (uses the NGINX we just built)
RUN cargo build --release

# Stage 2: Create the final runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    libpcre2-8-0 \
    zlib1g \
    gettext-base \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log/nginx /var/cache/nginx \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

# Copy NGINX from builder
COPY --from=builder /usr/sbin/nginx /usr/sbin/nginx
COPY --from=builder /etc/nginx /etc/nginx

# Copy the built module
COPY --from=builder /build/target/release/libngx_http_crowdsec_module.so /etc/nginx/modules/

# Copy configuration template and entrypoint
COPY docker/nginx.conf /etc/nginx/nginx.conf.template
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create HTML directory and default files
RUN mkdir -p /usr/share/nginx/html
RUN echo '<!DOCTYPE html><html><head><title>CrowdSec NGINX Module</title></head><body><h1>Hello from NGINX with CrowdSec!</h1><p>This page is protected by CrowdSec.</p></body></html>' > /usr/share/nginx/html/index.html
RUN echo '<!DOCTYPE html><html><head><title>Test Page</title></head><body><h1>Test Page</h1><p>This is a test page.</p></body></html>' > /usr/share/nginx/html/test.html

# Copy ban templates
COPY templates /etc/nginx/templates

# Create nginx user
RUN useradd -r -s /sbin/nologin nginx

# Expose port
EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
