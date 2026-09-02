# Multi-stage build for CrowdSec NGINX module
# Build NGINX and the Rust module together to ensure binary compatibility

# =============================================================================
# Stage 1: Build NGINX (cached separately - rarely changes)
# =============================================================================
ARG NGINX_VERSION=1.30.3

FROM rust:1.98-bookworm AS nginx-builder
ARG NGINX_VERSION

RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libpcre2-dev \
    zlib1g-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /nginx

# Download and build NGINX - this layer is cached unless NGINX_VERSION changes
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

# =============================================================================
# Stage 2: Build Rust module
# =============================================================================
FROM rust:1.98-bookworm AS rust-builder
ARG NGINX_VERSION

# Install build dependencies for ngx crate
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libpcre2-dev \
    zlib1g-dev \
    clang \
    llvm \
    && rm -rf /var/lib/apt/lists/*

# Copy NGINX build artifacts from previous stage
COPY --from=nginx-builder /nginx /nginx
COPY --from=nginx-builder /etc/nginx /etc/nginx
COPY --from=nginx-builder /usr/sbin/nginx /usr/sbin/nginx

# Set up environment for nginx-sys to find NGINX
ENV NGINX_SOURCE_DIR=/nginx/nginx-${NGINX_VERSION}
ENV NGINX_BUILD_DIR=/nginx/nginx-${NGINX_VERSION}/objs

WORKDIR /build

# Copy source code and build
# Note: We can't use the dummy lib.rs trick here because the ngx crate's build.rs
# needs to generate bindings that depend on our actual code structure
COPY Cargo.toml Cargo.lock* ./
COPY src ./src

# Compile test targets and build against the same NGINX source as the runtime binary.
# NGINX module unit-test binaries cannot link without the host NGINX executable.
RUN cargo check --tests --locked && cargo build --release --locked

# =============================================================================
# Stage 3: Create the final runtime image
# =============================================================================
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

# Copy NGINX from nginx-builder stage
COPY --from=nginx-builder /usr/sbin/nginx /usr/sbin/nginx
COPY --from=nginx-builder /etc/nginx /etc/nginx

# Copy the built module from rust-builder stage
COPY --from=rust-builder /build/target/release/libngx_http_crowdsec_module.so /etc/nginx/modules/

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
