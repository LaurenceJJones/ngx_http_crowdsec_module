# Runner for cscli hubtest against host-network NGINX target (:7822).
FROM crowdsecurity/crowdsec:v1.8.1

ARG NUCLEI_VERSION=3.3.9
RUN apk add --no-cache ca-certificates curl unzip \
    && curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei.zip

# Bake default cscli/crowdsec config from image staging (hubtest uses per-test runtime).
RUN rsync -a /staging/etc/crowdsec/ /etc/crowdsec/

WORKDIR /hub
ENTRYPOINT ["cscli"]
