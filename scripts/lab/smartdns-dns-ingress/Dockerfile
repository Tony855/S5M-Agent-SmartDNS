FROM alpine:3.24
RUN apk add --no-cache ca-certificates libgcc libstdc++ libssl3 libcrypto3 zlib iproute2 python3 curl gzip
# Match the production image's pinned Mihomo release and verify its artifact.
RUN set -eux; \
    curl --fail --show-error --silent --location --retry 3 --retry-all-errors \
      "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.31/mihomo-linux-amd64-compatible-v1.19.31.gz" \
      -o /tmp/mihomo.gz; \
    echo "04cf9f09671704f839ddbee2e93069dc831a4123a75281e725d1d96ab9ac1afc  /tmp/mihomo.gz" | sha256sum -c -; \
    gzip -dc /tmp/mihomo.gz > /usr/local/bin/mihomo; \
    chmod 0755 /usr/local/bin/mihomo; \
    /usr/local/bin/mihomo -v
COPY .runtime/smartdns /usr/sbin/smartdns
COPY smartdns-per-client.conf /etc/smartdns/smartdns.conf
COPY socks-observer.py /usr/local/bin/socks-observer.py
ENTRYPOINT ["/usr/sbin/smartdns", "-f", "-c", "/etc/smartdns/smartdns.conf"]
