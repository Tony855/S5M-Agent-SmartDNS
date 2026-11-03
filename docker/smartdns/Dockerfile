# syntax=docker/dockerfile:1
# Build only SmartDNS core; do not compile the optional Web UI.
ARG ALPINE_VERSION=3.22

FROM alpine:${ALPINE_VERSION} AS build
ARG SMARTDNS_REF=Release48.4
RUN apk add --no-cache --virtual .build-deps \
      build-base git linux-headers openssl-dev zlib-dev
RUN git clone --depth 1 --branch "${SMARTDNS_REF}" \
      https://github.com/pymumu/smartdns.git /src \
    && git -C /src rev-parse HEAD > /tmp/SMARTDNS_SOURCE_COMMIT \
    && make -C /src/src WITH_ZLIB=1 \
    && install -D -m 0755 /src/src/smartdns /out/usr/sbin/smartdns \
    && install -D -m 0644 /src/LICENSE /out/usr/share/licenses/smartdns/LICENSE \
    && install -D -m 0644 /tmp/SMARTDNS_SOURCE_COMMIT /out/usr/share/licenses/smartdns/SOURCE_COMMIT \
    && printf '%s\n' 'https://github.com/pymumu/smartdns' > /out/usr/share/licenses/smartdns/SOURCE_URL

FROM alpine:${ALPINE_VERSION} AS runtime
ARG SMARTDNS_REF=Release48.4
LABEL org.opencontainers.image.title="SmartDNS (core only)" \
      org.opencontainers.image.description="Lightweight SmartDNS DNS resolver without Web UI" \
      org.opencontainers.image.source="https://github.com/pymumu/smartdns" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.version="${SMARTDNS_REF}"

RUN apk add --no-cache ca-certificates libgcc libstdc++ libssl3 libcrypto3 zlib \
    && mkdir -p /etc/smartdns
COPY --from=build /out/usr/sbin/smartdns /usr/sbin/smartdns
COPY --from=build /out/usr/share/licenses/smartdns /usr/share/licenses/smartdns
COPY smartdns.conf /etc/smartdns/smartdns.conf

EXPOSE 53/udp 53/tcp
STOPSIGNAL SIGTERM
CMD ["/usr/sbin/smartdns", "-f", "-x"]
