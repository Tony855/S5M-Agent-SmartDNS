# syntax=docker/dockerfile:1
ARG ALPINE_VERSION=3.24
ARG MIHOMO_VERSION=v1.19.31
ARG S6_OVERLAY_VERSION=3.2.3.2
# SHA-256 digests published by the official MetaCubeX/mihomo v1.19.31 release.
ARG MIHOMO_AMD64_SHA256=04cf9f09671704f839ddbee2e93069dc831a4123a75281e725d1d96ab9ac1afc
ARG MIHOMO_ARM64_SHA256=9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4

FROM --platform=$BUILDPLATFORM alpine:${ALPINE_VERSION} AS agent-builder
ARG TARGETOS
ARG TARGETARCH
RUN apk add --no-cache go git
WORKDIR /src
COPY s5m-agent/go.mod s5m-agent/go.sum ./
RUN go mod download
COPY s5m-agent/main.go ./main.go
COPY s5m-agent/smartdns_runtime.go ./smartdns_runtime.go
RUN mkdir -p /out && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/s5m-agent .

FROM alpine:${ALPINE_VERSION} AS mihomo-fetch
ARG TARGETARCH
ARG MIHOMO_VERSION
ARG MIHOMO_AMD64_SHA256
ARG MIHOMO_ARM64_SHA256
RUN apk add --no-cache ca-certificates curl gzip
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) asset="mihomo-linux-amd64-compatible-${MIHOMO_VERSION}.gz"; expected_sha256="${MIHOMO_AMD64_SHA256}" ;; \
      arm64) asset="mihomo-linux-arm64-${MIHOMO_VERSION}.gz"; expected_sha256="${MIHOMO_ARM64_SHA256}" ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --fail --show-error --silent --location --retry 3 --retry-all-errors \
      "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/${asset}" -o /tmp/mihomo.gz; \
    echo "${expected_sha256}  /tmp/mihomo.gz" | sha256sum -c -; \
    gzip -dc /tmp/mihomo.gz > /usr/local/bin/mihomo; \
    chmod 0755 /usr/local/bin/mihomo; \
    /usr/local/bin/mihomo -v

FROM alpine:${ALPINE_VERSION} AS s6-overlay-fetch
ARG TARGETARCH
ARG S6_OVERLAY_VERSION
RUN apk add --no-cache ca-certificates curl xz
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) s6_arch="x86_64" ;; \
      arm64) s6_arch="aarch64" ;; \
      *) echo "Unsupported architecture for s6-overlay: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    mkdir -p /out; \
    base="https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}"; \
    curl --fail --show-error --silent --location --retry 3 --retry-all-errors "${base}/s6-overlay-noarch.tar.xz" -o /tmp/s6-overlay-noarch.tar.xz; \
    curl --fail --show-error --silent --location --retry 3 --retry-all-errors "${base}/s6-overlay-noarch.tar.xz.sha256" -o /tmp/s6-overlay-noarch.tar.xz.sha256; \
    curl --fail --show-error --silent --location --retry 3 --retry-all-errors "${base}/s6-overlay-${s6_arch}.tar.xz" -o /tmp/s6-overlay-${s6_arch}.tar.xz; \
    curl --fail --show-error --silent --location --retry 3 --retry-all-errors "${base}/s6-overlay-${s6_arch}.tar.xz.sha256" -o /tmp/s6-overlay-${s6_arch}.tar.xz.sha256; \
    (cd /tmp && sha256sum -c s6-overlay-noarch.tar.xz.sha256 && sha256sum -c s6-overlay-${s6_arch}.tar.xz.sha256); \
    tar -Jxpf /tmp/s6-overlay-noarch.tar.xz -C /out; \
    tar -Jxpf /tmp/s6-overlay-${s6_arch}.tar.xz -C /out

FROM alpine:${ALPINE_VERSION} AS runtime
LABEL org.opencontainers.image.source="https://github.com/Tony855/S5M-Agent-SmartDNS"
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S s5m && adduser -S -D -H -G s5m s5m \
    && mkdir -p /data /app
COPY --from=s6-overlay-fetch /out/ /
WORKDIR /app
COPY --from=agent-builder /out/s5m-agent /app/s5m-agent
COPY --from=mihomo-fetch /usr/local/bin/mihomo /usr/local/bin/mihomo
COPY s5m-agent/index.html /app/index.html
COPY s5m-agent/healthcheck.sh /healthcheck.sh
COPY s5m-agent/default-config.yaml /app/default-config.yaml
COPY s5m-agent/cont-init.d/ /etc/cont-init.d/
COPY s5m-agent/services/ /etc/s6-overlay/s6-rc.d/
RUN chmod 0755 /healthcheck.sh /etc/cont-init.d/10-mihomo-config \
    /etc/s6-overlay/s6-rc.d/mihomo/run \
    /etc/s6-overlay/s6-rc.d/agent/run \
    && chmod 0644 /etc/s6-overlay/s6-rc.d/mihomo/type \
    /etc/s6-overlay/s6-rc.d/agent/type
ENV S6_KEEP_ENV=1 \
    S6_CMD_WAIT_FOR_SERVICES=1 \
    S6_SERVICES_GRACETIME=15000 \
    S6_KILL_FINISH_MAXTIME=5000 \
    S5M_AGENT_PORT=80 \
    MIHOMO_HOME=/data \
    MIHOMO_API=127.0.0.1:8088
VOLUME ["/data"]
EXPOSE 80 7890
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/healthcheck.sh"]
ENTRYPOINT ["/init"]
