# Multi-stage build: keep the runtime image small and run as non-root.
FROM golang:1.23-alpine AS builder
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/S5M-Server .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && addgroup -S s5m && adduser -S -G s5m -h /app s5m \
 && mkdir -p /data/s5m-server && chown -R s5m:s5m /data
WORKDIR /app
COPY --from=builder /out/S5M-Server /app/S5M-Server
ENV S5M_ADDR=:8080 \
    S5M_DB=/data/s5m-server/s5m.db \
    S5M_CONFIG=/data/s5m-server/config.yaml \
    S5M_BACKUP=/data/s5m-server/backups
USER s5m
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/api/v1/health || exit 1
ENTRYPOINT ["/app/S5M-Server"]
