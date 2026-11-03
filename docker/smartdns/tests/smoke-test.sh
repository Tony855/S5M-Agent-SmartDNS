#!/usr/bin/env sh
set -eu

IMAGE="${1:-smartdns:test}"
NAME="smartdns-smoke-$$"
cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 2; }
command -v dig >/dev/null 2>&1 || { echo "dig is required (install dnsutils/bind-tools)" >&2; exit 2; }

docker run -d --name "$NAME" \
  -p 127.0.0.1::53/udp \
  -p 127.0.0.1::53/tcp \
  "$IMAGE" >/dev/null

UDP_BINDING=""
TCP_BINDING=""
i=0
while [ "$i" -lt 30 ]; do
  UDP_BINDING="$(docker port "$NAME" 53/udp 2>/dev/null | head -n 1 || true)"
  TCP_BINDING="$(docker port "$NAME" 53/tcp 2>/dev/null | head -n 1 || true)"
  UDP_PORT="${UDP_BINDING##*:}"
  TCP_PORT="${TCP_BINDING##*:}"
  if [ -n "$UDP_PORT" ] && [ -n "$TCP_PORT" ] \
    && dig @127.0.0.1 -p "$UDP_PORT" example.com A +time=2 +tries=1 +short 2>/dev/null | grep -Eq '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
    break
  fi
  i=$((i + 1))
  sleep 1
done

if [ -z "${UDP_PORT:-}" ] || [ -z "${TCP_PORT:-}" ]; then
  docker logs "$NAME" || true
  echo "SmartDNS did not expose UDP/TCP ports" >&2
  exit 1
fi

UDP_RESULT="$(dig @127.0.0.1 -p "$UDP_PORT" example.com A +time=3 +tries=1 +short)"
printf '%s\n' "$UDP_RESULT" | grep -Eq '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || {
  docker logs "$NAME" || true
  echo "UDP DNS query failed" >&2
  exit 1
}

TCP_RESULT="$(dig +tcp @127.0.0.1 -p "$TCP_PORT" example.com A +time=3 +tries=1 +short)"
printf '%s\n' "$TCP_RESULT" | grep -Eq '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || {
  docker logs "$NAME" || true
  echo "TCP DNS query failed" >&2
  exit 1
}

echo "PASS: SmartDNS answered example.com over UDP (port $UDP_PORT) and TCP (port $TCP_PORT)."
