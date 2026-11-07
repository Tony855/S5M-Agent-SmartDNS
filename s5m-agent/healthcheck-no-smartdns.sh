#!/bin/sh
set -eu
fail() { printf 'No-SmartDNS healthcheck failed: %s\n' "$*" >&2; exit 1; }
run_dns_probe() {
  label="$1"; pattern="$2"; shift 2
  if ! output="$("$@" 2>&1)"; then fail "$label command failed: $output"; fi
  if ! printf '%s\n' "$output" | grep -Eq "$pattern"; then fail "$label returned no valid address: $output"; fi
}
wget -q -T 3 -O /dev/null http://127.0.0.1:80/api/config || fail "Agent API is not ready"
pidof mihomo >/dev/null 2>&1 || fail "Mihomo process is not running"
if command -v smartdns >/dev/null 2>&1 || pidof smartdns >/dev/null 2>&1; then fail "SmartDNS must not be installed or running in this image"; fi
if grep -Eq "127\\.0\\.0\\.1:(6053|6054)|\\[::1\\]:(6053|6054)|localhost:(6053|6054)" /data/config.yaml; then fail "runtime Mihomo config still references retired SmartDNS listeners"; fi
dns_listener="$(awk '
  /^dns:[[:space:]]*$/ { in_dns=1; next }
  in_dns && /^[^[:space:]]/ { in_dns=0 }
  in_dns && /^[[:space:]]*listen:[[:space:]]*/ { sub(/^[[:space:]]*listen:[[:space:]]*/, ""); gsub(/"/, ""); print; exit }
' /data/config.yaml)"
dns_port="${dns_listener##*:}"
case "$dns_port" in ""|*[!0-9]*) fail "Mihomo DNS listen port is missing or invalid" ;; esac
run_dns_probe "UDP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +time=4 +tries=1 +short @127.0.0.1 -p "$dns_port" example.com A
run_dns_probe "TCP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +tcp +time=4 +tries=1 +short @127.0.0.1 -p "$dns_port" example.com A
run_dns_probe "domestic UDP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +time=4 +tries=1 +short @127.0.0.1 -p "$dns_port" www.baidu.com A
run_dns_probe "domestic TCP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +tcp +time=4 +tries=1 +short @127.0.0.1 -p "$dns_port" www.baidu.com A
if grep -Eq '^(  )?ipv6:[[:space:]]*true; then
  run_dns_probe "UDP AAAA" '^[0-9a-fA-F:]+$' dig +time=4 +tries=1 +short @127.0.0.1 -p "$dns_port" cloudflare.com AAAA
  run_dns_probe "TCP AAAA" '^[0-9a-fA-F:]+$' dig +tcp +time=4 +tries=1 +short @127.0.0.1 -p "$dns_port" cloudflare.com AAAA
fi
 /data/config.yaml; then
  run_dns_probe "UDP AAAA" '^[0-9a-fA-F:]+$' dig +time=4 +tries=1 +short @127.0.0.1 -p "$dns_port" cloudflare.com AAAA
  run_dns_probe "TCP AAAA" '^[0-9a-fA-F:]+$' dig +tcp +time=4 +tries=1 +short @127.0.0.1 -p "$dns_port" cloudflare.com AAAA
fi
