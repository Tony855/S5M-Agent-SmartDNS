#!/bin/sh
set -eu

fail() {
  printf 'SmartDNS healthcheck failed: %s\n' "$*" >&2
  exit 1
}

run_dns_probe() {
  label="$1"
  pattern="$2"
  shift 2
  if ! output="$("$@" 2>&1)"; then
    fail "$label command failed: $output"
  fi
  if ! printf '%s\n' "$output" | grep -Eq "$pattern"; then
    fail "$label returned no valid address: $output"
  fi
}

wget -q -T 3 -O /dev/null http://127.0.0.1:80/api/config || fail "Agent API is not ready"
pidof mihomo >/dev/null 2>&1 || fail "Mihomo process is not running"

# A deliberate disable is healthy only when Mihomo's own fallback DNS works.
# During the transition, also require the still-running SmartDNS listener to work.
if [ -f /data/smartdns.disabled ]; then
  dns_listener="$(awk '
    /^dns:[[:space:]]*$/ { in_dns=1; next }
    in_dns && /^[^[:space:]]/ { in_dns=0 }
    in_dns && /^[[:space:]]*listen:[[:space:]]*/ {
      sub(/^[[:space:]]*listen:[[:space:]]*/, "")
      gsub(/"/, "")
      print
      exit
    }
  ' /data/config.yaml)"
  dns_port="${dns_listener##*:}"
  case "$dns_port" in
    ""|*[!0-9]*) fail "Mihomo DNS listen port is missing or invalid" ;;
  esac
  if pidof smartdns >/dev/null 2>&1; then
    run_dns_probe "transition SmartDNS UDP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +time=3 +tries=1 +short @127.0.0.1 -p 6053 example.com A
  fi
  run_dns_probe "fallback UDP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +time=3 +tries=1 +short @127.0.0.1 -p "$dns_port" example.com A
  run_dns_probe "fallback TCP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +tcp +time=3 +tries=1 +short @127.0.0.1 -p "$dns_port" example.com A
  run_dns_probe "fallback domestic UDP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +time=3 +tries=1 +short @127.0.0.1 -p "$dns_port" www.baidu.com A
  run_dns_probe "fallback domestic TCP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +tcp +time=3 +tries=1 +short @127.0.0.1 -p "$dns_port" www.baidu.com A
  if grep -Eq '^  ipv6:[[:space:]]*true$' /data/config.yaml; then
    run_dns_probe "fallback UDP AAAA" '^[0-9a-fA-F:]+$' dig +time=3 +tries=1 +short @127.0.0.1 -p "$dns_port" cloudflare.com AAAA
    run_dns_probe "fallback TCP AAAA" '^[0-9a-fA-F:]+$' dig +tcp +time=3 +tries=1 +short @127.0.0.1 -p "$dns_port" cloudflare.com AAAA
  fi
  exit 0
fi

pidof smartdns >/dev/null 2>&1 || fail "SmartDNS process is not running"

# Require real A and AAAA address records over both transports.
run_dns_probe "primary UDP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +time=2 +tries=1 +short @127.0.0.1 -p 6053 example.com A
run_dns_probe "primary UDP AAAA" '^[0-9a-fA-F:]+$' dig +time=2 +tries=1 +short @127.0.0.1 -p 6053 cloudflare.com AAAA
run_dns_probe "primary TCP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +tcp +time=2 +tries=1 +short @127.0.0.1 -p 6053 example.com A
run_dns_probe "primary TCP AAAA" '^[0-9a-fA-F:]+$' dig +tcp +time=2 +tries=1 +short @127.0.0.1 -p 6053 cloudflare.com AAAA

# The domestic listener must be tested with a domain covered by the china-dot policy.
if grep -Fqx 'bind 127.0.0.1:6054 -group china-dot' /data/smartdns.conf; then
  grep -Fqx 'bind-tcp 127.0.0.1:6054 -group china-dot' /data/smartdns.conf || fail "domestic TCP listener is missing"
  run_dns_probe "domestic UDP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +time=2 +tries=1 +short @127.0.0.1 -p 6054 www.baidu.com A
  run_dns_probe "domestic UDP AAAA" '^[0-9a-fA-F:]+$' dig +time=2 +tries=1 +short @127.0.0.1 -p 6054 www.qq.com AAAA
  run_dns_probe "domestic TCP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +tcp +time=2 +tries=1 +short @127.0.0.1 -p 6054 www.baidu.com A
  run_dns_probe "domestic TCP AAAA" '^[0-9a-fA-F:]+$' dig +tcp +time=2 +tries=1 +short @127.0.0.1 -p 6054 www.qq.com AAAA
fi
