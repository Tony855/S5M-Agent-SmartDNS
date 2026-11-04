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

# A deliberate disable is healthy only when SmartDNS is stopped and Mihomo's
# own fallback DNS still resolves both the default and domestic route.
if [ -f /data/smartdns.disabled ]; then
  # During the short switch window the daemon may still be alive. If so,
  # require both its own listener and Mihomo's fallback path to work.
  if pidof smartdns >/dev/null 2>&1; then
    run_dns_probe "transition SmartDNS UDP A" '^[0-9]{1,3}(\\.[0-9]{1,3}){3} '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +time=3 +tries=1 +short @127.0.0.1 -p 5353 example.com A
  run_dns_probe "fallback TCP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +tcp +time=3 +tries=1 +short @127.0.0.1 -p 5353 example.com A
  run_dns_probe "fallback domestic UDP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +time=3 +tries=1 +short @127.0.0.1 -p 5353 www.baidu.com A
  run_dns_probe "fallback domestic TCP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +tcp +time=3 +tries=1 +short @127.0.0.1 -p 5353 www.baidu.com A
  if grep -Eq '^  ipv6:[[:space:]]*true$' /data/config.yaml; then
    run_dns_probe "fallback UDP AAAA" '^[0-9a-fA-F:]+$' dig +time=3 +tries=1 +short @127.0.0.1 -p 5353 cloudflare.com AAAA
    run_dns_probe "fallback TCP AAAA" '^[0-9a-fA-F:]+$' dig +tcp +time=3 +tries=1 +short @127.0.0.1 -p 5353 cloudflare.com AAAA
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
 dig +time=3 +tries=1 +short @127.0.0.1 -p 6053 example.com A
  fi
  run_dns_probe "fallback UDP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +time=3 +tries=1 +short @127.0.0.1 -p 5353 example.com A
  run_dns_probe "fallback TCP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +tcp +time=3 +tries=1 +short @127.0.0.1 -p 5353 example.com A
  run_dns_probe "fallback domestic UDP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +time=3 +tries=1 +short @127.0.0.1 -p 5353 www.baidu.com A
  run_dns_probe "fallback domestic TCP A" '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' dig +tcp +time=3 +tries=1 +short @127.0.0.1 -p 5353 www.baidu.com A
  if grep -Eq '^  ipv6:[[:space:]]*true$' /data/config.yaml; then
    run_dns_probe "fallback UDP AAAA" '^[0-9a-fA-F:]+$' dig +time=3 +tries=1 +short @127.0.0.1 -p 5353 cloudflare.com AAAA
    run_dns_probe "fallback TCP AAAA" '^[0-9a-fA-F:]+$' dig +tcp +time=3 +tries=1 +short @127.0.0.1 -p 5353 cloudflare.com AAAA
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
