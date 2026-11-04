#!/bin/sh
set -eu

wget -q -T 3 -O /dev/null http://127.0.0.1:80/api/config
pidof mihomo >/dev/null 2>&1
pidof smartdns >/dev/null 2>&1

# Process presence alone is insufficient: require successful A and AAAA answers
# over both loopback transports on SmartDNS's configured primary DNS port.
udp_a="$(dig +time=2 +tries=1 +short @127.0.0.1 -p 6053 example.com A)"
[ -n "$udp_a" ]
udp_aaaa="$(dig +time=2 +tries=1 +short @127.0.0.1 -p 6053 example.com AAAA)"
printf '%s\\n' "$udp_aaaa" | grep -Eq '^[0-9a-fA-F:]+$'
tcp_a="$(dig +tcp +time=2 +tries=1 +short @127.0.0.1 -p 6053 example.com A)"
[ -n "$tcp_a" ]
tcp_aaaa="$(dig +tcp +time=2 +tries=1 +short @127.0.0.1 -p 6053 example.com AAAA)"
printf '%s\\n' "$tcp_aaaa" | grep -Eq '^[0-9a-fA-F:]+$'

# The domestic-only policy listener is independent from the primary resolver.
# When configured, require A and AAAA over both transports before Docker reports healthy.
if grep -Fqx 'bind 127.0.0.1:6054 -group china-dot' /data/smartdns.conf; then
  grep -Fqx 'bind-tcp 127.0.0.1:6054 -group china-dot' /data/smartdns.conf
  domestic_udp_a="$(dig +time=2 +tries=1 +short @127.0.0.1 -p 6054 example.com A)"
  [ -n "$domestic_udp_a" ]
  domestic_udp_aaaa="$(dig +time=2 +tries=1 +short @127.0.0.1 -p 6054 example.com AAAA)"
  printf '%s\\n' "$domestic_udp_aaaa" | grep -Eq '^[0-9a-fA-F:]+$'
  domestic_tcp_a="$(dig +tcp +time=2 +tries=1 +short @127.0.0.1 -p 6054 example.com A)"
  [ -n "$domestic_tcp_a" ]
  domestic_tcp_aaaa="$(dig +tcp +time=2 +tries=1 +short @127.0.0.1 -p 6054 example.com AAAA)"
  printf '%s\\n' "$domestic_tcp_aaaa" | grep -Eq '^[0-9a-fA-F:]+$'
fi
