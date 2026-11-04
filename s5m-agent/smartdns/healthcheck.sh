#!/bin/sh
set -eu

wget -q -T 3 -O /dev/null http://127.0.0.1:80/api/config
pidof mihomo >/dev/null 2>&1
pidof smartdns >/dev/null 2>&1

# Require real A and AAAA address records over both transports.
udp_a="$(dig +time=2 +tries=1 +short @127.0.0.1 -p 6053 example.com A)"
printf '%s\n' "$udp_a" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
udp_aaaa="$(dig +time=2 +tries=1 +short @127.0.0.1 -p 6053 cloudflare.com AAAA)"
printf '%s\n' "$udp_aaaa" | grep -Eq '^[0-9a-fA-F:]+$'

tcp_a="$(dig +tcp +time=2 +tries=1 +short @127.0.0.1 -p 6053 example.com A)"
printf '%s\n' "$tcp_a" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
tcp_aaaa="$(dig +tcp +time=2 +tries=1 +short @127.0.0.1 -p 6053 cloudflare.com AAAA)"
printf '%s\n' "$tcp_aaaa" | grep -Eq '^[0-9a-fA-F:]+$'

# The domestic listener must be tested with a domain covered by the china-dot policy.
if grep -Fqx 'bind 127.0.0.1:6054 -group china-dot' /data/smartdns.conf; then
  grep -Fqx 'bind-tcp 127.0.0.1:6054 -group china-dot' /data/smartdns.conf
  domestic_udp_a="$(dig +time=2 +tries=1 +short @127.0.0.1 -p 6054 www.baidu.com A)"
  printf '%s\n' "$domestic_udp_a" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
  domestic_udp_aaaa="$(dig +time=2 +tries=1 +short @127.0.0.1 -p 6054 www.baidu.com AAAA)"
  printf '%s\n' "$domestic_udp_aaaa" | grep -Eq '^[0-9a-fA-F:]+$'
  domestic_tcp_a="$(dig +tcp +time=2 +tries=1 +short @127.0.0.1 -p 6054 www.baidu.com A)"
  printf '%s\n' "$domestic_tcp_a" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
  domestic_tcp_aaaa="$(dig +tcp +time=2 +tries=1 +short @127.0.0.1 -p 6054 www.baidu.com AAAA)"
  printf '%s\n' "$domestic_tcp_aaaa" | grep -Eq '^[0-9a-fA-F:]+$'
fi
