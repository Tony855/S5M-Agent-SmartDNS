#!/bin/sh
set -eu

wget -q -T 3 -O /dev/null http://127.0.0.1:80/api/config
pidof mihomo >/dev/null 2>&1
pidof smartdns >/dev/null 2>&1

# Process presence alone is insufficient: require successful answers over both
# loopback UDP and TCP on SmartDNS's configured nonstandard DNS port.
udp_answer="$(dig +time=2 +tries=1 +short @127.0.0.1 -p 6053 example.com A)"
[ -n "$udp_answer" ]
tcp_answer="$(dig +tcp +time=2 +tries=1 +short @127.0.0.1 -p 6053 example.com A)"
[ -n "$tcp_answer" ]
