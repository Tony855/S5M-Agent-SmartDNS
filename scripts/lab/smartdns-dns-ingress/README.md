# Docker DNS ingress source-IP lab

Run on a Linux Docker host from the repository root:

    bash scripts/lab/smartdns-dns-ingress/run.sh

The lab creates two isolated Docker bridge subnets and sends DNS-shaped UDP
and TCP requests through a port published only on the host's Docker bridge
gateway. It expects the receiver to observe 172.30.10.10 and 172.30.20.10 as
the source addresses for both transports. Set DNS_INGRESS_PORT to change the
host-side port. The script removes its temporary container and networks.

This tests Docker port-publishing/NAT source-address behavior only. It does
not validate SmartDNS group-match, Agent ingress configuration, Mihomo SOCKS
selection, DoT routing, or external proxy exit IP. A passing result is only
the first gate; repeat with the actual Agent/SmartDNS runtime and correlate
client IP, SmartDNS group, Mihomo proxy, and observed egress IP before enabling
per-client mode.

Requirements: Linux Docker Engine, IPv4 bridge networking,
and non-overlapping 172.30.10.0/24 and 172.30.20.0/24 networks. The lab never
binds a public/wildcard host address and does not alter production containers.
