# Docker DNS ingress source-IP lab

Run on a Linux Docker host from the repository root:

    bash scripts/lab/smartdns-dns-ingress/run.sh

The lab creates two isolated Docker bridge subnets and sends DNS-shaped UDP
and TCP requests through a port published only on the host's Docker bridge
gateway. It expects the receiver to observe 172.30.10.10 and 172.30.20.10 as
the source addresses for both transports. Set DNS_INGRESS_PORT to change the
host-side port. The script removes its temporary container and networks.

On standard Docker bridge networking this topology is expected to expose a
source-NAT rewrite: the receiver sees the host bridge gateway (for example
172.17.0.1), not the two client container addresses. The lab asserts this
behavior so it cannot be mistaken for source-preserving ingress. It does not
prove what happens to packets arriving from a physical LAN interface. Test
that separately on a real host using two LAN clients and capture both the host
LAN interface and the SmartDNS container interface.

This does not validate SmartDNS group-match, Agent ingress configuration,
Mihomo SOCKS selection, DoT routing, or external proxy exit IP. Do not enable
per-client mode based on this test. The real Agent/SmartDNS runtime must still
correlate client IP, SmartDNS group, Mihomo proxy, and observed egress IP.

Requirements: Linux Docker Engine, IPv4 bridge networking,
and non-overlapping 172.30.10.0/24 and 172.30.20.0/24 networks. The lab never
binds a public/wildcard host address and does not alter production containers.
