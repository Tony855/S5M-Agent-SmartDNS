# SmartDNS DNS ingress source-IP labs

The existing `run.sh` tests Docker published-port NAT behavior. The existing
`run-routed.sh` tests kernel/Docker routed-bridge source preservation with a
Python receiver. Neither proves SmartDNS itself selects the right client group.

## Real SmartDNS daemon group-match test

The GitHub Actions workflow
`.github/workflows/smartdns-real-daemon-ingress.yml` builds the exact pinned
SmartDNS source commit used by the combined Agent image, starts the real daemon
on a dedicated routed bridge, and sends DNS queries from two Linux network
namespaces with distinct client addresses.

Expected results:
- `192.168.50.10` receives `192.0.2.10`
- `192.168.50.20` receives `192.0.2.20`
- both results are verified over UDP and TCP

This tests actual SmartDNS `group-match -client-ip` behavior using the source
address delivered to the daemon, not only a generic receiver. It remains a
same-host IPv4 lab; it does not prove physical LAN routing, Agent validator or
deployment acceptance, IPv6, firewall deployment, Mihomo SOCKS selection,
DoT transport, or public proxy egress.

Local execution after building the pinned daemon:

```sh
docker build --target smartdns-builder --tag s5m-smartdns-lab-builder -f s5m-agent/Dockerfile.smartdns .
id="$(docker create s5m-smartdns-lab-builder)"
mkdir -p scripts/lab/smartdns-dns-ingress/.runtime
docker cp "$id:/out/usr/sbin/smartdns" scripts/lab/smartdns-dns-ingress/.runtime/smartdns
docker rm "$id"
docker build --tag s5m-smartdns-routed-lab scripts/lab/smartdns-dns-ingress
sudo bash scripts/lab/smartdns-dns-ingress/run-smartdns-routed.sh
```

The test uses isolated namespaces, a dedicated Docker network, and TEST-NET-1
addresses. It does not modify production containers or publish a host port.

## Dual-network Agent topology check

The real-daemon routed test also models the Agent's intended Docker topology:
the container is created on the ordinary `bridge` network first (default
egress), then attached to the routed ingress network with a static address
before it starts. The test verifies both network attachments and checks that
the default route still points at the ordinary bridge gateway. It then sends
the per-client DNS queries over the routed interface and confirms the daemon
sees the original client CIDRs.

This is still a same-host IPv4 lab. It validates Docker's dual-network
primitive, not the production deployer's network creation, host firewall
rules, router route installation, IPv6, or real public proxy egress.

## Fail-closed unmatched client assertion

The real-daemon fixture marks every mapped DoT server with
`-exclude-default-group` and sends a third query from an unmapped client CIDR.
The test requires that client to receive no A answer. This guards against
SmartDNS silently placing a per-client upstream back into the default group,
which would otherwise let unmapped clients use an arbitrary proxy exit.

The same test now starts two local SOCKS5 observer sidecars on the SmartDNS
container's loopback ports. For an uncached upstream query, the first client
must cause CONNECT attempts only on its own named SOCKS listener, the second
client only on the other listener, and an unmapped client must cause no SOCKS
attempt on either listener. The observers deliberately reject the tunnel after
recording the target; this proves SmartDNS's group-to-proxy selection without
pretending to verify a real public proxy exit.


## Physical LAN acceptance capture (target Docker host)

The same-host network-namespace labs above are not physical LAN acceptance.
For a target deployment host, use the read-only capture helper and run the
client probe from an actual LAN device. The helper does not create networks,
change routes, touch firewall rules, restart containers, or publish ports.

On the Docker host (root required; `tcpdump`, `nsenter`, `timeout`, and
Docker CLI required):

```sh
sudo bash scripts/lab/smartdns-dns-ingress/physical-lan-capture.sh s5m-agent eth0 90
```

Replace `eth0` with the physical LAN interface that receives client traffic.
The script captures DNS ingress TCP/UDP port 6055 on that interface and inside
the Agent container network namespace. Capture files are created under
`/var/tmp` with directory mode 0700 and file mode 0600. The script is
read-only with respect to Docker, routes, firewall and service state.

On each physical client, run the probe directly against the Agent's routed
container ingress address (not the router's DNS forwarder):

```sh
python3 scripts/lab/smartdns-dns-ingress/physical-client-probe.py 172.31.0.10 example.com --transport udp --qtype A
python3 scripts/lab/smartdns-dns-ingress/physical-client-probe.py 172.31.0.10 example.com --transport tcp --qtype A
python3 scripts/lab/smartdns-dns-ingress/physical-client-probe.py 2001:db8:31::10 example.com --transport udp --qtype AAAA
python3 scripts/lab/smartdns-dns-ingress/physical-client-probe.py 2001:db8:31::10 example.com --transport tcp --qtype AAAA
```

The example addresses are documentation placeholders; replace them with the
actual routed ingress addresses. Run the IPv6 probes only when IPv6 routing
and an IPv6 ingress listener have been explicitly configured.

For each client, record the probe's `SOURCE_ADDR`, the packet source seen on
the host LAN capture, and the packet source seen inside the Agent namespace.
The latter must equal the real client address. Repeat with at least two
distinct client CIDRs, over UDP and TCP, and separately for IPv4 and IPv6.
A router DNS forwarder/cache is not an equivalent test because SmartDNS may
then see only the router address.

This is capture tooling only: it cannot turn the host attestation's
`source_ip_preserved` flag true, and a successful packet capture still does
not prove firewall persistence, SmartDNS client-group selection, or real
proxy CONNECT/public egress. Keep per-client mode fail-closed until the
complete evidence chain has been reviewed.
