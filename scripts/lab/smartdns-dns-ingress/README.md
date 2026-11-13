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


## Physical LAN source-IP acceptance

The same-host labs do not prove physical LAN routing. The following two-stage
acceptance proves that actual client packets traverse the host and reach the
Agent network namespace with the original source address. It does not require
SmartDNS to be listening yet, so it can be completed before enabling per-client
mode.

1. On the Docker host, start simultaneous captures (root required):

```sh
sudo bash scripts/lab/smartdns-dns-ingress/physical-lan-capture.sh s5m-agent eth0 90
```

Replace `eth0` with the physical LAN interface that receives client traffic.
The capture helper is read-only and captures both directions on port 6055 on
the physical interface and inside the Agent namespace. Files are stored with
directory mode 0700 and file mode 0600.

2. On each physical client, send both UDP and TCP probes to its family-matched
routed Agent ingress address. The probe sends a harmless UDP marker and a TCP
connection attempt; a refused TCP connection is acceptable because the goal
at this stage is to prove packet delivery, not resolver health.

```sh
python3 scripts/lab/smartdns-dns-ingress/physical-ingress-packet-probe.py 172.31.0.10 --result-file ./s5m-ingress-probes.jsonl
```

Run it from at least one actual client in every configured CIDR. For IPv6
CIDRs, use the actual routed IPv6 ingress address. Copy the JSONL result file
to the Docker host after the capture finishes.

3. On the Docker host, verify the paired pcaps and create the root-owned
physical evidence file:

```sh
sudo python3 scripts/lab/smartdns-dns-ingress/physical-ingress-verify.py \
  --config /etc/s5m-agent-ingress/config.json \
  --host-pcap /var/tmp/<capture-dir>/host-lan.pcap \
  --container-pcap /var/tmp/<capture-dir>/container-ingress.pcap \
  --probe-results ./s5m-ingress-probes.jsonl
```

The verifier requires each configured client CIDR to have both UDP and TCP
probe tuples present in both captures, with identical source/destination
addresses and source ports. It writes
`/etc/s5m-agent-ingress/physical-evidence.json` atomically, root-owned mode
0600, bound to the exact host config hash. Evidence expires after seven days
and is invalidated by any config change. Re-run it after changing router
routes, Docker networks, ingress addresses, or client CIDRs.

The host controller consumes only this verifier-generated evidence. Without
valid evidence, `source_ip_preserved`, `udp_ready`, and `tcp_ready` remain
false. This proves routed packet delivery/source preservation only; it does
not prove SmartDNS DNS answers or proxy egress.

4. After per-client mode is enabled, run the DNS probe from every physical
client for A/AAAA over UDP/TCP to verify actual resolver behavior:

```sh
python3 scripts/lab/smartdns-dns-ingress/physical-client-probe.py 172.31.0.10 example.com --transport udp --qtype A
python3 physical-client-probe.py 172.31.0.10 example.com --transport tcp --qtype A
python3 physical-client-probe.py 172.31.0.10 example.com --transport udp --qtype AAAA
python3 physical-client-probe.py 172.31.0.10 example.com --transport tcp --qtype AAAA
```

Repeat with the actual IPv6 ingress address and IPv6 client CIDRs. The
physical DNS probe must return RCODE=0. Separately verify the selected proxy's
real CONNECT and public egress IP; the local SOCKS observer lab is not proof
of public proxy egress.
