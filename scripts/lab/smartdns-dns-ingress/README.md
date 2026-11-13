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

The real-daemon fixture also marks every mapped DoT server with
`-exclude-default-group` and sends a third query from an unmapped client CIDR.
The test requires that client to receive no A answer. This guards against
SmartDNS silently placing a per-client upstream back into the default group,
which would otherwise let unmapped clients use an arbitrary proxy exit.
