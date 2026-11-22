# SmartDNS DNS ingress source-IP labs

The same-host labs do not prove physical LAN routing. The physical acceptance
procedure below is separate from the Docker namespace experiments.

## Current supported family

IPv4 routed ingress is the default per-client deployment path. IPv6 routed
ingress is an explicit opt-in (`ENABLE_PER_CLIENT_INGRESS_IPV6=1`) and remains
**experimental / not production-accepted** until physical LAN/router IPv6
UDP/TCP source preservation is recorded. Do not leave IPv6 enabled in
production based only on CI.

The IPv6 deployer preflight requires an IPv6-enabled Docker default bridge,
a global IPv6 address on the trusted host interface, and exact loopback-only
host mappings. After routed attach, the lifecycle helper requires the
non-loopback `::` mapping to have an empty HostPort and verifies that the
container retains its default IPv6 egress route. Any allocated non-loopback
host port is rejected. The CI-only `probe-ipv6-routed-loopback.sh` now fails
the workflow if Docker reports an unsafe mapping or a changed default route;
unsupported Docker prerequisites are reported as a skip. The latest observed
GitHub-hosted Docker run reported `PROBE_RESULT=SAFE_LOOPBACK_ONLY` and the
dual-stack lifecycle integration passed. This proves only that runner's Docker
publication/lifecycle behavior, not a physical router, LAN packet path,
SmartDNS group selection, proxy CONNECT, DoT, or public egress.

Use IPv6 opt-in only for a controlled field-acceptance run. Before production
enablement, capture real IPv6 client packets on the trusted LAN interface and
inside the Agent namespace, verify exact source-address preservation for both
UDP and TCP in every configured IPv6 CIDR, and complete the SmartDNS/proxy
acceptance steps below. If the Docker probe or runtime mapping validation
fails, keep IPv6 ingress disabled.

## Physical LAN source-IP acceptance

The same-host labs do not prove physical LAN routing. The following stages
prove that actual IPv4 client packets traverse the host and reach the Agent
network namespace with the original source address. This stage can be completed
before enabling SmartDNS per-client mode.

1. On the Docker host, start simultaneous captures as root:

   sudo bash scripts/lab/smartdns-dns-ingress/physical-lan-capture.sh s5m-agent eth0 90

   Replace eth0 with the physical LAN interface that receives client traffic.
   The helper captures port 6055 on the physical interface and inside the Agent
   namespace. Its root-owned capture manifest records container identity,
   interface, stable global host-interface addresses, container PID plus Docker StartedAt runtime identity and time window (capture manifest v4). The
   capture helper rejects address changes during the capture; the verifier
   compares the exact stable address set with the live NIC before signing. A
   changed host next-hop address invalidates old physical evidence.

2. On at least one actual client in every configured IPv4 or IPv6 CIDR, send both UDP
   and TCP packet probes to that family's fixed routed Agent ingress address:

   python3 scripts/lab/smartdns-dns-ingress/physical-ingress-packet-probe.py 172.31.10.2 --result-file ./s5m-ingress-probes.jsonl

   For an IPv6 client, use the routed IPv6 ingress address in the same command,
   for example `python3 scripts/lab/smartdns-dns-ingress/physical-ingress-packet-probe.py 2001:db8:31::2 --result-file ./s5m-ingress-probes.jsonl`.

   A refused TCP connection is acceptable at this stage because the goal is
   packet delivery/source preservation, not resolver health. Copy the JSONL
   results to the Docker host after capture finishes.

3. On the Docker host, verify the paired pcaps and create signed root-owned
   physical evidence:

   sudo python3 scripts/lab/smartdns-dns-ingress/physical-ingress-verify.py --config /etc/s5m-agent-ingress/config.json --host-pcap /var/tmp/<capture-dir>/host-lan.pcap --container-pcap /var/tmp/<capture-dir>/container-ingress.pcap --probe-results ./s5m-ingress-probes.jsonl

   Every configured IPv4 and IPv6 CIDR must have both UDP and TCP tuples in both pcaps,
   with identical source/destination addresses and ports. The verifier writes
   physical-evidence.json atomically, root-owned mode 0600, bound to the exact
   version-4 evidence binds the host config hash, stable host-interface address set, host interface ifindex/MAC, immutable container ID, runtime PID and Docker StartedAt, plus the routed
   network ID. Evidence expires after seven days and is invalidated by
   config/host-address/container/network changes. Temporary, tentative,
   deprecated and DAD-failed NIC addresses are excluded from the route/evidence
   snapshot so privacy-address rotation cannot silently change the router next hop.

4. After the full Master/Agent readiness gate permits per-client runtime, run
   unique, uncached A and AAAA DNS names over UDP and TCP from every physical
   client. Use `physical-client-probe.py <ingress-ip> <unique-test-name> --transport udp|tcp --qtype A|AAAA`.
   Confirm SmartDNS receives the actual client source IP, selects only the
   mapped group/listener, completes the configured DoT upstream query, and
   makes unmapped clients fail closed.

5. Run the real proxy egress verifier against every configured Mihomo listener
   with the expected public egress IP, for example
   `sudo bash scripts/lab/smartdns-dns-ingress/physical-proxy-egress-verify.sh s5m-agent --expect 16000=<expected-public-ip>`.
   Correlate the successful SOCKS CONNECT/public egress result with the
   uncached SmartDNS A/AAAA query and the corresponding SmartDNS/Mihomo logs.
   The direct CONNECT probe alone does not prove SmartDNS used that listener
   for DoT; the end-to-end client query and DoT verification must also pass.

## Field acceptance that remains mandatory

- Actual LAN router static route to the Docker ingress subnet through the
  Docker host's trusted LAN address.
- Physical IPv4 and IPv6 UDP/TCP source preservation for every configured client CIDR.
- SmartDNS A/AAAA UDP/TCP group selection from real clients.
- Real proxy CONNECT, DoT upstream and externally observed egress IP per proxy.
- Host reboot, Agent reconnect, Master restart, SmartDNS enable/disable and
  interrupted-transaction rollback.
- Physical IPv6 router static-route and UDP/TCP source-preservation acceptance
  before IPv6 can be enabled for production.

No item above is considered passed merely because the corresponding
same-host GitHub Actions lab is green.
