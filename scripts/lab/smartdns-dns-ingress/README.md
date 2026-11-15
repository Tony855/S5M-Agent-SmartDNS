# SmartDNS DNS ingress source-IP labs

The same-host labs do not prove physical LAN routing. The physical acceptance
procedure below is separate from the Docker namespace experiments.

## Current supported family

PR #242 currently provisions IPv4 per-client ingress only. Both deployers and
the host network lifecycle helper reject IPv6 per-client provisioning. Do not
add IPv6 client CIDRs to production host config, do not set
ENABLE_PER_CLIENT_INGRESS_IPV6=1, and do not treat an IPv6 namespace test as
production acceptance. The IPv6 packet parser/probe tooling is not an IPv6
deployment guarantee.

A CI-only diagnostic, probe-ipv6-routed-loopback.sh, tests whether a disposable
GitHub Actions Docker daemon can use an IPv6 loopback-only ephemeral host
mapping while retaining the default bridge IPv6 egress route. Even a
PROBE_RESULT=SAFE_LOOPBACK_ONLY result would prove only that runner's Docker
publication mechanics; it would not enable production IPv6. The deployer,
network lifecycle, firewall, Agent, Server and real-LAN IPv6 acceptance gates
must all be implemented and rerun first.

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
   interface and time window. The verifier requires the configured host
   interface to match the manifest.

2. On at least one actual client in every configured IPv4 CIDR, send both UDP
   and TCP packet probes to the fixed IPv4 routed Agent ingress address:

   python3 scripts/lab/smartdns-dns-ingress/physical-ingress-packet-probe.py 172.31.10.2 --result-file ./s5m-ingress-probes.jsonl

   A refused TCP connection is acceptable at this stage because the goal is
   packet delivery/source preservation, not resolver health. Copy the JSONL
   results to the Docker host after capture finishes.

3. On the Docker host, verify the paired pcaps and create signed root-owned
   physical evidence:

   sudo python3 scripts/lab/smartdns-dns-ingress/physical-ingress-verify.py --config /etc/s5m-agent-ingress/config.json --host-pcap /var/tmp/<capture-dir>/host-lan.pcap --container-pcap /var/tmp/<capture-dir>/container-ingress.pcap --probe-results ./s5m-ingress-probes.jsonl

   Every configured IPv4 CIDR must have both UDP and TCP tuples in both pcaps,
   with identical source/destination addresses and ports. The verifier writes
   physical-evidence.json atomically, root-owned mode 0600, bound to the exact
   host config hash, container ID and routed network ID. Evidence expires after
   seven days and is invalidated by config/container/network changes.

4. After the full Master/Agent readiness gate permits per-client runtime, run
   A and AAAA DNS queries over UDP and TCP from every physical client. Confirm
   SmartDNS receives the actual client source IP, selects only the mapped
   group/listener, and unmapped clients fail closed.

Separately run the real proxy egress verifier against each configured Mihomo
listener and expected public egress IP. Correlate that with the actual SmartDNS
DoT query path; a local SOCKS observer or direct CONNECT test alone does not
prove the complete client-CIDR-to-public-egress chain.

## Field acceptance that remains mandatory

- Actual LAN router static route to the Docker ingress subnet through the
  Docker host's trusted LAN address.
- Physical IPv4 UDP/TCP source preservation for every configured client CIDR.
- SmartDNS A/AAAA UDP/TCP group selection from real clients.
- Real proxy CONNECT, DoT upstream and externally observed egress IP per proxy.
- Host reboot, Agent reconnect, Master restart, SmartDNS enable/disable and
  interrupted-transaction rollback.
- A separate safe IPv6 routed publication design plus physical IPv6 UDP/TCP
  source-preservation acceptance before IPv6 can be enabled.

No item above is considered passed merely because the corresponding
same-host GitHub Actions lab is green.
