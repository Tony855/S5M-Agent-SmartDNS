# S5M Agent host-side DNS ingress firewall controller

This is a **restricted firewall reconciler**, not a complete routed-Docker provisioner. It owns only the `inet s5m_agent_ingress` nftables table and never changes Docker networks, host routes, Docker bridge defaults, or proxy settings. Do not expose the Docker socket to the Agent container.

## Host prerequisites

Linux Docker host with the bridge network driver, Docker Engine/CLI supporting routed bridge gateway mode, `trusted_host_interfaces`, and `docker network connect --gw-priority`; Python 3, systemd, nftables (`nft`), iproute2 (`ip`, `nsenter`), util-linux (`flock`), and Docker CLI/Engine are required for provisioning. Physical capture additionally requires `tcpdump`; the real proxy egress probe requires `curl`. On Debian/Ubuntu, the host-side packages are typically `nftables iproute2 util-linux python3 tcpdump curl` (install Docker Engine separately). The installer checks the firewall-controller dependencies before writing units. The network lifecycle helper checks Docker gateway-priority support and the trusted host interface before creating or attaching a network. No packages are installed automatically.

## Configuration

Create `/etc/s5m-agent-ingress/config.json` as root, mode `0600`:

```json
{
  "version": 1,
  "interface": "eth1",
  "ipv4_address": "172.31.10.2",
  "ipv6_address": null,
  "client_cidrs": ["192.168.50.0/24"]
}
```

Use the actual physical ingress interface and the Agent's dedicated routed-network addresses. Addresses and CIDRs must be canonical, unicast, non-overlapping, and address-family compatible. The controller rejects unknown JSON keys, unsafe file ownership/mode, symlinks, and noncanonical networks.

## Install and operate

```sh
sudo install -d -o root -g root -m 0700 /etc/s5m-agent-ingress
sudo install -o root -g root -m 0600 config.json /etc/s5m-agent-ingress/config.json
sudo ./install-host-controller.sh
sudo systemctl status s5m-agent-ingress.timer
sudo journalctl -u s5m-agent-ingress.service
```

The service invalidates the previous readiness attestation before every reconciliation, then validates the full nftables transaction, serializes concurrent runs with `flock`, and atomically replaces only its dedicated nftables table. If config/interface/ownership validation, nft check/apply, or the final attestation write fails, readiness stays absent instead of leaving a stale success proof. A 30-second systemd timer refreshes the attestation so stale data expires quickly if reconciliation stops. If nft validation/application fails, the previous nftables table is preserved by nftables transaction semantics.

## Deliberate fail-closed boundary

The installer creates a per-host 32-byte HMAC key at `/etc/s5m-agent-ingress/evidence.key` (root-owned mode 0600); upgrades retain the existing key and reject unsafe key files. After upgrading from an unsigned-evidence build, rerun the physical verifier once to replace the old evidence with a signed record. The generated attestation sets `firewall_ready=true` only after the owned allowlist table was applied. It sets `firewall_persistent=true` only when the systemd timer is both enabled and active; otherwise it remains false. It sets `udp_ready`, `tcp_ready`, and `source_ip_preserved` true only when `/etc/s5m-agent-ingress/physical-evidence.json` is root-owned mode 0600, fresh (maximum age seven days), matches the exact config SHA256, and carries a valid HMAC from that host key. The verifier signs only after correlating paired physical host/Agent namespace captures for every configured client CIDR and checking the capture manifest interface/window, immutable Agent container ID, and immutable routed Docker network ID. The host controller re-inspects that exact owned bridge on every reconcile and invalidates source-IP evidence if the network is recreated, loses routed gateway mode, changes its trusted interface, or no longer carries the configured ingress address. The controller verifies the HMAC before trusting any evidence field; unsigned or hand-edited boolean claims fail closed. Generate evidence only with `scripts/lab/smartdns-dns-ingress/physical-ingress-verify.py`; never copy the key/evidence between hosts or edit evidence manually. This controller still does not create/attach routed Docker networks or install router static routes.

A separate routed-network lifecycle and external router static routes are still required. Physical evidence must come from actual LAN clients, with identical UDP/TCP source tuples observed on the host LAN interface and inside the Agent namespace; local Docker simulations are not sufficient. After enabling per-client mode, separately run the DNS A/AAAA UDP/TCP probe and real proxy CONNECT/public-egress acceptance.


## Uninstall

```sh
sudo ./uninstall-host-controller.sh
```

The uninstall script removes the dedicated routed Docker endpoint/network **before** disabling the firewall timer or deleting the nftables table. It uses the saved network config and the restricted lifecycle helper; if the helper/config is missing, Docker cannot be inspected, or unexpected containers are attached, it aborts and leaves the firewall in place. Only after the routed network is gone does it remove the controller-owned attestation/table and systemd units. It retains administrator config, host routes and router routes; remove any RouterOS static route separately. It does not touch the default bridge.

## Routed Docker ingress network lifecycle

The separate `network-lifecycle.py` helper provisions only the dedicated Docker bridge. It runs on the Docker host as root; it is never mounted into the Agent and never uses Docker socket access from inside the Agent.

Create `/etc/s5m-agent-ingress/network.json` as root-owned mode `0600` (replace the documentation-only addresses with the actual non-overlapping LAN plan):

```json
{
  "version": 1,
  "network": "s5m-agent-ingress",
  "container": "s5m-agent",
  "interface": "eth1",
  "ipv4_subnet": "172.31.10.0/24",
  "ipv4_gateway": "172.31.10.1",
  "ipv4_address": "172.31.10.2",
  "ipv6_subnet": null,
  "ipv6_gateway": null,
  "ipv6_address": null,
  "client_cidrs": ["192.168.50.0/24"]
}
```

Before provisioning, deploy/redeploy the Agent with `ENABLE_PER_CLIENT_INGRESS=1` in `/etc/default/s5m-agent-smartdns`. The interactive `deploy-s5m-agent.sh` offers menu item `22` to toggle the same option; save it with `19` and redeploy with `2`. The deployment script publishes UDP/TCP 6055 only on random host ports bound to `127.0.0.1`; remote clients never use those host ports and reach the stable container address directly through the routed bridge. This loopback-only mapping is required because Docker routed gateway mode filters ingress to published container ports. The lifecycle helper refuses containers whose 6055 mappings are missing or whose non-loopback mapping allocates a host port. After attach it accepts Docker's routed-only `0.0.0.0` mapping only when `HostPort` is empty. IPv6 per-client ingress is currently disabled. Validation showed that Docker allocates a non-loopback IPv6 host port for the `[::]::6055` mapping even when the default bridge IPv6 switch is off. Both deploy scripts and the network helper now fail closed for IPv6; do not set `ENABLE_PER_CLIENT_INGRESS_IPV6=1`. A separate IPv6 ingress design is required before re-enabling it.

After both host configs exist and the helper is installed, both `deploy-agent.sh` and `deploy-s5m-agent.sh` automatically attempt `provision` after a successful redeploy (after removing the old container so its static IP is free). If that step warns/fails, shared SmartDNS remains available and per-client remains fail-closed; fix the host config and retry manually.

Install the helper and provision after the Agent container is running:

```sh
sudo install -o root -g root -m 0600 network.json /etc/s5m-agent-ingress/network.json
sudo /usr/local/libexec/s5m-agent-ingress/network-lifecycle.py provision --config /etc/s5m-agent-ingress/network.json --firewall-config /etc/s5m-agent-ingress/config.json
```

Before touching Docker, it first acquires the same host lock used by the firewall controller and invokes its read-only `verify` operation. Provisioning is refused unless the physical ingress interface is currently up, the live nftables table exactly matches the source-CIDR allowlist, the systemd refresh timer is enabled and active, and a fresh root-owned attestation matches the exact interface/address/CIDR contract. This preflight proves firewall readiness only; it does not require or fabricate physical source-IP evidence. The lock is held through network attach and route verification so controller removal/reconcile cannot race the provision operation. It then creates a labeled, dedicated bridge in routed gateway mode, restricts direct routing to the configured trusted host interface, attaches the Agent with fixed addresses and gateway priority `-1`, then checks that the normal Docker `bridge` network and its default IPv4 egress gateway remain in place. Docker CLI versions without `network connect --gw-priority` are rejected before any network mutation. If attach or post-attach checks fail, a newly attached interface and newly created network are rolled back. Existing same-name networks are never adopted unless their ownership label, subnets, gateways and routed-mode options match exactly.

Configure a static route on the upstream LAN router to the **Docker ingress subnet** via the Docker host's address on the trusted interface (not a route to the client CIDR). The helper prints both a generic route and a RouterOS v7 command, for example `/ip route add dst-address=172.31.10.0/24 gateway=192.168.1.2 comment="S5M-Agent DNS ingress"`. This helper deliberately does not SSH into or modify routers and does not install host routes. The physical LAN packet-capture verifier remains mandatory before the attestation can claim source preservation.

To remove only the dedicated network, first stop the Agent or ensure no other containers are attached, then run:

```sh
sudo /usr/local/libexec/s5m-agent-ingress/network-lifecycle.py uninstall --config /etc/s5m-agent-ingress/network.json
```

IPv6 provisioning is currently rejected before any Docker mutation because the tested Docker dual-network publication allocates a non-loopback IPv6 host port. Cleanup does not depend on the current firewall config, so it remains possible after firewall CIDRs are changed; it still requires the saved network config to match the exact owned Docker network. Docker gateway mode behavior is documented at <https://docs.docker.com/engine/network/port-publishing/>: routed networks still enforce published-container-port filtering, while the host port is unused on the routed endpoint. The helper refuses to remove a network not carrying its ownership label or one with unexpected attached containers. It does not touch the default Docker bridge.
