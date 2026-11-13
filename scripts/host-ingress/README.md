# S5M Agent host-side DNS ingress firewall controller

This is a **restricted firewall reconciler**, not a complete routed-Docker provisioner. It owns only the `inet s5m_agent_ingress` nftables table and never changes Docker networks, host routes, Docker bridge defaults, or proxy settings. Do not expose the Docker socket to the Agent container.

## Configuration

Create `/etc/s5m-agent-ingress/config.json` as root, mode `0600`:

```json
{
  "version": 1,
  "interface": "eth1",
  "ipv4_address": "172.31.10.2",
  "ipv6_address": "2001:db8:31::2",
  "client_cidrs": ["192.168.50.0/24", "2001:db8:50::/64"]
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

The service validates the full nftables transaction before applying it, serializes concurrent runs with `flock`, and atomically replaces only its dedicated nftables table. A 30-second systemd timer refreshes the attestation so stale data expires quickly if reconciliation stops. If nft validation/application fails, the previous nftables table is preserved by nftables transaction semantics.

## Deliberate fail-closed boundary

The generated attestation sets `firewall_ready=true` only after the owned allowlist table was applied. It sets `firewall_persistent=true` only when the systemd timer is both enabled and active; otherwise it remains false. It always sets `udp_ready=false`, `tcp_ready=false`, and `source_ip_preserved=false`. This component does not create/attach routed Docker networks, install router static routes, prove forwarding or socket reachability, or perform physical LAN source-IP capture. Therefore it cannot make the Master provisioning gate pass and cannot enable per-client SmartDNS by itself. Never edit the attestation manually to turn these flags on.

A separate routed-network lifecycle and real LAN UDP/TCP capture/verification are still required. In particular, `source_ip_preserved=true` requires a real client on the configured LAN and matching client source addresses in the Agent network namespace capture; local Docker simulations are not sufficient.


## Uninstall

```sh
sudo ./uninstall-host-controller.sh
```

The uninstall operation disables the refresh timer, removes the controller-owned attestation and nftables table, and removes the systemd units/binary. It deliberately retains the administrator configuration and does not touch Docker networks, host routes, or the default bridge.
