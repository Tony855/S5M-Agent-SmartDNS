#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
[[ "${EUID}" -eq 0 ]] || { echo "run with sudo/root" >&2; exit 1; }
command -v docker >/dev/null
command -v ip >/dev/null
IPV6="${S5M_TEST_IPV6:-0}"
[[ "$IPV6" == "0" || "$IPV6" == "1" ]] || { echo "S5M_TEST_IPV6 must be 0 or 1" >&2; exit 1; }
NAME=s5m-ingress-lifecycle-ci
NETWORK=s5m-ingress-lifecycle-ci
TMP="$(mktemp -d /run/s5m-ingress-lifecycle.XXXXXX)"
cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT
cleanup
mkdir -m 0700 "$TMP"
if [[ "$IPV6" == "1" ]]; then
  docker network inspect bridge | python3 -c 'import json,sys; c=json.load(sys.stdin)[0]["IPAM"]["Config"]; assert any(":" in x.get("Subnet","") and x.get("Gateway") for x in c), "default bridge must have IPv6 gateway"'
  ip -6 addr show dev docker0 scope global | grep -q 'inet6 ' || { echo "default bridge host interface lacks a global IPv6 address" >&2; exit 1; }
  docker run -d --name "$NAME" --network bridge \
    -p "127.0.0.1::6055/udp" -p "127.0.0.1::6055/tcp" \
    -p "[::1]::6055/udp" -p "[::1]::6055/tcp" \
    alpine:3.24 sleep 3600 >/dev/null
else
  docker run -d --name "$NAME" --network bridge \
    -p "127.0.0.1::6055/udp" -p "127.0.0.1::6055/tcp" \
    alpine:3.24 sleep 3600 >/dev/null
fi
IFACE=docker0
ip link show dev "$IFACE" >/dev/null
docker inspect --format '{{json .NetworkSettings.Ports}}' "$NAME"
python3 - "$TMP/network.json" "$IPV6" <<'PY'
import json, sys
ipv6 = sys.argv[2] == "1"
config = {
    "version": 1,
    "network": "s5m-ingress-lifecycle-ci",
    "container": "s5m-ingress-lifecycle-ci",
    "interface": "docker0",
    "ipv4_subnet": "172.31.250.0/24",
    "ipv4_gateway": "172.31.250.1",
    "ipv4_address": "172.31.250.2",
    "ipv6_subnet": "fd00:172:250::/64" if ipv6 else None,
    "ipv6_gateway": "fd00:172:250::1" if ipv6 else None,
    "ipv6_address": "fd00:172:250::2" if ipv6 else None,
    "client_cidrs": ["192.168.50.0/24"] + (["fd00:192:168:50::/64"] if ipv6 else []),
}
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump(config, stream)
PY
python3 - "$TMP/firewall.json" "$IPV6" <<'PY'
import json, sys
ipv6 = sys.argv[2] == "1"
config = {
    "version": 1,
    "interface": "docker0",
    "ipv4_address": "172.31.250.2",
    "ipv6_address": "fd00:172:250::2" if ipv6 else None,
    "client_cidrs": ["192.168.50.0/24"] + (["fd00:192:168:50::/64"] if ipv6 else []),
}
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump(config, stream)
PY
chmod 0600 "$TMP/network.json" "$TMP/firewall.json"
# Verify the live firewall contract before attaching the routed network.
# Only the read-only nftables/systemd probes are mocked; Docker and iproute2
# lifecycle operations below still execute against the real CI host.
mkdir -m 0700 "$TMP/mock-bin"
python3 "$ROOT/scripts/host-ingress/controller.py" render --config "$TMP/firewall.json" >"$TMP/live-nft.txt"
python3 - "$TMP/firewall.json" "$TMP/attestation.json" <<'PY'
import json, sys, time
with open(sys.argv[1], encoding="utf-8") as stream:
    config = json.load(stream)
attestation = {
    "version": 1, "updated_at": int(time.time()), "interface": config["interface"],
    "ipv4_address": config["ipv4_address"], "ipv6_address": config["ipv6_address"],
    "client_cidrs": sorted(config["client_cidrs"]),
    "source_ip_preserved": False, "firewall_ready": True,
    "firewall_persistent": True, "udp_ready": False, "tcp_ready": False,
}
with open(sys.argv[2], "w", encoding="utf-8") as stream:
    json.dump(attestation, stream)
PY
chmod 0600 "$TMP/attestation.json"
cat >"$TMP/mock-bin/nft" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "$#" -eq 4 && "$1" == "list" && "$2" == "table" && "$3" == "inet" && "$4" == "s5m_agent_ingress" ]]; then
  cat "$S5M_TEST_NFT_OUTPUT"
  exit 0
fi
exit 1
SH
cat >"$TMP/mock-bin/systemctl" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "$1" == "is-enabled" ]]; then printf 'enabled\n'; exit 0; fi
if [[ "$1" == "is-active" ]]; then exit 0; fi
exit 1
SH
chmod 0755 "$TMP/mock-bin/nft" "$TMP/mock-bin/systemctl"
export S5M_TEST_NFT_OUTPUT="$TMP/live-nft.txt"
export S5M_INGRESS_ATTESTATION="$TMP/attestation.json"
export PATH="$TMP/mock-bin:$PATH"
python3 "$ROOT/scripts/host-ingress/network-lifecycle.py" provision --config "$TMP/network.json" --firewall-config "$TMP/firewall.json"
# Reconcile twice: the second run must not duplicate or re-address the endpoint.
python3 "$ROOT/scripts/host-ingress/network-lifecycle.py" provision --config "$TMP/network.json" --firewall-config "$TMP/firewall.json"
container_inspect="$(docker inspect "$NAME")"
python3 - "$IPV6" "$container_inspect" <<'PY'
import json, sys
ipv6 = sys.argv[1] == "1"
networks = json.loads(sys.argv[2])[0]["NetworkSettings"]["Networks"]
assert "bridge" in networks and "s5m-ingress-lifecycle-ci" in networks
ingress = networks["s5m-ingress-lifecycle-ci"]
assert ingress["IPAddress"] == "172.31.250.2"
if ipv6:
    assert ingress["GlobalIPv6Address"] == "fd00:172:250::2"
PY
ROUTE4="$(docker exec "$NAME" ip -4 route show default)"
BRIDGE_GW4="$(docker inspect -f '{{.NetworkSettings.Networks.bridge.Gateway}}' "$NAME")"
[[ "$ROUTE4" == *"via $BRIDGE_GW4"* ]] || { echo "default IPv4 route changed: $ROUTE4 expected via $BRIDGE_GW4" >&2; exit 1; }
if [[ "$IPV6" == "1" ]]; then
  ROUTE6="$(docker exec "$NAME" ip -6 route show default)"
  BRIDGE_GW6="$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPv6Gateway}}' "$NAME")"
  [[ "$ROUTE6" == *"via $BRIDGE_GW6"* ]] || { echo "default IPv6 route changed: $ROUTE6 expected via $BRIDGE_GW6" >&2; exit 1; }
fi
# Cleanup must still work if the firewall CIDR contract has since changed.
python3 - "$TMP/firewall.json" <<'PY'
import json, os, sys
path=sys.argv[1]
with open(path,encoding="utf-8") as f: data=json.load(f)
data["client_cidrs"]=["192.168.51.0/24"]
with open(path,"w",encoding="utf-8") as f: json.dump(data,f)
os.chmod(path,0o600)
PY
python3 "$ROOT/scripts/host-ingress/network-lifecycle.py" uninstall --config "$TMP/network.json"
docker inspect "$NAME" | python3 -c 'import json,sys; n=json.load(sys.stdin)[0]["NetworkSettings"]["Networks"]; assert "bridge" in n and "s5m-ingress-lifecycle-ci" not in n'
if [[ "$IPV6" == "1" ]]; then
  echo "PASS: dual-stack routed network lifecycle create/reconcile/uninstall preserves IPv4 and IPv6 default bridge egress"
else
  echo "PASS: IPv4 routed network lifecycle create/reconcile/uninstall preserves default bridge egress"
fi
