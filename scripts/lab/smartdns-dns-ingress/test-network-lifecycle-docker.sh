#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
[[ "${EUID}" -eq 0 ]] || { echo "run with sudo/root" >&2; exit 1; }
command -v docker >/dev/null
command -v ip >/dev/null
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
docker run -d --name "$NAME" --network bridge alpine:3.24 sleep 3600 >/dev/null
IFACE=docker0
ip link show dev "$IFACE" >/dev/null
cat >"$TMP/network.json" <<EOF
{
  "version": 1,
  "network": "$NETWORK",
  "container": "$NAME",
  "interface": "$IFACE",
  "ipv4_subnet": "172.31.250.0/24",
  "ipv4_gateway": "172.31.250.1",
  "ipv4_address": "172.31.250.2",
  "ipv6_subnet": null,
  "ipv6_gateway": null,
  "ipv6_address": null,
  "client_cidrs": ["192.168.50.0/24"]
}
EOF
cat >"$TMP/firewall.json" <<'EOF'
{
  "version": 1,
  "interface": "docker0",
  "ipv4_address": "172.31.250.2",
  "ipv6_address": null,
  "client_cidrs": ["192.168.50.0/24"]
}
EOF
chmod 0600 "$TMP/network.json" "$TMP/firewall.json"
python3 "$ROOT/scripts/host-ingress/network-lifecycle.py" provision --config "$TMP/network.json" --firewall-config "$TMP/firewall.json"
# Reconcile twice: the second run must not duplicate or re-address the endpoint.
python3 "$ROOT/scripts/host-ingress/network-lifecycle.py" provision --config "$TMP/network.json" --firewall-config "$TMP/firewall.json"
docker inspect "$NAME" | python3 -c 'import json,sys; n=json.load(sys.stdin)[0]["NetworkSettings"]["Networks"]; assert "bridge" in n and "s5m-ingress-lifecycle-ci" in n; assert n["s5m-ingress-lifecycle-ci"]["IPAddress"]=="172.31.250.2"'
ROUTE="$(docker exec "$NAME" ip -4 route show default)"
BRIDGE_GW="$(docker inspect -f '{{.NetworkSettings.Networks.bridge.Gateway}}' "$NAME")"
[[ "$ROUTE" == *"via $BRIDGE_GW"* ]] || { echo "default bridge route changed: $ROUTE expected via $BRIDGE_GW" >&2; exit 1; }
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
echo "PASS: routed network lifecycle create/reconcile/uninstall preserves default bridge egress"
