#!/usr/bin/env bash
set -Eeuxo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
[[ "$EUID" -eq 0 ]] || { echo "run with sudo/root" >&2; exit 1; }
for cmd in docker ip sysctl; do command -v "$cmd" >/dev/null || { echo "$cmd is required" >&2; exit 1; }; done
[[ -x "$ROOT/.runtime/smartdns" ]] || { echo "missing $ROOT/.runtime/smartdns; build the pinned SmartDNS builder first" >&2; exit 1; }
SERVER=s5m-smartdns-real-daemon-lab
NET_IN=s5m-smartdns-real-ingress
LAN_BR=br-s5m-lan
NS_A=s5m-smart-client-a
NS_B=s5m-smart-client-b
cleanup() {
  docker rm -f "$SERVER" >/dev/null 2>&1 || true
  docker network rm "$NET_IN" >/dev/null 2>&1 || true
  ip netns del "$NS_A" >/dev/null 2>&1 || true
  ip netns del "$NS_B" >/dev/null 2>&1 || true
  ip link del "$LAN_BR" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
ip link add "$LAN_BR" type bridge
ip addr add 192.168.50.1/24 dev "$LAN_BR"
ip link set "$LAN_BR" up
if [[ "$(sysctl -n net.ipv4.ip_forward)" != "1" ]]; then
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
fi
for spec in "$NS_A 192.168.50.10 vsa" "$NS_B 192.168.50.20 vsb"; do
  read -r ns address veth <<<"$spec"
  host_veth="${veth}-host"
  ip netns add "$ns"
  ip link add "$host_veth" type veth peer name eth0 netns "$ns"
  ip link set "$host_veth" master "$LAN_BR"
  ip link set "$host_veth" up
  ip -n "$ns" link set lo up
  ip -n "$ns" addr add "$address/24" dev eth0
  ip -n "$ns" link set eth0 up
  ip -n "$ns" route add 172.31.0.0/24 via 192.168.50.1
done
docker network create --driver bridge --subnet 172.31.0.0/24 --gateway 172.31.0.1 \
  --opt com.docker.network.bridge.gateway_mode_ipv4=routed \
  --opt "com.docker.network.bridge.trusted_host_interfaces=$LAN_BR" \
  --opt com.docker.network.bridge.name=br-s5m-real "$NET_IN" >/dev/null
docker run -d --name "$SERVER" --restart no --network "$NET_IN" --ip 172.31.0.10 \
  -p 0.0.0.0::6055/udp -p 0.0.0.0::6055/tcp \
  --cap-drop ALL --security-opt no-new-privileges:true s5m-smartdns-routed-lab >/dev/null
sleep 2
state="$(docker inspect -f '{{.State.Status}}' "$SERVER")"
if [[ "$state" != running ]]; then docker logs "$SERVER"; echo "SmartDNS daemon failed to start (state=$state)" >&2; exit 1; fi
for transport in udp tcp; do
  ip netns exec "$NS_A" python3 "$ROOT/client-query.py" 192.0.2.10 "$transport"
  ip netns exec "$NS_B" python3 "$ROOT/client-query.py" 192.0.2.20 "$transport"
done
echo "PASS: real SmartDNS daemon selected distinct CIDR groups over routed ingress for UDP and TCP."
echo "LIMIT: same-host IPv4 lab only; Agent validator/deployment, IPv6, Mihomo SOCKS and real proxy egress remain separate acceptance gates."
