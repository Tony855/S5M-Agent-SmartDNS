#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
[[ "$EUID" -eq 0 ]] || { echo "run with sudo/root" >&2; exit 1; }
for cmd in docker ip sysctl python3; do command -v "$cmd" >/dev/null || { echo "$cmd is required" >&2; exit 1; }; done
SERVER=s5m-dns-routed-lab
NET_IN=s5m-dns-routed-ingress
LAN_BR=br-lab-lan
NS_A=s5m-lan-client-a
NS_B=s5m-lan-client-b
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
sysctl -w net.ipv4.ip_forward=1 >/dev/null
for spec in "$NS_A 192.168.50.10 veth-a" "$NS_B 192.168.50.20 veth-b"; do
  read -r ns address veth <<<"$spec"
  veth_host="$veth-host"
  ip netns add "$ns"
  ip link add "$veth_host" type veth peer name eth0 netns "$ns"
  ip link set "$veth_host" master "$LAN_BR"
  ip link set "$veth_host" up
  ip -n "$ns" link set lo up
  ip -n "$ns" addr add "$address/24" dev eth0
  ip -n "$ns" link set eth0 up
  ip -n "$ns" route add 172.31.0.0/24 via 192.168.50.1
done
docker network create --driver bridge --subnet 172.31.0.0/24 --gateway 172.31.0.1 \
  --opt com.docker.network.bridge.gateway_mode_ipv4=routed \
  --opt "com.docker.network.bridge.trusted_host_interfaces=$LAN_BR" \
  --opt com.docker.network.bridge.name=br-s5mi "$NET_IN" >/dev/null
docker run -d --name "$SERVER" --restart no --network "$NET_IN" --ip 172.31.0.10 \
  -p 0.0.0.0::6055/udp -p 0.0.0.0::6055/tcp \
  -v "$ROOT/server.py:/lab/server.py:ro" python:3.12-alpine python -u /lab/server.py >/dev/null
for _ in $(seq 1 30); do docker logs "$SERVER" 2>&1 | grep -q 'READY tcp' && break; sleep 1; done
docker logs "$SERVER" 2>&1 | grep -q 'READY tcp'
ip netns exec "$NS_A" python3 "$ROOT/client.py" 172.31.0.10 6055
ip netns exec "$NS_B" python3 "$ROOT/client.py" 172.31.0.10 6055
logs="$(docker logs "$SERVER" 2>&1)"
printf '%s\n' "$logs"
for expected in 'OBSERVED udp 192.168.50.10:' 'OBSERVED tcp 192.168.50.10:' \
                'OBSERVED udp 192.168.50.20:' 'OBSERVED tcp 192.168.50.20:'; do
  grep -Fq "$expected" <<<"$logs" || { echo "FAIL: routed ingress did not preserve LAN source: $expected" >&2; exit 1; }
done
echo "PASS: routed bridge direct ingress preserved both simulated LAN client IPs for UDP and TCP."
echo "LIMIT: same-host Linux routed-lab only; physical LAN/SmartDNS/proxy egress remain unverified."
