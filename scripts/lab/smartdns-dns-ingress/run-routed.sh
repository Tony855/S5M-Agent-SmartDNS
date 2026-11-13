#!/usr/bin/env bash
set -Eeuo pipefail
docker version
ROOT="$(cd "$(dirname "$0")" && pwd)"
SERVER=s5m-dns-routed-lab
NET_A=s5m-dns-routed-a
NET_B=s5m-dns-routed-b
NET_IN=s5m-dns-routed-ingress
BR_A=br-s5ma
BR_B=br-s5mb
cleanup() {
  docker rm -f "$SERVER" >/dev/null 2>&1 || true
  docker network rm "$NET_IN" "$NET_A" "$NET_B" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create --driver bridge --subnet 172.30.10.0/24 --gateway 172.30.10.1 \
  --opt "com.docker.network.bridge.name=$BR_A" \
  --opt com.docker.network.bridge.enable_ip_masquerade=false "$NET_A" >/dev/null
docker network create --driver bridge --subnet 172.30.20.0/24 --gateway 172.30.20.1 \
  --opt "com.docker.network.bridge.name=$BR_B" \
  --opt com.docker.network.bridge.enable_ip_masquerade=false "$NET_B" >/dev/null
docker network create --driver bridge --subnet 172.31.0.0/24 --gateway 172.31.0.1 \
  --opt com.docker.network.bridge.gateway_mode_ipv4=routed \
  --opt "com.docker.network.bridge.trusted_host_interfaces=$BR_A:$BR_B" \
  --opt com.docker.network.bridge.name=br-s5mi "$NET_IN" >/dev/null
docker run -d --name "$SERVER" --restart no --network "$NET_IN" --ip 172.31.0.10 \
  -p 0.0.0.0::6055/udp -p 0.0.0.0::6055/tcp \
  -v "$ROOT/server.py:/lab/server.py:ro" python:3.12-alpine python -u /lab/server.py >/dev/null
for _ in $(seq 1 30); do docker logs "$SERVER" 2>&1 | grep -q 'READY tcp' && break; sleep 1; done
docker logs "$SERVER" 2>&1 | grep -q 'READY tcp'
for spec in "$NET_A 172.30.10.10 172.30.10.1" "$NET_B 172.30.20.10 172.30.20.1"; do
  read -r network address gateway <<<"$spec"
  docker run --rm --cap-add NET_ADMIN --network "$network" --ip "$address" \
    -v "$ROOT/client.py:/lab/client.py:ro" python:3.12-alpine \
    sh -c "route add -net 172.31.0.0/24 gw $gateway && python /lab/client.py 172.31.0.10 6055"
done
logs="$(docker logs "$SERVER" 2>&1)"
printf '%s\n' "$logs"
for expected in 'OBSERVED udp 172.30.10.10:' 'OBSERVED tcp 172.30.10.10:' \
                'OBSERVED udp 172.30.20.10:' 'OBSERVED tcp 172.30.20.10:'; do
  grep -Fq "$expected" <<<"$logs" || { echo "FAIL: routed ingress did not preserve source: $expected" >&2; exit 1; }
done
echo "PASS: routed bridge direct path preserved both source IPs for UDP and TCP."
echo "LIMIT: same-host routed Docker test only; physical LAN/SmartDNS/proxy egress remain unverified."
