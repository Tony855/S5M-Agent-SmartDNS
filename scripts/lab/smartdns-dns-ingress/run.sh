#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
command -v docker >/dev/null
GW="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')"
[[ "$GW" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "Cannot determine Docker bridge gateway" >&2; exit 1; }
PORT="$(printenv DNS_INGRESS_PORT || echo 16055)"
SERVER=s5m-dns-ingress-lab
NET_A=s5m-dns-lab-a
NET_B=s5m-dns-lab-b
cleanup() { docker rm -f "$SERVER" >/dev/null 2>&1 || true; docker network rm "$NET_A" "$NET_B" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker network create --subnet 172.30.10.0/24 "$NET_A" >/dev/null
docker network create --subnet 172.30.20.0/24 "$NET_B" >/dev/null
docker run -d --name "$SERVER" --restart no -p "$GW:$PORT:6055/udp" -p "$GW:$PORT:6055/tcp" -v "$ROOT/server.py:/lab/server.py:ro" python:3.12-alpine python -u /lab/server.py >/dev/null
for _ in $(seq 1 30); do docker logs "$SERVER" 2>&1 | grep -q 'READY tcp' && break; sleep 1; done
docker logs "$SERVER" 2>&1 | grep -q 'READY tcp'
for spec in "$NET_A 172.30.10.10" "$NET_B 172.30.20.10"; do
  read -r network address <<<"$spec"
  docker run --rm --network "$network" --ip "$address" -v "$ROOT/client.py:/lab/client.py:ro" python:3.12-alpine python /lab/client.py "$GW" "$PORT"
done
logs="$(docker logs "$SERVER" 2>&1)"
printf '%s\n' "$logs"
for expected in "OBSERVED udp $GW:" "OBSERVED tcp $GW:"; do
  count="$(grep -Fc "$expected" <<<"$logs" || true)"
  [[ "$count" -eq 2 ]] || { echo "FAIL: expected Docker bridge gateway SNAT for both clients: $expected (count=$count)" >&2; exit 1; }
done
echo "CONFIRMED: Docker bridge-to-bridge published-port path rewrites both client source IPs to $GW."
echo "BLOCKER: this path cannot support SmartDNS group-match -client-ip per original client."
echo "LIMIT: real LAN-to-Agent ingress and SmartDNS/proxy egress still require a separate test."
