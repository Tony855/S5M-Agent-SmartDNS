#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
command -v docker >/dev/null
docker compose version >/dev/null 2>&1
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
for expected in 'OBSERVED udp 172.30.10.10:' 'OBSERVED tcp 172.30.10.10:' 'OBSERVED udp 172.30.20.10:' 'OBSERVED tcp 172.30.20.10:'; do
  grep -Fq "$expected" <<<"$logs" || { echo "FAIL: source address not preserved: $expected" >&2; exit 1; }
done
echo "PASS: Docker published UDP/TCP ingress preserved both client source IPs."
echo "LIMIT: this test does not validate SmartDNS or proxy egress."
