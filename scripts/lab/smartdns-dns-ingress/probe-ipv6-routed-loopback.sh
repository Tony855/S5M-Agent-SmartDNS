#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# CI-only diagnostic: test whether Docker can publish a routed IPv6 container
# port while allocating any host-side ephemeral port on ::1 only. This script
# runs only from the GitHub Actions ingress lab; it must never be used as a
# production enablement switch or as physical-LAN source-IP evidence.

[[ "${EUID}" -eq 0 ]] || { echo "run with sudo/root" >&2; exit 1; }
for cmd in docker python3 systemctl; do
  command -v "$cmd" >/dev/null || { echo "SKIP: missing $cmd"; exit 0; }
done

DAEMON_JSON=/etc/docker/daemon.json
install -d -m 0755 /etc/docker
if ! python3 - "$DAEMON_JSON" <<'PY'
import json, os, pathlib, sys
path = pathlib.Path(sys.argv[1])
try:
    config = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
except Exception as exc:
    print(f"SKIP: cannot safely merge Docker daemon config: {exc}")
    raise SystemExit(1)
if not isinstance(config, dict):
    print("SKIP: Docker daemon config is not an object")
    raise SystemExit(1)
config["ipv6"] = True
config["fixed-cidr-v6"] = "fd00:172:17::/64"
config["ip6tables"] = True
tmp = path.with_suffix(".json.s5m-probe")
tmp.write_text(json.dumps(config, sort_keys=True) + "\n", encoding="utf-8")
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY
then
  echo "SKIP: unable to configure disposable CI Docker daemon for IPv6"
  exit 0
fi

if ! systemctl restart docker; then
  echo "SKIP: Docker daemon restart unavailable; IPv6 publication probe not run"
  exit 0
fi
ready=0
for _ in $(seq 1 45); do
  if docker info >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
if [[ "$ready" != "1" ]]; then
  echo "SKIP: Docker did not become ready after enabling default-bridge IPv6"
  exit 0
fi

NAME=s5m-ingress-ipv6-loopback-probe
NETWORK=s5m-ingress-ipv6-loopback-probe
cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

bridge_json="$(docker network inspect bridge 2>/dev/null || true)"
if ! python3 - "$bridge_json" <<'PY'
import json, sys
try:
    bridge = json.loads(sys.argv[1])[0]
    configs = bridge.get("IPAM", {}).get("Config") or []
    if not any(":" in str(item.get("Subnet", "")) and item.get("Gateway") for item in configs):
        raise ValueError("default bridge has no IPv6 subnet/gateway")
except Exception as exc:
    print(f"SKIP: {exc}")
    raise SystemExit(1)
PY
then
  echo "SKIP: default bridge IPv6 gateway is unavailable; cannot test egress preservation"
  exit 0
fi

if ! docker run -d --name "$NAME" --network bridge \
  -p "127.0.0.1::6055/udp" -p "127.0.0.1::6055/tcp" \
  -p "[::1]::6055/udp" -p "[::1]::6055/tcp" \
  alpine:3.24 sleep 3600 >/dev/null; then
  echo "UNSAFE/UNSUPPORTED: Docker cannot create IPv6 loopback-only ephemeral 6055 mappings"
  exit 0
fi

if ! docker network create --driver bridge --ipv6 \
  --subnet 172.31.252.0/24 --gateway 172.31.252.1 \
  --subnet fd00:172:252::/64 --gateway fd00:172:252::1 \
  --opt com.docker.network.bridge.gateway_mode_ipv4=routed \
  --opt com.docker.network.bridge.gateway_mode_ipv6=routed \
  --opt com.docker.network.bridge.trusted_host_interfaces=docker0 \
  "$NETWORK" >/dev/null; then
  echo "UNSAFE/UNSUPPORTED: Docker cannot create the dual-stack routed bridge probe network"
  exit 0
fi

if ! docker network connect --gw-priority -1 --ip 172.31.252.2 \
  --ip6 fd00:172:252::2 "$NETWORK" "$NAME"; then
  echo "UNSAFE/UNSUPPORTED: Docker cannot attach the dual-stack routed endpoint without changing its gateway policy"
  exit 0
fi

inspect="$(docker inspect "$NAME")"
routes4="$(docker exec "$NAME" ip -4 route show default 2>/dev/null || true)"
routes6="$(docker exec "$NAME" ip -6 route show default 2>/dev/null || true)"
if ! python3 "$ROOT/ipv6_routed_probe.py" "$inspect" "$routes4" "$routes6"; then
  echo "UNSAFE: Docker allocated a non-loopback host port or changed default egress; IPv6 per-client ingress must remain disabled." >&2
  exit 1
fi
echo "IPv6 routed publication probe completed"
