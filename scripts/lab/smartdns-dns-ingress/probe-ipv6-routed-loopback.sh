#!/usr/bin/env bash
set -Eeuo pipefail

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
if python3 - "$inspect" "$routes4" "$routes6" <<'PY'
import ipaddress, json, sys

container = json.loads(sys.argv[1])[0]
ports = container.get("NetworkSettings", {}).get("Ports") or {}
networks = container.get("NetworkSettings", {}).get("Networks") or {}
bridge = networks.get("bridge") or {}
gateway4 = bridge.get("Gateway", "")
gateway6 = bridge.get("IPv6Gateway", "")
routes4 = [line.strip() for line in sys.argv[2].splitlines() if line.strip()]
routes6 = [line.strip() for line in sys.argv[3].splitlines() if line.strip()]

def canonical(value):
    try:
        return ipaddress.ip_address(value).compressed
    except Exception:
        return value

safe = True
for proto in ("udp", "tcp"):
    entries = ports.get(f"6055/{proto}") or []
    actual = [(canonical(item.get("HostIp", "")), item.get("HostPort", "")) for item in entries]
    expected_hosts = {"127.0.0.1", "::1", "0.0.0.0", "::"}
    if len(actual) != 4 or {host for host, _ in actual} != expected_hosts:
        print(f"{proto}: unexpected published mappings: {actual}")
        safe = False
        continue
    for host, port in actual:
        if host in ("127.0.0.1", "::1"):
            if not port.isdigit() or not (1 <= int(port) <= 65535):
                print(f"{proto}: loopback mapping has no valid ephemeral host port: {(host, port)}")
                safe = False
        elif port != "":
            print(f"{proto}: non-loopback host binding is allocated: {(host, port)}")
            safe = False

if not gateway4 or len(routes4) != 1 or f"via {gateway4}" not in routes4[0]:
    print(f"IPv4 default route changed or ambiguous: gateway={gateway4!r}, routes={routes4}")
    safe = False
if not gateway6 or len(routes6) != 1 or f"via {gateway6}" not in routes6[0]:
    print(f"IPv6 default route changed or ambiguous: gateway={gateway6!r}, routes={routes6}")
    safe = False

print("6055 port mappings:", json.dumps(ports, sort_keys=True))
print("default bridge IPv4 gateway:", gateway4, "routes:", routes4)
print("default bridge IPv6 gateway:", gateway6, "routes:", routes6)
if not safe:
    print("PROBE_RESULT=UNSAFE")
    raise SystemExit(0)
print("PROBE_RESULT=SAFE_LOOPBACK_ONLY")
PY
then
  echo "IPv6 routed publication probe completed"
else
  echo "IPv6 routed publication probe parser failed"
  exit 1
fi
