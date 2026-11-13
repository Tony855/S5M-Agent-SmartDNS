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
NS_C=s5m-smart-client-c
PROXY_A=s5m-smart-socks-a
PROXY_B=s5m-smart-socks-b
LOG_DIR=""
cleanup() {
  docker rm -f "$PROXY_A" "$PROXY_B" "$SERVER" >/dev/null 2>&1 || true
  [[ -z "$LOG_DIR" ]] || rm -rf "$LOG_DIR"
  docker network rm "$NET_IN" >/dev/null 2>&1 || true
  ip netns del "$NS_A" >/dev/null 2>&1 || true
  ip netns del "$NS_B" >/dev/null 2>&1 || true
  ip netns del "$NS_C" >/dev/null 2>&1 || true
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
for spec in "$NS_A 192.168.50.10 vsa" "$NS_B 192.168.50.20 vsb" "$NS_C 192.168.50.30 vsc"; do
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
# Keep the ordinary Docker bridge as the default egress network. Attach the
# routed LAN-ingress network before start so SmartDNS can bind its static IP
# without changing the container's default route.
docker create --name "$SERVER" --restart no --network bridge \
  -p 127.0.0.1::6055/udp -p 127.0.0.1::6055/tcp \
  --cap-drop ALL --security-opt no-new-privileges:true s5m-smartdns-routed-lab >/dev/null
docker network connect --ip 172.31.0.10 "$NET_IN" "$SERVER"
docker start "$SERVER" >/dev/null
sleep 2
state="$(docker inspect -f '{{.State.Status}}' "$SERVER")"
if [[ "$state" != running ]]; then docker logs "$SERVER"; echo "SmartDNS daemon failed to start (state=$state)" >&2; exit 1; fi
networks="$(docker inspect -f '{{range $name, $net := .NetworkSettings.Networks}}{{$name}}={{$net.IPAddress}} {{end}}' "$SERVER")"
[[ "$networks" == *"bridge="* && "$networks" == *"$NET_IN=172.31.0.10"* ]] || { echo "container is not attached to both default and routed networks: $networks" >&2; exit 1; }
default_gateway="$(docker inspect -f '{{.NetworkSettings.Networks.bridge.Gateway}}' "$SERVER")"
route="$(docker exec "$SERVER" ip route show default)"
[[ "$route" == *"via $default_gateway"* ]] || { echo "default egress route changed after routed network attach: $route (expected gateway $default_gateway)" >&2; exit 1; }
echo "PASS: container keeps default bridge egress route via $default_gateway while routed LAN ingress is attached at 172.31.0.10."

LOG_DIR="$(mktemp -d)"
docker run -d --name "$PROXY_A" --restart no --network "container:$SERVER" -v "$LOG_DIR:/logs" \
  --cap-drop ALL --security-opt no-new-privileges:true --entrypoint python3 \
  s5m-smartdns-routed-lab /usr/local/bin/socks-observer.py 19081 /logs/proxy-a.log >/dev/null
docker run -d --name "$PROXY_B" --restart no --network "container:$SERVER" -v "$LOG_DIR:/logs" \
  --cap-drop ALL --security-opt no-new-privileges:true --entrypoint python3 \
  s5m-smartdns-routed-lab /usr/local/bin/socks-observer.py 19082 /logs/proxy-b.log >/dev/null
sleep 1
log_count() { [[ -f "$1" ]] && wc -l < "$1" || echo 0; }
wait_for_log_increase() {
  local path="$1" before="$2"
  for _ in $(seq 1 40); do
    if (( $(log_count "$path") > before )); then return 0; fi
    sleep 0.25
  done
  return 1
}
wait_for_quiet() {
  local previous_a previous_b current_a current_b stable=0
  previous_a="$(log_count "$LOG_DIR/proxy-a.log")"
  previous_b="$(log_count "$LOG_DIR/proxy-b.log")"
  for _ in $(seq 1 40); do
    sleep 0.25
    current_a="$(log_count "$LOG_DIR/proxy-a.log")"
    current_b="$(log_count "$LOG_DIR/proxy-b.log")"
    if [[ "$current_a" == "$previous_a" && "$current_b" == "$previous_b" ]]; then
      stable=$((stable + 1))
      if (( stable >= 4 )); then return 0; fi
    else
      stable=0
    fi
    previous_a="$current_a"
    previous_b="$current_b"
  done
  echo "SOCKS observers did not become quiet; proxy-a log:" >&2
  cat "$LOG_DIR/proxy-a.log" 2>/dev/null >&2 || true
  echo "proxy-b log:" >&2
  cat "$LOG_DIR/proxy-b.log" 2>/dev/null >&2 || true
  return 1
}
for transport in udp tcp; do
  ip netns exec "$NS_A" python3 "$ROOT/client-query.py" probe-a.test 192.0.2.10 "$transport"
  ip netns exec "$NS_B" python3 "$ROOT/client-query.py" probe-b.test 192.0.2.20 "$transport"
  ip netns exec "$NS_C" python3 "$ROOT/client-query.py" probe-a.test NONE "$transport"

  a_before="$(log_count "$LOG_DIR/proxy-a.log")"
  b_before="$(log_count "$LOG_DIR/proxy-b.log")"
  ip netns exec "$NS_A" python3 "$ROOT/client-probe.py" a-route-check.example.com "$transport"
  wait_for_log_increase "$LOG_DIR/proxy-a.log" "$a_before" || { echo "client A did not use its named SOCKS listener" >&2; cat "$LOG_DIR/proxy-a.log" 2>/dev/null || true; exit 1; }
  wait_for_quiet
  [[ "$(log_count "$LOG_DIR/proxy-b.log")" == "$b_before" ]] || { echo "client A unexpectedly used client B SOCKS listener" >&2; exit 1; }

  a_before="$(log_count "$LOG_DIR/proxy-a.log")"
  b_before="$(log_count "$LOG_DIR/proxy-b.log")"
  ip netns exec "$NS_B" python3 "$ROOT/client-probe.py" b-route-check.example.com "$transport"
  wait_for_log_increase "$LOG_DIR/proxy-b.log" "$b_before" || { echo "client B did not use its named SOCKS listener" >&2; cat "$LOG_DIR/proxy-b.log" 2>/dev/null || true; exit 1; }
  wait_for_quiet
  [[ "$(log_count "$LOG_DIR/proxy-a.log")" == "$a_before" ]] || { echo "client B unexpectedly used client A SOCKS listener" >&2; exit 1; }

  a_before="$(log_count "$LOG_DIR/proxy-a.log")"
  b_before="$(log_count "$LOG_DIR/proxy-b.log")"
  ip netns exec "$NS_C" python3 "$ROOT/client-probe.py" unmapped-route-check.example.com "$transport"
  wait_for_quiet
  [[ "$(log_count "$LOG_DIR/proxy-a.log")" == "$a_before" && "$(log_count "$LOG_DIR/proxy-b.log")" == "$b_before" ]] || { echo "unmapped client unexpectedly reached a named SOCKS listener" >&2; exit 1; }
done
echo "PASS: real SmartDNS daemon selected distinct client CIDR groups, excluded unmatched clients from default upstreams, and sent mapped queries only to the matching named SOCKS listener over UDP and TCP."
echo "LIMIT: same-host IPv4 lab only; Agent validator/deployment, IPv6, Mihomo SOCKS and real proxy egress remain separate acceptance gates."
