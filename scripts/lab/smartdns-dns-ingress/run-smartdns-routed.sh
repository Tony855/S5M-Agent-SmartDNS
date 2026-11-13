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
MIHOMO=s5m-mihomo-real-listener-lab
LOG_DIR=""
LIFECYCLE_DIR=""
cleanup() {
  docker rm -f "$MIHOMO" "$PROXY_A" "$PROXY_B" "$SERVER" >/dev/null 2>&1 || true
  [[ -z "$LOG_DIR" ]] || rm -rf "$LOG_DIR"
  [[ -z "$LIFECYCLE_DIR" ]] || rm -rf "$LIFECYCLE_DIR"
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
# Keep the ordinary Docker bridge as the default egress network. Start a
# harmless placeholder first, then use the production host helper to attach
# the routed endpoint before SmartDNS binds its exact ingress address.
docker create --name "$SERVER" --restart no --network bridge \
  -p 127.0.0.1::6055/udp -p 127.0.0.1::6055/tcp \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --entrypoint /bin/sh s5m-smartdns-routed-lab -c 'sleep 3600' >/dev/null
docker start "$SERVER" >/dev/null
sleep 1
LIFECYCLE_DIR="$(mktemp -d /run/s5m-smartdns-lifecycle.XXXXXX)"
cat >"$LIFECYCLE_DIR/network.json" <<EOF
{
  "version": 1,
  "network": "$NET_IN",
  "container": "$SERVER",
  "interface": "$LAN_BR",
  "ipv4_subnet": "172.31.0.0/24",
  "ipv4_gateway": "172.31.0.1",
  "ipv4_address": "172.31.0.10",
  "ipv6_subnet": null,
  "ipv6_gateway": null,
  "ipv6_address": null,
  "client_cidrs": ["192.168.50.0/24"]
}
EOF
cat >"$LIFECYCLE_DIR/firewall.json" <<EOF
{
  "version": 1,
  "interface": "$LAN_BR",
  "ipv4_address": "172.31.0.10",
  "ipv6_address": null,
  "client_cidrs": ["192.168.50.0/24"]
}
EOF
chmod 0600 "$LIFECYCLE_DIR/network.json" "$LIFECYCLE_DIR/firewall.json"
python3 "$ROOT/../../host-ingress/network-lifecycle.py" provision \
  --config "$LIFECYCLE_DIR/network.json" --firewall-config "$LIFECYCLE_DIR/firewall.json"
docker exec -d "$SERVER" /bin/sh -c '/usr/sbin/smartdns -f -c /etc/smartdns/smartdns.conf >/tmp/smartdns.log 2>&1'
sleep 2
state="$(docker inspect -f '{{.State.Status}}' "$SERVER")"
if [[ "$state" != running ]]; then docker logs "$SERVER"; echo "SmartDNS container failed to start (state=$state)" >&2; exit 1; fi
docker exec "$SERVER" python3 -c 'import socket; s=socket.create_connection(("172.31.0.10",6055),timeout=2); s.close()' || { docker exec "$SERVER" cat /tmp/smartdns.log; echo "SmartDNS did not bind routed TCP ingress" >&2; exit 1; }
networks="$(docker inspect -f '{{range $name, $net := .NetworkSettings.Networks}}{{$name}}={{$net.IPAddress}} {{end}}' "$SERVER")"
[[ "$networks" == *"bridge="* && "$networks" == *"$NET_IN=172.31.0.10"* ]] || { echo "container is not attached to both default and routed networks: $networks" >&2; exit 1; }
default_gateway="$(docker inspect -f '{{.NetworkSettings.Networks.bridge.Gateway}}' "$SERVER")"
route="$(docker exec "$SERVER" ip route show default)"
[[ "$route" == *"via $default_gateway"* ]] || { echo "default egress route changed after routed network attach: $route (expected gateway $default_gateway)" >&2; exit 1; }
echo "PASS: container keeps default bridge egress route via $default_gateway while routed LAN ingress is attached at 172.31.0.10."

LOG_DIR="$(mktemp -d)"
docker run -d --name "$PROXY_A" --restart no --network "container:$SERVER" -v "$LOG_DIR:/logs" \
  --cap-drop ALL --security-opt no-new-privileges:true --entrypoint python3 \
  s5m-smartdns-routed-lab /usr/local/bin/socks-observer.py 19091 /logs/proxy-a.log >/dev/null
docker run -d --name "$PROXY_B" --restart no --network "container:$SERVER" -v "$LOG_DIR:/logs" \
  --cap-drop ALL --security-opt no-new-privileges:true --entrypoint python3 \
  s5m-smartdns-routed-lab /usr/local/bin/socks-observer.py 19092 /logs/proxy-b.log >/dev/null
mkdir -p "$LOG_DIR/mihomo"
docker run -d --name "$MIHOMO" --restart no --network "container:$SERVER" \
  -v "$ROOT/mihomo-per-client.yaml:/etc/mihomo/config.yaml:ro" -v "$LOG_DIR:/logs" \
  --cap-drop ALL --security-opt no-new-privileges:true --entrypoint /usr/local/bin/mihomo \
  s5m-smartdns-routed-lab -d /logs/mihomo -f /etc/mihomo/config.yaml >/dev/null
sleep 2
mihomo_state="$(docker inspect -f '{{.State.Status}}' "$MIHOMO")"
if [[ "$mihomo_state" != running ]]; then docker logs "$MIHOMO"; echo "Mihomo daemon failed to start (state=$mihomo_state)" >&2; exit 1; fi
for _ in $(seq 1 40); do
  if docker exec "$SERVER" python3 -c 'import socket; [socket.create_connection(("127.0.0.1", p), timeout=.2).close() for p in (16000,16001)]' >/dev/null 2>&1; then break; fi
  sleep 0.25
done
docker exec "$SERVER" python3 -c 'import socket; [socket.create_connection(("127.0.0.1", p), timeout=1).close() for p in (16000,16001)]' || { docker logs "$MIHOMO"; echo "Mihomo per-client listeners did not become ready" >&2; exit 1; }
echo "PASS: real Mihomo started both loopback SOCKS listeners with distinct pinned outbound proxies."
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
echo "PASS: real SmartDNS + real Mihomo selected distinct client CIDR groups, excluded unmatched clients from default upstreams, and reached only the matching Mihomo listener and pinned outbound SOCKS proxy over UDP and TCP."
echo "LIMIT: same-host IPv4 lab only; Agent validator/deployment, IPv6, physical LAN/router acceptance and real public proxy egress remain separate acceptance gates. The Mihomo outbound endpoints in this lab are rejecting SOCKS observers, not production proxies."
