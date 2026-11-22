#!/usr/bin/env bash
# Read-only physical LAN ingress capture. Run on the Docker host as root.
set -Eeuo pipefail

usage() {
  echo "Usage: $0 <agent-container> <lan-interface> [duration-seconds] [output-directory]" >&2
  echo "Example: sudo $0 s5m-agent eth0 90" >&2
  exit 2
}
[[ $# -ge 2 && $# -le 4 ]] || usage
[[ $EUID -eq 0 ]] || { echo "ERROR: run as root" >&2; exit 1; }
CONTAINER=$1
[[ "$CONTAINER" =~ ^[A-Za-z0-9_.-]{1,128}$ ]] || usage
LAN_IF=$2
DURATION=${3:-90}
OUT_DIR=${4:-}
[[ "$DURATION" =~ ^[0-9]+$ ]] && (( DURATION >= 10 && DURATION <= 600 )) || usage
[[ "$LAN_IF" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || usage
for cmd in docker ip tcpdump nsenter timeout python3; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: missing required command: $cmd" >&2; exit 1; }
done
ip link show dev "$LAN_IF" >/dev/null 2>&1 || { echo "ERROR: interface not found: $LAN_IF" >&2; exit 1; }
docker inspect "$CONTAINER" >/dev/null 2>&1 || { echo "ERROR: container not found: $CONTAINER" >&2; exit 1; }
NETWORK_CONFIG="${S5M_INGRESS_NETWORK_CONFIG:-/etc/s5m-agent-ingress/network.json}"
[[ -f "$NETWORK_CONFIG" && ! -L "$NETWORK_CONFIG" ]] || { echo "ERROR: routed ingress network config missing or unsafe: $NETWORK_CONFIG" >&2; exit 1; }
NETWORK=$(python3 - "$NETWORK_CONFIG" "$CONTAINER" <<'PY'
import json, os, re, stat, sys
path, container = sys.argv[1], sys.argv[2]
st = os.lstat(path)
if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077 or st.st_size > 16384:
    raise SystemExit("network config must be a root-owned mode-0600 regular file")
with open(path, encoding="utf-8") as stream:
    cfg = json.load(stream)
name = cfg.get("network")
if cfg.get("container") != container or not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", name):
    raise SystemExit("network config container/name does not match the capture target")
print(name)
PY
) || { echo "ERROR: cannot read routed ingress network identity" >&2; exit 1; }
NETWORK_ID=$(docker network inspect -f '{{.Id}}' "$NETWORK")
[[ "$NETWORK_ID" =~ ^[0-9a-f]{64}$ ]] || { echo "ERROR: invalid routed Docker network identity" >&2; exit 1; }
CONTAINER_IDENTITY=$(docker inspect -f '{{.Id}}|{{.State.Pid}}|{{.State.StartedAt}}' "$CONTAINER")
IFS='|' read -r CONTAINER_ID PID CONTAINER_STARTED_AT <<<"$CONTAINER_IDENTITY"
[[ "$CONTAINER_ID" =~ ^[0-9a-f]{64}$ ]] || { echo "ERROR: invalid Agent container ID" >&2; exit 1; }
[[ "$PID" =~ ^[1-9][0-9]*$ ]] && [[ -d "/proc/$PID/ns/net" ]] || { echo "ERROR: container is not running" >&2; exit 1; }
[[ "$CONTAINER_STARTED_AT" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$ ]] || { echo "ERROR: invalid Agent container start timestamp" >&2; exit 1; }
capture_stable_host_addresses() {
  ip -j addr show dev "$LAN_IF" | python3 -c '
import ipaddress, json, sys
records = json.load(sys.stdin)
if not isinstance(records, list) or len(records) != 1:
    raise SystemExit("cannot uniquely inspect the trusted host interface")
addresses = set()
for item in records[0].get("addr_info", []):
    if not isinstance(item, dict) or item.get("scope") != "global":
        continue
    flags = set(item.get("flags", [])) if isinstance(item.get("flags", []), list) else set()
    if item.get("temporary") is True or flags.intersection({"temporary", "tentative", "dadfailed", "deprecated"}):
        continue
    try:
        address = ipaddress.ip_address(item.get("local", ""))
    except ValueError:
        continue
    if address.is_unspecified or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved or getattr(address, "ipv4_mapped", None):
        continue
    addresses.add(str(address))
print(json.dumps(sorted(addresses), separators=(",", ":")))
'
}
HOST_INTERFACE_ADDRESSES=$(capture_stable_host_addresses) || { echo "ERROR: cannot snapshot stable global addresses on $LAN_IF" >&2; exit 1; }
capture_host_link_identity() {
  ip -j addr show dev "$LAN_IF" | python3 -c '
import json, re, sys
records = json.load(sys.stdin)
if not isinstance(records, list) or len(records) != 1:
    raise SystemExit("cannot uniquely inspect the trusted host interface")
record = records[0]
if type(record.get("ifindex")) is not int or record["ifindex"] <= 0:
    raise SystemExit("trusted host interface ifindex is missing or invalid")
flags = record.get("flags", [])
if not isinstance(flags, list) or "UP" not in flags or "LOWER_UP" not in flags:
    raise SystemExit("trusted host interface must be UP and LOWER_UP during physical capture")
mac = record.get("address")
if not isinstance(mac, str) or mac != mac.lower() or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
    raise SystemExit("trusted host interface must expose a canonical six-octet Ethernet MAC")
octets = bytes(int(part, 16) for part in mac.split(":"))
if octets[0] & 1 or octets in (b"\x00" * 6, b"\xff" * 6):
    raise SystemExit("trusted host interface MAC must be unicast and nonzero")
print(f"{record['ifindex']}|{mac}")
'
}
HOST_INTERFACE_IDENTITY=$(capture_host_link_identity) || { echo "ERROR: cannot snapshot physical link identity on $LAN_IF" >&2; exit 1; }
IFS='|' read -r HOST_INTERFACE_IFINDEX HOST_INTERFACE_MAC <<<"$HOST_INTERFACE_IDENTITY"

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR=$(mktemp -d -m 0700 "/var/tmp/s5m-dns-ingress-$(date +%Y%m%d-%H%M%S)-XXXXXX")
else
  [[ ! -e "$OUT_DIR" && ! -L "$OUT_DIR" ]] || { echo "ERROR: output path already exists" >&2; exit 1; }
  install -d -m 0700 "$OUT_DIR"
fi
chmod 0700 "$OUT_DIR"
HOST_PCAP="$OUT_DIR/host-lan.pcap"
CONTAINER_PCAP="$OUT_DIR/container-ingress.pcap"
HOST_LOG="$OUT_DIR/host-lan.txt"
CONTAINER_LOG="$OUT_DIR/container-ingress.txt"
FILTER='port 6055'
STARTED_AT=$(date +%s)
HOST_PID=""
CONTAINER_PID=""
cleanup() {
  [[ -n "$HOST_PID" ]] && kill -INT "$HOST_PID" 2>/dev/null || true
  [[ -n "$CONTAINER_PID" ]] && kill -INT "$CONTAINER_PID" 2>/dev/null || true
  [[ -n "$HOST_PID" ]] && wait "$HOST_PID" 2>/dev/null || true
  [[ -n "$CONTAINER_PID" ]] && wait "$CONTAINER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "Starting read-only captures for $DURATION seconds."
echo "Host interface: $LAN_IF; Agent container PID: $PID; routed network: $NETWORK ($NETWORK_ID); DNS ingress port: 6055."
echo "Run the physical client probe(s) now against the container's routed ingress IP."
timeout --signal=INT --kill-after=5 "$DURATION" tcpdump -ni "$LAN_IF" -s 0 -U -w "$HOST_PCAP" "$FILTER" >/dev/null 2>&1 &
HOST_PID=$!
timeout --signal=INT --kill-after=5 "$DURATION" nsenter -t "$PID" -n tcpdump -ni any -s 0 -U -w "$CONTAINER_PCAP" "$FILTER" >/dev/null 2>&1 &
CONTAINER_PID=$!
sleep 2
[[ -n "$HOST_PID" ]] && kill -0 "$HOST_PID" 2>/dev/null || { echo "ERROR: host capture did not start" >&2; exit 1; }
[[ -n "$CONTAINER_PID" ]] && kill -0 "$CONTAINER_PID" 2>/dev/null || { echo "ERROR: container namespace capture did not start" >&2; exit 1; }
echo "CAPTURE_READY output=$OUT_DIR"
sleep "$DURATION" || true
cleanup
HOST_PID=""
CONTAINER_PID=""
FINISHED_AT=$(date +%s)
CURRENT_CONTAINER_IDENTITY=$(docker inspect -f '{{.Id}}|{{.State.Pid}}|{{.State.StartedAt}}' "$CONTAINER")
[[ "$CURRENT_CONTAINER_IDENTITY" == "$CONTAINER_IDENTITY" ]] || { echo "ERROR: Agent container restarted during capture; discard captures and retry" >&2; exit 1; }
HOST_INTERFACE_ADDRESSES_END=$(capture_stable_host_addresses) || { echo "ERROR: cannot recheck stable global addresses on $LAN_IF" >&2; exit 1; }
[[ "$HOST_INTERFACE_ADDRESSES" == "$HOST_INTERFACE_ADDRESSES_END" ]] || { echo "ERROR: trusted host interface addresses changed during capture; discard evidence and recapture" >&2; exit 1; }
HOST_INTERFACE_IDENTITY_END=$(capture_host_link_identity) || { echo "ERROR: cannot recheck physical link identity on $LAN_IF" >&2; exit 1; }
[[ "$HOST_INTERFACE_IDENTITY" == "$HOST_INTERFACE_IDENTITY_END" ]] || { echo "ERROR: trusted host interface ifindex/MAC changed during capture; discard evidence and recapture" >&2; exit 1; }
printf '{"version":4,"container":"%s","container_id":"%s","network":"%s","network_id":"%s","container_pid":%s,"container_started_at":"%s","host_interface":"%s","host_interface_addresses":%s,"host_interface_ifindex":%s,"host_interface_mac":"%s","started_at":%s,"finished_at":%s,"host_pcap":"host-lan.pcap","container-pcap":"container-ingress.pcap"}\n' \
  "$CONTAINER" "$CONTAINER_ID" "$NETWORK" "$NETWORK_ID" "$PID" "$CONTAINER_STARTED_AT" "$LAN_IF" "$HOST_INTERFACE_ADDRESSES" "$HOST_INTERFACE_IFINDEX" "$HOST_INTERFACE_MAC" "$STARTED_AT" "$FINISHED_AT" >"$OUT_DIR/capture-manifest.json.tmp"
chmod 0600 "$OUT_DIR/capture-manifest.json.tmp"
mv "$OUT_DIR/capture-manifest.json.tmp" "$OUT_DIR/capture-manifest.json"
tcpdump -nn -tttt -r "$HOST_PCAP" >"$HOST_LOG" 2>&1 || true
tcpdump -nn -tttt -r "$CONTAINER_PCAP" >"$CONTAINER_LOG" 2>&1 || true
chmod 0600 "$OUT_DIR"/*
echo
echo "=== Host LAN ingress packets ==="
cat "$HOST_LOG"
echo
echo "=== Agent network namespace ingress packets ==="
cat "$CONTAINER_LOG"
echo
echo "Capture manifest: $OUT_DIR/capture-manifest.json; run physical-ingress-verify.py with the paired pcaps and client probe JSONL."
echo "This script does not prove source preservation, firewall policy, SmartDNS group selection, or proxy egress."
echo "Evidence files (mode 0600): $HOST_PCAP $CONTAINER_PCAP $HOST_LOG $CONTAINER_LOG"
