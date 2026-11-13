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
LAN_IF=$2
DURATION=${3:-90}
OUT_DIR=${4:-}
[[ "$DURATION" =~ ^[0-9]+$ ]] && (( DURATION >= 10 && DURATION <= 600 )) || usage
[[ "$LAN_IF" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || usage
for cmd in docker ip tcpdump nsenter timeout; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: missing required command: $cmd" >&2; exit 1; }
done
ip link show dev "$LAN_IF" >/dev/null 2>&1 || { echo "ERROR: interface not found: $LAN_IF" >&2; exit 1; }
docker inspect "$CONTAINER" >/dev/null 2>&1 || { echo "ERROR: container not found: $CONTAINER" >&2; exit 1; }
PID=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")
[[ "$PID" =~ ^[1-9][0-9]*$ ]] && [[ -d "/proc/$PID/ns/net" ]] || { echo "ERROR: container is not running" >&2; exit 1; }

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
FILTER='(udp dst port 6055) or (tcp dst port 6055)'
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
echo "Host interface: $LAN_IF; Agent container PID: $PID; DNS ingress port: 6055."
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
echo "CAPTURE_ONLY: compare source IPs in both files with SOURCE_ADDR from each physical client."
echo "This script does not prove source preservation, firewall policy, SmartDNS group selection, or proxy egress."
echo "Evidence files (mode 0600): $HOST_PCAP $CONTAINER_PCAP $HOST_LOG $CONTAINER_LOG"
