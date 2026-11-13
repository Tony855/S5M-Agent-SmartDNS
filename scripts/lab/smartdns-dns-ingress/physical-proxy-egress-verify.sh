#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  sudo bash physical-proxy-egress-verify.sh <agent-container> --expect <socks-port>=<public-egress-ip> [--expect ...] [--url https://api.ipify.org]

Run on the Docker host after per-client Mihomo listeners are configured.
The script enters the Agent network namespace and performs a real SOCKS5
CONNECT using remote DNS resolution. It compares the returned public egress
IP with the expected IP for each listener. It does not modify containers,
routes, firewall rules, or proxy configuration.
EOF
}

[[ ${EUID} -eq 0 ]] || { echo "run with sudo/root" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }
command -v nsenter >/dev/null 2>&1 || { echo "nsenter is required" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then usage; exit 0; fi
CONTAINER=${1:-}
[[ -n "$CONTAINER" ]] || { usage >&2; exit 2; }
shift
URL=https://api.ipify.org
EXPECTATIONS=()
while (($#)); do
  case "$1" in
    --expect)
      (($# >= 2)) || { echo "--expect requires port=public-ip" >&2; exit 2; }
      EXPECTATIONS+=("$2")
      shift 2
      ;;
    --url)
      (($# >= 2)) || { echo "--url requires a URL" >&2; exit 2; }
      URL="$2"
      shift 2
      ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
(("${#EXPECTATIONS[@]}" > 0)) || { echo "at least one --expect is required" >&2; usage >&2; exit 2; }

PID="$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")"
[[ "$PID" =~ ^[1-9][0-9]*$ ]] || { echo "Agent container is not running: $CONTAINER" >&2; exit 1; }
declare -A SEEN_PORTS=()
for item in "${EXPECTATIONS[@]}"; do
  [[ "$item" == *=* ]] || { echo "invalid expectation: $item (expected port=ip)" >&2; exit 2; }
  port="${item%%=*}"
  expected="${item#*=}"
  [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || { echo "invalid SOCKS port: $port" >&2; exit 2; }
  [[ -z "${SEEN_PORTS[$port]:-}" ]] || { echo "duplicate SOCKS port: $port" >&2; exit 2; }
  SEEN_PORTS[$port]=1
  python3 - "$expected" <<'PY'
import ipaddress,sys
try:
    ip=ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit("expected egress must be a literal public IP address")
if not ip.is_global:
    raise SystemExit("expected egress IP must be globally routable")
PY
  actual="$(nsenter -t "$PID" -n -- curl --noproxy "" --fail --silent --show-error \
    --connect-timeout 8 --max-time 25 --socks5-hostname "127.0.0.1:$port" "$URL")" || {
      echo "FAIL: SOCKS listener $port could not complete a real CONNECT to $URL" >&2
      exit 1
    }
  python3 - "$actual" "$expected" "$port" <<'PY'
import ipaddress,sys
try:
    actual=ipaddress.ip_address(sys.argv[1].strip())
    expected=ipaddress.ip_address(sys.argv[2])
except ValueError:
    raise SystemExit("proxy egress endpoint did not return a single IP address")
if not actual.is_global:
    raise SystemExit("proxy egress endpoint returned a non-global IP")
if actual!=expected:
    raise SystemExit(f"FAIL: SOCKS listener {sys.argv[3]} egress {actual} != expected {expected}")
print(f"PASS: SOCKS listener {sys.argv[3]} completed CONNECT; public egress IP={actual}")
PY
done
