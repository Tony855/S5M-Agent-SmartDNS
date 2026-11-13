#!/usr/bin/env bash
# Prove the standalone Agent deployer rejects an unimplemented DNS host
# publication before making any Docker API call or changing service state.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY="$ROOT/scripts/deploy-agent.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin"
cat >"$TMP/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$DOCKER_CALL_LOG"
exit 0
DOCKER
chmod +x "$TMP/bin/docker"

cat >"$TMP/agent.conf" <<CONF
IMAGE="ghcr.io/tony855/s5m-agent-smartdns:dev"
CONTAINER_NAME="s5m-agent-ingress-guard-test"
S5M_HOSTNAME="ingress-guard-test"
BIND_IP="127.0.0.1"
WEB_BIND_IP="127.0.0.1"
WEB_PORT="0"
PROXY_PORT="0"
PROXY_BIND_IP="127.0.0.1"
DNS_PORT="5353"
DATA_DIR="$TMP/data"
RESTART_POLICY="unless-stopped"
ENABLE_TUN="0"
EXTRA_ENV_FILE=""
PULL_IMAGE="0"
CONF
chmod 0600 "$TMP/agent.conf"

export DOCKER_CALL_LOG="$TMP/docker.log"
: >"$DOCKER_CALL_LOG"
if sudo env PATH="$TMP/bin:/usr/bin:/bin" CONFIG_FILE="$TMP/agent.conf" \
  bash "$DEPLOY" >"$TMP/deploy.log" 2>&1; then
  echo "unsafe DNS_PORT publication unexpectedly passed deploy preflight" >&2
  cat "$TMP/deploy.log" >&2
  exit 1
fi

grep -Fq "DNS_PORT 暂不可用" "$TMP/deploy.log" || {
  echo "deployment failed for an unexpected reason" >&2
  cat "$TMP/deploy.log" >&2
  exit 1
}
if [[ -s "$DOCKER_CALL_LOG" ]]; then
  echo "Docker was called before the DNS ingress guard rejected the config" >&2
  cat "$DOCKER_CALL_LOG" >&2
  exit 1
fi

echo "Agent DNS ingress fail-closed preflight test passed"
