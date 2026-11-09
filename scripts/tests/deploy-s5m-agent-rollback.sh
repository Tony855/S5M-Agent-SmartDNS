#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY_SCRIPT="$ROOT/scripts/deploy-s5m-agent.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin"
: > "$TMP/docker.log"
cat > "$TMP/bin/docker" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$DOCKER_CALL_LOG"
cmd="$1"; shift || true
get_status() {
  awk -F'|' -v n="$1" '$1 == n { print $2; found=1 } END { if (!found) exit 1 }' "$STATE_FILE"
}
write_state() {
  local name="$1" status="$2" tmp="${STATE_FILE}.tmp"
  awk -F'|' -v n="$name" '$1 != n { print }' "$STATE_FILE" > "$tmp" || true
  printf '%s|%s\n' "$name" "$status" >> "$tmp"
  mv "$tmp" "$STATE_FILE"
  chmod 666 "$STATE_FILE"
}
delete_state() {
  local name="$1" tmp="${STATE_FILE}.tmp"
  awk -F'|' -v n="$name" '$1 != n { print }' "$STATE_FILE" > "$tmp" || true
  mv "$tmp" "$STATE_FILE"
  chmod 666 "$STATE_FILE"
}
case "$cmd" in
  info) exit 0 ;;
  ps)
    if [[ " $* " == *" -a "* ]]; then cut -d'|' -f1 "$STATE_FILE"; fi
    exit 0
    ;;
  pull)
    [[ "${FAIL_PULL:-false}" != "true" ]] || exit 1
    exit 0
    ;;
  stop)
    status="$(get_status "$1")" || exit 1
    write_state "$1" stopped
    exit 0
    ;;
  rename)
    status="$(get_status "$1")" || exit 1
    delete_state "$1"
    write_state "$2" "$status"
    exit 0
    ;;
  start)
    write_state "$1" running
    exit 0
    ;;
  run)
    printf '%q\n' "$@" >> "$DOCKER_RUN_ARGS_LOG"
    [[ "${FAIL_RUN:-false}" != "true" ]] || exit 1
    write_state "s5m-agent" running
    echo mock-container-id
    exit 0
    ;;
  inspect)
    name="$1"
    status="$(get_status "$name")" || exit 1
    format=""
    while (($#)); do
      if [[ "$1" == "--format" ]]; then format="$2"; break; fi
      shift
    done
    case "$format" in
      "{{.State.Status}}") printf '%s\n' "$status" ;;
      "{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}") printf '%s\n' "${VERIFY_HEALTH:-healthy}" ;;
      *) printf '{}\n' ;;
    esac
    exit 0
    ;;
  rm)
    delete_state "${@: -1}"
    exit 0
    ;;
  image) exit 0 ;;
  rmi) exit 0 ;;
  logs) exit 0 ;;
  *) exit 0 ;;
esac
MOCK
chmod +x "$TMP/bin/docker"

cat > "$TMP/agent.conf" <<EOF
DATA_DIR="$TMP/data"
EOF
printf 's5m-agent|running\n' > "$TMP/state"

run_deploy() {
  sudo env PATH="$TMP/bin:$PATH" \
    DOCKER_CALL_LOG="$TMP/docker.log" DOCKER_RUN_ARGS_LOG="$TMP/docker-run-args.log" \
    STATE_FILE="$TMP/state" CONFIG_FILE="$TMP/agent.conf" "${@:1}" bash "$DEPLOY_SCRIPT" deploy
}

# Registry failure must leave the old container running and untouched.
: > "$TMP/docker.log"
if run_deploy FAIL_PULL=true; then
  echo "deploy unexpectedly succeeded when image pull failed" >&2
  exit 1
fi
[[ "$(cat "$TMP/state")" == "s5m-agent|running" ]]
if grep -Eq '^(stop|rename|rm) ' "$TMP/docker.log"; then
  echo "old container was touched before image pull succeeded" >&2
  cat "$TMP/docker.log" >&2
  exit 1
fi

# New-container startup failure must restore the previous container.
printf 's5m-agent|running\n' > "$TMP/state"
: > "$TMP/docker.log"
if run_deploy FAIL_RUN=true; then
  echo "deploy unexpectedly succeeded when docker run failed" >&2
  exit 1
fi
grep -q '^pull ' "$TMP/docker.log"
grep -q '^stop s5m-agent$' "$TMP/docker.log"
grep -q '^rename s5m-agent s5m-agent-rollback-' "$TMP/docker.log"
grep -q '^rename s5m-agent-rollback-.* s5m-agent$' "$TMP/docker.log"
grep -q '^start s5m-agent$' "$TMP/docker.log"
[[ "$(cat "$TMP/state")" == "s5m-agent|running" ]]

# An unhealthy replacement must also be removed and the old container restored.
printf 's5m-agent|running\n' > "$TMP/state"
: > "$TMP/docker.log"
if run_deploy VERIFY_HEALTH=unhealthy; then
  echo "deploy unexpectedly succeeded with an unhealthy replacement" >&2
  exit 1
fi
if ! grep -q '^rename s5m-agent-rollback-.* s5m-agent$' "$TMP/docker.log"; then
  echo "rollback command log:" >&2
  cat "$TMP/docker.log" >&2
  echo "remaining state:" >&2
  cat "$TMP/state" >&2
  exit 1
fi
[[ "$(cat "$TMP/state")" == "s5m-agent|running" ]]


# Successful redeploy must pass each Docker option/value as a separate argv item.
printf 's5m-agent|running\n' > "$TMP/state"
: > "$TMP/docker.log"
: > "$TMP/docker-run-args.log"
if ! run_deploy; then
  echo "deploy unexpectedly failed with a healthy replacement" >&2
  exit 1
fi
for expected in '-d' '--name' 's5m-agent' '--restart' 'unless-stopped' '-p' '80:80/tcp' '127.0.0.1:7890:7890/tcp' '127.0.0.1:7890:7890/udp' '--device' '/dev/net/tun:/dev/net/tun' '--cap-add' 'NET_ADMIN' 'NET_RAW' '-v' "$TMP/data:/data" '-e' 'TZ=Asia/Shanghai' 'ghcr.io/tony855/s5m-agent-smartdns:dev'; do
  if ! grep -Fxq -- "$expected" "$TMP/docker-run-args.log"; then
    echo "docker run lost or combined argument: $expected" >&2
    cat "$TMP/docker-run-args.log" >&2
    exit 1
  fi
done
if grep -Eq '^["]|"
 "$TMP/docker-run-args.log"; then
  echo "docker run arguments contain literal quote characters" >&2
  cat "$TMP/docker-run-args.log" >&2
  exit 1
fi

echo "Legacy Agent deployment argv boundaries and pull/start/health rollback paths verified."
