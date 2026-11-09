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
echo "Legacy Agent deployment argv boundaries and pull/start/health rollback paths verified."
