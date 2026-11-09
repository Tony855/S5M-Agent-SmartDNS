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
read_state() {
  if [[ -f "$STATE_FILE" ]]; then
    IFS='|' read -r STATE_NAME STATE_STATUS < "$STATE_FILE"
  else
    STATE_NAME=""; STATE_STATUS=""
  fi
}
write_state() { printf '%s|%s\n' "$1" "$2" > "$STATE_FILE"; }
case "$cmd" in
  info) exit 0 ;;
  ps)
    read_state
    if [[ " $* " == *" -a "* ]]; then
      [[ -n "$STATE_NAME" ]] && printf '%s\n' "$STATE_NAME"
    fi
    exit 0
    ;;
  pull)
    [[ "${FAIL_PULL:-false}" != "true" ]] || exit 1
    exit 0
    ;;
  stop)
    read_state
    if [[ "$1" == "$STATE_NAME" ]]; then write_state "$STATE_NAME" stopped; fi
    exit 0
    ;;
  rename)
    read_state
    if [[ "$1" != "$STATE_NAME" ]]; then exit 1; fi
    write_state "$2" "$STATE_STATUS"
    exit 0
    ;;
  start)
    write_state "$1" running
    exit 0
    ;;
  run)
    [[ "${FAIL_RUN:-false}" != "true" ]] || exit 1
    write_state "s5m-agent" running
    echo mock-container-id
    exit 0
    ;;
  inspect)
    read_state
    name="$1"
    [[ "$name" == "$STATE_NAME" ]] || exit 1
    format=""
    while (($#)); do
      if [[ "$1" == "--format" ]]; then format="$2"; break; fi
      shift
    done
    case "$format" in
      "{{.State.Status}}") printf '%s\n' "$STATE_STATUS" ;;
      "{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}") printf '%s\n' "${VERIFY_HEALTH:-healthy}" ;;
      *) printf '{}\n' ;;
    esac
    exit 0
    ;;
  rm)
    read_state
    name="${@: -1}"
    if [[ "$name" == "$STATE_NAME" ]]; then : > "$STATE_FILE"; fi
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
    DOCKER_CALL_LOG="$TMP/docker.log" STATE_FILE="$TMP/state" \
    CONFIG_FILE="$TMP/agent.conf" "${@:1}" bash "$DEPLOY_SCRIPT" deploy
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
grep -q '^rename s5m-agent-rollback-.* s5m-agent$' "$TMP/docker.log"
[[ "$(cat "$TMP/state")" == "s5m-agent|running" ]]

echo "Legacy Agent deployment pull/start/health rollback paths verified."
