#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/scripts/deploy-s5m-agent.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin"
cat > "$TMP/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$DOCKER_CALL_LOG"
case "${1:-} ${2:-}" in
  "info") exit 0 ;;
  "pull"*)
    [[ "${MOCK_PULL_FAIL:-0}" != 1 ]] || exit 1
    exit 0
    ;;
  "image inspect")
    [[ "${MOCK_INSPECT_FAIL:-0}" != 1 ]] || exit 1
    exit 0
    ;;
  "ps"*) exit 0 ;;
  *) exit 0 ;;
esac
DOCKER
chmod +x "$TMP/bin/docker"

run_menu() {
  local config="$1"
  shift
  printf '21\n0\n' | sudo env PATH="$TMP/bin:$PATH" \
    CONFIG_FILE="$config" DOCKER_CALL_LOG="$TMP/docker.log" "$@" \
    bash "$SCRIPT" menu >"$TMP/output.log" 2>&1
}

# Successful pull selects and persists only the no-SmartDNS image.
cat > "$TMP/success.conf" <<'CONF'
IMAGE=ghcr.io/tony855/s5m-agent-smartdns:dev
CONF
: > "$TMP/docker.log"
run_menu "$TMP/success.conf"
grep -Fxq 'IMAGE=ghcr.io/tony855/s5m-agent:dev' "$TMP/success.conf"
grep -Fq 'pull ghcr.io/tony855/s5m-agent:dev' "$TMP/docker.log"
if grep -Eq '^(stop|rm|run|restart) ' "$TMP/docker.log"; then
  echo "Image selection unexpectedly changed container lifecycle" >&2
  cat "$TMP/docker.log" >&2
  exit 1
fi

# Failed pull must not change the selected image or persisted configuration.
cat > "$TMP/failure.conf" <<'CONF'
IMAGE=ghcr.io/tony855/s5m-agent-smartdns:dev
CONF
cp "$TMP/failure.conf" "$TMP/failure.expected"
: > "$TMP/docker.log"
run_menu "$TMP/failure.conf" MOCK_PULL_FAIL=1
cmp -s "$TMP/failure.expected" "$TMP/failure.conf"
if grep -Eq '^(stop|rm|run|restart) ' "$TMP/docker.log"; then
  echo "Failed image pull unexpectedly changed container lifecycle" >&2
  cat "$TMP/docker.log" >&2
  exit 1
fi

# A successful pull followed by a failed local inspect must also keep selection.
cat > "$TMP/inspect-failure.conf" <<'CONF'
IMAGE=ghcr.io/tony855/s5m-agent-smartdns:dev
CONF
cp "$TMP/inspect-failure.conf" "$TMP/inspect-failure.expected"
: > "$TMP/docker.log"
run_menu "$TMP/inspect-failure.conf" MOCK_INSPECT_FAIL=1
cmp -s "$TMP/inspect-failure.expected" "$TMP/inspect-failure.conf"

echo "No-SmartDNS image pull selection and failure-path tests passed."
