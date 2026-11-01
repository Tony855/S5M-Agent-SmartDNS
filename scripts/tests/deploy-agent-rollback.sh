#!/usr/bin/env bash
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
DEPLOY="$ROOT/scripts/deploy-agent.sh"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
awk '
  /^BACKUP_NAME=/ { copy=1 }
  /^if docker container inspect "\$CONTAINER_NAME"/ { copy=0 }
  copy { print }
' "$DEPLOY" >"$tmp"
# shellcheck disable=SC1090
source "$tmp"
trap - EXIT
assert_eq() {
  [[ "$1" == "$2" ]] || { printf 'expected %s, got %s: %s\n' "$2" "$1" "$3" >&2; exit 1; }
}
test_successful_restore() (
  CONTAINER_NAME=s5m-agent BACKUP_NAME=s5m-agent.rollback.test
  HAD_OLD=1 NEW_STARTED=1 NEW_PRESENT=1 BACKUP_PRESENT=1 OLD_RUNNING=0
  docker() {
    case "$1" in
      container)
        [[ "$2" == inspect ]] || return 90
        if [[ "$3" == "$CONTAINER_NAME" ]]; then [[ "$NEW_PRESENT" == 1 ]]
        elif [[ "$3" == "$BACKUP_NAME" ]]; then [[ "$BACKUP_PRESENT" == 1 ]]
        else return 91; fi ;;
      rm) [[ "$2" == -f && "$3" == "$CONTAINER_NAME" ]] || return 92; NEW_PRESENT=0 ;;
      rename) [[ "$2" == "$BACKUP_NAME" && "$3" == "$CONTAINER_NAME" ]] || return 93; BACKUP_PRESENT=0 ;;
      start) [[ "$2" == "$CONTAINER_NAME" ]] || return 94; OLD_RUNNING=1 ;;
      *) return 95 ;;
    esac
  }
  restore_previous
  assert_eq "$NEW_PRESENT" 0 "failed new container removed"
  assert_eq "$BACKUP_PRESENT" 0 "old backup renamed back"
  assert_eq "$OLD_RUNNING" 1 "old container restarted"
  assert_eq "$HAD_OLD" 0 "rollback state cleared"
)
test_failed_new_container_removal_preserves_backup() (
  CONTAINER_NAME=s5m-agent BACKUP_NAME=s5m-agent.rollback.test
  HAD_OLD=1 NEW_STARTED=1 NEW_PRESENT=1 BACKUP_PRESENT=1 OLD_RUNNING=0
  docker() {
    case "$1" in
      container) [[ "$2" == inspect ]] || return 90; return 0 ;;
      rm) return 1 ;;
      rename|start) echo "must not rename or start old container while new container remains" >&2; return 91 ;;
      *) return 92 ;;
    esac
  }
  if restore_previous; then echo "expected rollback failure" >&2; exit 1; fi
  assert_eq "$BACKUP_PRESENT" 1 "old backup remains available"
  assert_eq "$OLD_RUNNING" 0 "must not start possibly wrong container"
)
bash -n "$DEPLOY"
test_successful_restore
test_failed_new_container_removal_preserves_backup
echo "Agent deployment rollback fault-injection tests passed"
