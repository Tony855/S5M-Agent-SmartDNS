#!/usr/bin/env bash
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
DEPLOY="$ROOT/scripts/deploy-agent.sh"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
awk '
  /^stop_existing_container_checked\(\)/ { copy=1 }
  /^if docker container inspect "\$CONTAINER_NAME"/ { copy=0 }
  copy { print }
' "$DEPLOY" >"$tmp"
# shellcheck disable=SC1090
CONTAINER_NAME=s5m-agent
log() { :; }
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

test_stop_failure_keeps_old_service_available() (
  MOCK_STATE=running
  start_calls=0
  docker() {
    case "$1" in
      stop) return 1 ;;
      inspect) printf '%s\n' "$MOCK_STATE" ;;
      start) start_calls=$((start_calls + 1)); MOCK_STATE=running ;;
      *) return 90 ;;
    esac
  }
  if stop_existing_container_checked s5m-agent; then
    echo "stop helper unexpectedly accepted a running container" >&2
    exit 1
  fi
  assert_eq "$MOCK_STATE" running "old service remains running after failed stop"
  assert_eq "$start_calls" 1 "helper attempts to restore old service"
)

test_stop_error_with_confirmed_exit_is_safe() (
  MOCK_STATE=exited
  docker() {
    case "$1" in
      stop) return 1 ;;
      inspect) printf '%s\n' "$MOCK_STATE" ;;
      *) return 90 ;;
    esac
  }
  stop_existing_container_checked s5m-agent
)

test_successful_stop_is_verified() (
  MOCK_STATE=running
  docker() {
    case "$1" in
      stop) MOCK_STATE=exited ;;
      inspect) printf '%s\n' "$MOCK_STATE" ;;
      *) return 90 ;;
    esac
  }
  stop_existing_container_checked s5m-agent
)

bash -n "$DEPLOY"
test_stop_failure_keeps_old_service_available
test_stop_error_with_confirmed_exit_is_safe
test_successful_stop_is_verified
echo "Agent deployment stop failure and rollback fault-injection tests passed"
