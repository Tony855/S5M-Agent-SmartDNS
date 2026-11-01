#!/usr/bin/env bash
# Fault-injection tests for the deployment rollback functions.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_SCRIPT="$(cd "$SCRIPT_DIR/.." && pwd)/s5m-deploy.sh"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# Load only the production logging/rollback functions; never execute deployment.
sed -n '/^log()/,/^http_get()/ { /^http_get()/q; p; }' "$DEPLOY_SCRIPT" > "$tmp"
# shellcheck disable=SC1090
source "$tmp"
# The deploy script installs an EXIT trap; the test invokes rollback explicitly per case.
trap - EXIT

assert_eq() {
  [[ "$1" == "$2" ]] || { echo "expected '$2', got '$1': $3" >&2; exit 1; }
}

run_restore_success() (
  CONTAINER=s5m-agent
  BACKUP_NAME=s5m-agent.rollback.test
  HAD_OLD=1
  NEW_STARTED=1
  DEPLOY_OK=0
  NEW_PRESENT=1
  BACKUP_PRESENT=1
  OLD_RUNNING=0

  docker() {
    case "$1" in
      rm)
        [[ "$2" == "-f" && "$3" == "$CONTAINER" ]] || return 90
        NEW_PRESENT=0
        ;;
      container)
        [[ "$2" == "inspect" && "$3" == "$BACKUP_NAME" ]] || return 91
        (( BACKUP_PRESENT == 1 ))
        ;;
      rename)
        [[ "$2" == "$BACKUP_NAME" && "$3" == "$CONTAINER" ]] || return 92
        BACKUP_PRESENT=0
        ;;
      start)
        [[ "$2" == "$CONTAINER" ]] || return 93
        OLD_RUNNING=1
        ;;
      *) echo "unexpected docker command: $*" >&2; return 94 ;;
    esac
  }

  rollback_on_exit || true
  assert_eq "$NEW_PRESENT" 0 "partial replacement must be removed"
  assert_eq "$BACKUP_PRESENT" 0 "backup must be renamed back"
  assert_eq "$OLD_RUNNING" 1 "previous container must be started"
)

run_restore_rename_failure_keeps_backup() (
  CONTAINER=s5m-agent
  BACKUP_NAME=s5m-agent.rollback.test
  HAD_OLD=1
  NEW_STARTED=1
  DEPLOY_OK=0
  NEW_PRESENT=1
  BACKUP_PRESENT=1
  OLD_RUNNING=0

  docker() {
    case "$1" in
      rm) NEW_PRESENT=0 ;;
      container) return 0 ;;
      rename) return 1 ;;
      start) OLD_RUNNING=1 ;;
      *) return 94 ;;
    esac
  }

  rollback_on_exit || true
  assert_eq "$NEW_PRESENT" 0 "partial replacement must be removed even if restore rename fails"
  assert_eq "$BACKUP_PRESENT" 1 "failed restore must retain backup container"
  assert_eq "$OLD_RUNNING" 0 "must not start an un-restored container name"
)

run_restore_success
run_restore_rename_failure_keeps_backup
echo "deployment rollback fault-injection tests passed"
