#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/good/data" "$TMP/outside"
ln -s "$TMP/outside" "$TMP/parent-link"
ln -s "$TMP/outside" "$TMP/final-link"

for script in \
  "$ROOT/scripts/deploy-s5m-agent.sh" \
  "$ROOT/scripts/deploy-agent.sh" \
  "$ROOT/scripts/s5m-deploy.sh"; do
  helper="$TMP/helper.sh"
  awk '
    /^validate_data_dir_path\(\) \{$/ { inside=1 }
    inside { print }
    inside && /^}$/ { exit }
  ' "$script" > "$helper"
  test -s "$helper"

  DATA_DIR="$TMP/good/data" bash -c 'source "$1"; validate_data_dir_path' _ "$helper"

  for unsafe in \
    "$TMP/parent-link/data" \
    "$TMP/final-link" \
    "$TMP/../outside" \
    "relative/path" \
    "/" \
    "$TMP//double"; do
    if DATA_DIR="$unsafe" bash -c 'source "$1"; validate_data_dir_path' _ "$helper" >/dev/null 2>&1; then
      echo "unsafe DATA_DIR accepted by $script: $unsafe" >&2
      exit 1
    fi
  done
done

echo "Agent data-directory symlink and traversal safety tests passed."
