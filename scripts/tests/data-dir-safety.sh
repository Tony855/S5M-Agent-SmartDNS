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
    "$TMP//double" \
    "$TMP/good/data/"; do
    if DATA_DIR="$unsafe" bash -c 'source "$1"; validate_data_dir_path' _ "$helper" >/dev/null 2>&1; then
      echo "unsafe DATA_DIR accepted by $script: $unsafe" >&2
      exit 1
    fi
  done

done

# The explicit wipe path must refuse a mount point anywhere below DATA_DIR.
awk '
  /^ensure_no_data_dir_mounts\(\) \{$/ { inside=1 }
  inside { print }
  inside && /^}$/ { exit }
' "$ROOT/scripts/deploy-s5m-agent.sh" > "$TMP/mount-helper.sh"
test -s "$TMP/mount-helper.sh"
mkdir -p "$TMP/bin"
cat > "$TMP/bin/findmnt" <<'SH'
#!/usr/bin/env sh
[ "${FINDMNT_FAIL:-0}" = "1" ] && exit 2
printf '%s\n' "$FINDMNT_TARGETS"
SH
chmod 0755 "$TMP/bin/findmnt"
run_mount_check() {
  DATA_DIR="$1" FINDMNT_TARGETS="$2" FINDMNT_FAIL="${3:-0}" PATH="$TMP/bin:/usr/bin:/bin" \
    bash -c 'err() { return 1; }; source "$1"; ensure_no_data_dir_mounts' _ "$TMP/mount-helper.sh"
}
safe_mounts="$(printf '/\n/tmp\n%s\n' "$TMP/outside")"
run_mount_check "$TMP/good/data" "$safe_mounts"
for mounted in "$TMP/good/data" "$TMP/good/data/cache"; do
  nested_mounts="$(printf '/\n%s\n' "$mounted")"
  if run_mount_check "$TMP/good/data" "$nested_mounts"; then
    echo "nested data mount unexpectedly accepted: $mounted" >&2
    exit 1
  fi
done
if run_mount_check "$TMP/good/data" "/" 1; then
  echo "mount table failure unexpectedly accepted for destructive wipe" >&2
  exit 1
fi

echo "Agent data-directory symlink, traversal, and nested-mount safety tests passed."
