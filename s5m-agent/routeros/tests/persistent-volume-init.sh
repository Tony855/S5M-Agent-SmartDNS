#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)"
INIT="$ROOT/s5m-agent/routeros/cont-init.d/10-mihomo-config"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
printf '#!/bin/sh\nexit 0\n' > "$TMP/mihomo.initial"
chmod 0755 "$TMP/mihomo.initial"
printf 'secret: test-secret\n' > "$TMP/default-config.yaml"

run_init() {
  MIHOMO_HOME="$1" MIHOMO_INITIAL_BIN="$TMP/mihomo.initial" \
    DEFAULT_CONFIG_PATH="$TMP/default-config.yaml" sh "$INIT"
}

DATA="$TMP/data"
mkdir -p "$DATA"
printf 'attacker-controlled sentinel\n' > "$TMP/sentinel"
ln -s "$TMP/sentinel" "$DATA/bin/mihomo.tmp.$"
run_init "$DATA"
test -x "$DATA/bin/mihomo"
test "$(stat -c '%a' "$DATA/bin/mihomo")" = 700
test "$(stat -c '%a' "$DATA/config.yaml")" = 600
test "$(cat "$TMP/sentinel")" = "attacker-controlled sentinel"
test -L "$DATA/bin/mihomo.tmp.$"
if find "$DATA/bin" -maxdepth 1 -type f -name 'mihomo.tmp.*' | grep -q .; then
  echo "kernel temporary file was not cleaned up" >&2
  exit 1
fi

chmod 0644 "$DATA/config.yaml"
run_init "$DATA"
test "$(stat -c '%a' "$DATA/config.yaml")" = 600

BAD_CONFIG="$TMP/bad-config"
mkdir -p "$BAD_CONFIG/bin"
ln -s "$TMP/sentinel" "$BAD_CONFIG/config.yaml"
if run_init "$BAD_CONFIG"; then
  echo "symlinked config unexpectedly accepted" >&2
  exit 1
fi
test "$(cat "$TMP/sentinel")" = "attacker-controlled sentinel"

BAD_BIN="$TMP/bad-bin"
mkdir -p "$BAD_BIN/bin"
ln -s "$TMP/sentinel" "$BAD_BIN/bin/mihomo"
if run_init "$BAD_BIN"; then
  echo "symlinked kernel unexpectedly accepted" >&2
  exit 1
fi
BAD_BACKUP="$TMP/bad-backup"
mkdir -p "$BAD_BACKUP/bin"
ln -s "$TMP/sentinel" "$BAD_BACKUP/bin/mihomo.previous"
if run_init "$BAD_BACKUP"; then
  echo "symlinked rollback binary unexpectedly accepted" >&2
  exit 1
fi


BAD_DIR="$TMP/bad-dir"
mkdir -p "$BAD_DIR"
ln -s "$TMP/outside" "$BAD_DIR/bin"
if run_init "$BAD_DIR"; then
  echo "symlinked bin directory unexpectedly accepted" >&2
  exit 1
fi
test ! -e "$TMP/outside"

echo "RouterOS persistent-volume initialization security tests passed."
