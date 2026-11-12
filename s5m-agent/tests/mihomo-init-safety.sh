#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)"
INIT="$ROOT/s5m-agent/cont-init.d/10-mihomo-config"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

printf 'secret: test-secret\n' > "$TMP/default.yaml"
chmod 0644 "$TMP/default.yaml"
printf '#!/bin/sh\nexit 0\n' > "$TMP/mihomo"
chmod 0755 "$TMP/mihomo"
printf '#!/bin/sh\n[ "$1" = "--recover-config-transaction-before-services" ] || exit 2\nexit 0\n' > "$TMP/s5m-agent-stub"
chmod 0755 "$TMP/s5m-agent-stub"
export S5M_AGENT_BINARY="$TMP/s5m-agent-stub"

run_init() {
  MIHOMO_HOME="$1" \
  MIHOMO_BIN="$TMP/mihomo-installed" \
  DEFAULT_CONFIG_PATH="$TMP/default.yaml" \
  LEGACY_CONFIG_PATH="$TMP/legacy/config.yaml" \
    sh "$INIT"
}

# First boot creates a private config using an exclusive same-directory temp file.
DATA="$TMP/data"
mkdir -p "$DATA"
run_init "$DATA"
test -f "$DATA/config.yaml"
test "$(stat -c '%a' "$DATA/config.yaml")" = 600
test "$(stat -c '%a' "$DATA")" = 700
grep -q '^secret: test-secret$' "$DATA/config.yaml"

# Existing config is protected on every boot.
chmod 0644 "$DATA/config.yaml"
run_init "$DATA"
test "$(stat -c '%a' "$DATA/config.yaml")" = 600

# A symlinked data root or any symlinked parent component is rejected.
mkdir -p "$TMP/outside"
ln -s "$TMP/outside" "$TMP/data-link"
if run_init "$TMP/data-link"; then
  echo "symlinked MIHOMO_HOME unexpectedly accepted" >&2
  exit 1
fi
if run_init "$TMP/data-link/child"; then
  echo "symlinked MIHOMO_HOME parent unexpectedly accepted" >&2
  exit 1
fi
if run_init "/tmp"; then
  echo "system root-level temporary directory unexpectedly accepted" >&2
  exit 1
fi

# A symlinked config must not overwrite its target.
BAD_CONFIG="$TMP/bad-config"
mkdir -p "$BAD_CONFIG"
printf 'sentinel\n' > "$TMP/sentinel"
ln -s "$TMP/sentinel" "$BAD_CONFIG/config.yaml"
if run_init "$BAD_CONFIG"; then
  echo "symlinked config unexpectedly accepted" >&2
  exit 1
fi
test "$(cat "$TMP/sentinel")" = sentinel

# A symlinked no-SmartDNS migration backup must be rejected.
BAD_BACKUP="$TMP/bad-backup"
mkdir -p "$BAD_BACKUP"
printf 'secret: preserved\n' > "$BAD_BACKUP/config.yaml"
ln -s "$TMP/sentinel" "$BAD_BACKUP/config.yaml.pre-no-smartdns"
if run_init "$BAD_BACKUP"; then
  echo "symlinked migration backup unexpectedly accepted" >&2
  exit 1
fi
test "$(cat "$TMP/sentinel")" = sentinel

# Symlinked kernel and rollback files must not be followed.
BAD_KERNEL="$TMP/bad-kernel"
mkdir -p "$BAD_KERNEL"
if MIHOMO_HOME="$BAD_KERNEL" MIHOMO_BIN="$TMP/kernel-link" DEFAULT_CONFIG_PATH="$TMP/default.yaml" LEGACY_CONFIG_PATH="$TMP/legacy/config.yaml" sh -c 'ln -s "$1" "$2"' _ "$TMP/sentinel" "$TMP/kernel-link"; then :; fi
if MIHOMO_HOME="$BAD_KERNEL" MIHOMO_BIN="$TMP/kernel-link" DEFAULT_CONFIG_PATH="$TMP/default.yaml" LEGACY_CONFIG_PATH="$TMP/legacy/config.yaml" sh "$INIT"; then
  echo "symlinked kernel unexpectedly accepted" >&2
  exit 1
fi
rm -f "$TMP/kernel-link"
ln -s "$TMP/sentinel" "$TMP/kernel-link.previous"
if MIHOMO_HOME="$BAD_KERNEL" MIHOMO_BIN="$TMP/kernel-link" DEFAULT_CONFIG_PATH="$TMP/default.yaml" LEGACY_CONFIG_PATH="$TMP/legacy/config.yaml" sh "$INIT"; then
  echo "symlinked rollback kernel unexpectedly accepted" >&2
  exit 1
fi
test "$(cat "$TMP/sentinel")" = sentinel

echo "Mihomo persistent-volume initialization safety tests passed."
