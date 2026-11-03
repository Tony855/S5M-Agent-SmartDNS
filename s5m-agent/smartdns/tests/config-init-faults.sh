#!/bin/sh
set -eu

SCRIPT="${1:-s5m-agent/smartdns/cont-init.d/20-smartdns-config}"
SCRIPT="$(cd "$(dirname "$SCRIPT")" && pwd)/$(basename "$SCRIPT")"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
BIN="$ROOT/bin"
mkdir -p "$BIN"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }
run_init() {
  SMARTDNS_CONFIG_PATH="$ROOT/data/smartdns.conf" \
  SMARTDNS_DEFAULT_CONFIG="$ROOT/default/smartdns.conf" \
  PATH="$BIN:$PATH" sh "$SCRIPT"
}
reset_case() {
  rm -rf "$ROOT/data" "$ROOT/default" "$BIN"
  mkdir -p "$ROOT/data" "$ROOT/default" "$BIN"
  printf 'server 1.1.1.1\n' > "$ROOT/default/smartdns.conf"
  chmod 0644 "$ROOT/default/smartdns.conf"
}

reset_case
rm "$ROOT/default/smartdns.conf"
if run_init >/dev/null 2>&1; then fail "missing default config must fail"; fi
[ ! -e "$ROOT/data/smartdns.conf" ] || fail "missing default created destination"
pass "missing default config fails closed"

reset_case
: > "$ROOT/default/smartdns.conf"
if run_init >/dev/null 2>&1; then fail "empty default config must fail"; fi
[ ! -e "$ROOT/data/smartdns.conf" ] || fail "empty default created destination"
pass "empty default config fails closed"

reset_case
printf 'do-not-touch\n' > "$ROOT/data/target.conf"
ln -s "$ROOT/data/target.conf" "$ROOT/data/smartdns.conf"
if run_init >/dev/null 2>&1; then fail "symlink config path must fail"; fi
[ -L "$ROOT/data/smartdns.conf" ] || fail "symlink config path was replaced"
[ "$(cat "$ROOT/data/target.conf")" = "do-not-touch" ] || fail "symlink target was modified"
pass "symlink config path is rejected without touching its target"

reset_case
rm -rf "$ROOT/data/smartdns.conf"
mkdir "$ROOT/data/smartdns.conf"
if run_init >/dev/null 2>&1; then fail "directory config path must fail"; fi
[ -d "$ROOT/data/smartdns.conf" ] || fail "directory config path was replaced"
pass "non-regular config path is rejected"
reset_case
cat > "$BIN/cp" <<'WRAPPER'
#!/bin/sh
[ "${FAIL_CP:-0}" = 1 ] && exit 73
exec /bin/cp "$@"
WRAPPER
chmod +x "$BIN/cp"
if FAIL_CP=1 run_init >/dev/null 2>&1; then fail "copy failure must fail"; fi
[ ! -e "$ROOT/data/smartdns.conf" ] || fail "copy failure left destination"
[ -z "$(find "$ROOT/data" -maxdepth 1 -name "smartdns.conf.tmp.*" -print -quit)" ] || fail "copy failure left temp file"
pass "copy failure cleans staging file and fails"

reset_case
cat > "$BIN/mv" <<'WRAPPER'
#!/bin/sh
[ "${FAIL_MV:-0}" = 1 ] && exit 74
exec /bin/mv "$@"
WRAPPER
chmod +x "$BIN/mv"
: > "$ROOT/data/smartdns.conf"
if FAIL_MV=1 run_init >/dev/null 2>&1; then fail "atomic rename failure must fail"; fi
[ -f "$ROOT/data/smartdns.conf" ] || fail "rename failure removed existing destination"
[ ! -s "$ROOT/data/smartdns.conf" ] || fail "rename failure replaced destination"
[ -z "$(find "$ROOT/data" -maxdepth 1 -name "smartdns.conf.tmp.*" -print -quit)" ] || fail "rename failure left temp file"
pass "atomic rename failure leaves original destination untouched"

reset_case
run_init || fail "initialization should succeed"
cmp -s "$ROOT/default/smartdns.conf" "$ROOT/data/smartdns.conf" || fail "default content mismatch"
[ "$(stat -c %a "$ROOT/data/smartdns.conf")" = 600 ] || fail "new config mode is not 0600"
[ -z "$(find "$ROOT/data" -maxdepth 1 -name "smartdns.conf.tmp.*" -print -quit)" ] || fail "successful init left temp file"
pass "successful initialization installs complete 0600 config"

reset_case
printf 'operator-owned-config\n' > "$ROOT/data/smartdns.conf"
chmod 0644 "$ROOT/data/smartdns.conf"
run_init || fail "existing config should be retained"
[ "$(cat "$ROOT/data/smartdns.conf")" = "operator-owned-config" ] || fail "operator config overwritten"
[ "$(stat -c %a "$ROOT/data/smartdns.conf")" = 600 ] || fail "existing config mode not hardened"
pass "existing operator config is preserved and permissions hardened"

reset_case
cat > "$BIN/cp" <<'WRAPPER'
#!/bin/sh
[ "${FAIL_CP:-0}" = 1 ] && exit 73
exec /bin/cp "$@"
WRAPPER
chmod +x "$BIN/cp"
if FAIL_CP=1 run_init >/dev/null 2>&1; then fail "injected failure unexpectedly succeeded"; fi
run_init || fail "initializer did not recover after transient failure"
[ "$(stat -c %a "$ROOT/data/smartdns.conf")" = 600 ] || fail "recovered config mode incorrect"
pass "retry after transient initialization failure recovers cleanly"

echo "All SmartDNS config initialization fault-injection tests passed."
