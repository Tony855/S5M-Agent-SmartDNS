#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo '请使用 root 运行' >&2; exit 1; }
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
for cmd in python3 nft ip flock systemctl; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "缺少宿主机依赖：$cmd" >&2; exit 1; }
done
DEST=/usr/local/libexec/s5m-agent-ingress
CONFIG=/etc/s5m-agent-ingress/config.json
[[ -f "$CONFIG" && ! -L "$CONFIG" ]] || { echo "缺少安全配置文件：$CONFIG（请先按文档创建）" >&2; exit 1; }

# Validate the administrator-supplied config before changing host files or
# installing units. The validator also checks root ownership and parent safety.
python3 "$ROOT/controller.py" check --config "$CONFIG"
chmod 0600 "$CONFIG"

install -d -o root -g root -m 0755 "$DEST" /etc/s5m-agent-ingress /run/s5m-agent-ingress
python3 - /etc/s5m-agent-ingress/evidence.key <<'PY'
import os, re, secrets, stat, sys
path = sys.argv[1]
try:
    st = os.lstat(path)
except FileNotFoundError:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as stream:
        stream.write(secrets.token_hex(32) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory_fd = os.open(os.path.dirname(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(directory_fd)
    finally: os.close(directory_fd)
    st = os.lstat(path)
if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
    raise SystemExit("physical evidence HMAC key must be root-owned mode 0600; refusing unsafe key")
with open(path, "rb") as stream:
    raw = stream.read(128)
if not re.fullmatch(rb"[0-9a-f]{64}", raw.strip()):
    raise SystemExit("physical evidence HMAC key must contain 32 bytes encoded as lowercase hex")
PY
install -o root -g root -m 0755 "$ROOT/controller.py" "$DEST/controller.py"
install -o root -g root -m 0755 "$ROOT/network-lifecycle.py" "$DEST/network-lifecycle.py"
python3 -m py_compile "$DEST/controller.py" "$DEST/network-lifecycle.py"
rm -rf "$DEST/__pycache__"
install -o root -g root -m 0644 "$ROOT/s5m-agent-ingress.service" /etc/systemd/system/s5m-agent-ingress.service
install -o root -g root -m 0644 "$ROOT/s5m-agent-ingress.timer" /etc/systemd/system/s5m-agent-ingress.timer
systemctl daemon-reload
systemctl enable --now s5m-agent-ingress.timer
systemctl start s5m-agent-ingress.service
systemctl --no-pager --full status s5m-agent-ingress.timer
