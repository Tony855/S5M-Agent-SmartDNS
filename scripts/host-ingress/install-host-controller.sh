#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo '请使用 root 运行' >&2; exit 1; }
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEST=/usr/local/libexec/s5m-agent-ingress
CONFIG=${S5M_INGRESS_CONFIG:-/etc/s5m-agent-ingress/config.json}
[[ -f "$CONFIG" && ! -L "$CONFIG" ]] || { echo "缺少安全配置文件：$CONFIG（请先按文档创建）" >&2; exit 1; }

# Validate the administrator-supplied config before changing host files or
# installing units. The validator also checks root ownership and parent safety.
python3 "$ROOT/controller.py" check --config "$CONFIG"
chmod 0600 "$CONFIG"

install -d -o root -g root -m 0755 "$DEST" /etc/s5m-agent-ingress /run/s5m-agent-ingress
install -o root -g root -m 0755 "$ROOT/controller.py" "$DEST/controller.py"
install -o root -g root -m 0644 "$ROOT/s5m-agent-ingress.service" /etc/systemd/system/s5m-agent-ingress.service
install -o root -g root -m 0644 "$ROOT/s5m-agent-ingress.timer" /etc/systemd/system/s5m-agent-ingress.timer
systemctl daemon-reload
systemctl enable --now s5m-agent-ingress.timer
systemctl start s5m-agent-ingress.service
systemctl --no-pager --full status s5m-agent-ingress.timer
