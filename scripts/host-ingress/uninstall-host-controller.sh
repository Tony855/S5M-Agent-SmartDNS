#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo '请使用 root 运行' >&2; exit 1; }
DEST=/usr/local/libexec/s5m-agent-ingress
NETWORK_CONFIG=/etc/s5m-agent-ingress/network.json

# Detach the routed endpoint before removing its firewall. If the network
# config/helper is missing or the network has unexpected attachments, abort
# while the source-CIDR firewall remains installed.
if [[ -e "$NETWORK_CONFIG" ]]; then
  [[ -f "$NETWORK_CONFIG" && ! -L "$NETWORK_CONFIG" ]] || { echo "拒绝使用不安全的 routed network 配置：$NETWORK_CONFIG" >&2; exit 1; }
  [[ -x "$DEST/network-lifecycle.py" ]] || { echo "缺少 network lifecycle helper；保留防火墙，拒绝卸载" >&2; exit 1; }
  "$DEST/network-lifecycle.py" uninstall --config "$NETWORK_CONFIG"
else
  command -v docker >/dev/null 2>&1 || { echo "无法检查 Docker ingress network；保留防火墙，拒绝卸载" >&2; exit 1; }
  managed_networks="$(docker network ls --filter label=com.s5m.managed=s5m-agent-dns-ingress --format '{{.Name}}')" || { echo "无法检查受管 Docker ingress network；保留防火墙，拒绝卸载" >&2; exit 1; }
  [[ -z "$managed_networks" ]] || { echo "发现受管 routed network 但缺少 $NETWORK_CONFIG；保留防火墙并先恢复 network 配置" >&2; exit 1; }
fi

if systemctl is-active --quiet s5m-agent-ingress.timer || systemctl is-enabled --quiet s5m-agent-ingress.timer; then
  systemctl disable --now s5m-agent-ingress.timer
fi
systemctl stop s5m-agent-ingress.service 2>/dev/null || true
if [[ -x "$DEST/controller.py" ]]; then
  "$DEST/controller.py" remove
fi
rm -f /etc/systemd/system/s5m-agent-ingress.timer /etc/systemd/system/s5m-agent-ingress.service
systemctl daemon-reload
rm -f "$DEST/controller.py"
rmdir "$DEST" 2>/dev/null || true
echo 'S5M host firewall controller removed after routed Docker ingress was detached; config and router routes were retained.'
if [[ -x "$DEST/network-lifecycle.py" ]]; then
  echo 'The standalone network lifecycle helper was retained for future provisioning.'
fi
