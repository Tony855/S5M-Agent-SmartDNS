#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo '请使用 root 运行' >&2; exit 1; }
if systemctl is-active --quiet s5m-agent-ingress.timer || systemctl is-enabled --quiet s5m-agent-ingress.timer; then
  systemctl disable --now s5m-agent-ingress.timer
fi
systemctl stop s5m-agent-ingress.service 2>/dev/null || true
if [[ -x /usr/local/libexec/s5m-agent-ingress/controller.py ]]; then
  /usr/local/libexec/s5m-agent-ingress/controller.py remove
fi
rm -f /etc/systemd/system/s5m-agent-ingress.timer /etc/systemd/system/s5m-agent-ingress.service
systemctl daemon-reload
rm -f /usr/local/libexec/s5m-agent-ingress/controller.py
rmdir /usr/local/libexec/s5m-agent-ingress 2>/dev/null || true
echo 'S5M host ingress controller removed; config and Docker network/routes were retained.'
