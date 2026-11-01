#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG_FILE="${CONFIG_FILE:-/etc/default/s5m-agent-smartdns}"

log() { printf '[S5M-Agent] %s\n' "$*"; }
die() { printf '[S5M-Agent][ERROR] %s\n' "$*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || die "请使用 root 运行。"
command -v docker >/dev/null 2>&1 || die "未检测到 Docker，请先安装并启动 Docker。"

if [[ -L "$CONFIG_FILE" ]]; then
  die "配置文件不能是符号链接：$CONFIG_FILE"
fi
if [[ ! -e "$CONFIG_FILE" ]]; then
  install -d -m 0755 "$(dirname "$CONFIG_FILE")"
  cat >"$CONFIG_FILE" <<'CONFIG'
# S5M-Agent-SmartDNS 一键部署配置
IMAGE="ghcr.io/tony855/s5m-agent-smartdns:dev"
CONTAINER_NAME="s5m-agent"
S5M_HOSTNAME=""
BIND_IP="0.0.0.0"
WEB_PORT="80"
# 代理端口默认不映射；启用时默认只绑定本机回环地址。
PROXY_PORT="0"
PROXY_BIND_IP="127.0.0.1"
# SmartDNS 容器内部端口为 6053；默认不对宿主机发布。
DNS_PORT="0"
DATA_DIR="/opt/s5m-agent/data"
RESTART_POLICY="unless-stopped"
ENABLE_TUN="0"
EXTRA_ENV_FILE=""
PULL_IMAGE="1"
CONFIG
  chmod 600 "$CONFIG_FILE"
  log "已生成配置文件：$CONFIG_FILE"
fi
[[ -f "$CONFIG_FILE" ]] || die "配置路径不是普通文件：$CONFIG_FILE"
chmod 600 "$CONFIG_FILE"

# shellcheck disable=SC1090
source "$CONFIG_FILE"

IMAGE="${IMAGE:-ghcr.io/tony855/s5m-agent-smartdns:dev}"
CONTAINER_NAME="${CONTAINER_NAME:-s5m-agent}"
S5M_HOSTNAME="${S5M_HOSTNAME:-$(hostname)}"
BIND_IP="${BIND_IP:-0.0.0.0}"
WEB_PORT="${WEB_PORT:-80}"
PROXY_PORT="${PROXY_PORT:-0}"
# Legacy config files without PROXY_BIND_IP retain their previous BIND_IP behavior.
PROXY_BIND_IP="${PROXY_BIND_IP:-$BIND_IP}"
DNS_PORT="${DNS_PORT:-0}"
DATA_DIR="${DATA_DIR:-/opt/s5m-agent/data}"
RESTART_POLICY="${RESTART_POLICY:-unless-stopped}"
ENABLE_TUN="${ENABLE_TUN:-0}"
EXTRA_ENV_FILE="${EXTRA_ENV_FILE:-}"
PULL_IMAGE="${PULL_IMAGE:-1}"

valid_port() {
  local p="$1" name="$2"
  [[ "$p" =~ ^[0-9]+$ ]] || die "$name 必须是 0-65535 的整数。"
  (( p >= 0 && p <= 65535 )) || die "$name 超出范围。"
}
valid_port "$WEB_PORT" WEB_PORT
valid_port "$PROXY_PORT" PROXY_PORT
valid_port "$DNS_PORT" DNS_PORT
[[ -n "$IMAGE" && -n "$CONTAINER_NAME" && -n "$DATA_DIR" ]] || die "IMAGE、CONTAINER_NAME、DATA_DIR 不能为空。"
[[ "$CONTAINER_NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || die "CONTAINER_NAME 格式不合法。"
[[ "$ENABLE_TUN" == "0" || "$ENABLE_TUN" == "1" ]] || die "ENABLE_TUN 只能是 0 或 1。"
[[ "$PULL_IMAGE" == "0" || "$PULL_IMAGE" == "1" ]] || die "PULL_IMAGE 只能是 0 或 1。"
[[ "$BIND_IP" =~ ^[0-9a-fA-F:.]+$ ]] || die "BIND_IP 格式不正确。"
if (( PROXY_PORT > 0 )); then
  [[ "$PROXY_BIND_IP" =~ ^[0-9a-fA-F:.]+$ ]] || die "PROXY_BIND_IP 格式不正确。"
fi
[[ "$RESTART_POLICY" =~ ^(no|always|unless-stopped|on-failure(:[0-9]+)?)$ ]] || die "RESTART_POLICY 不合法。"

if [[ -n "$EXTRA_ENV_FILE" ]]; then
  [[ -f "$EXTRA_ENV_FILE" && ! -L "$EXTRA_ENV_FILE" ]] || die "EXTRA_ENV_FILE 必须指向普通文件且不能是符号链接。"
  chmod 600 "$EXTRA_ENV_FILE"
fi
if [[ "$ENABLE_TUN" == "1" && ! -c /dev/net/tun ]]; then
  die "已启用 TUN，但宿主机不存在字符设备 /dev/net/tun。"
fi

install -d -m 0700 "$DATA_DIR"
if [[ "$PULL_IMAGE" == "1" ]]; then
  log "拉取镜像：$IMAGE"
  docker pull "$IMAGE"
fi

BIND_ADDR="$BIND_IP"
[[ "$BIND_IP" == *:* ]] && BIND_ADDR="[$BIND_IP]"
PROXY_BIND_ADDR="$PROXY_BIND_IP"
[[ "$PROXY_BIND_IP" == *:* ]] && PROXY_BIND_ADDR="[$PROXY_BIND_IP]"
args=(run -d --name "$CONTAINER_NAME" --restart "$RESTART_POLICY")
args+=(-e "S5M_HOSTNAME=$S5M_HOSTNAME" -v "$DATA_DIR:/data")
[[ -n "$EXTRA_ENV_FILE" ]] && args+=(--env-file "$EXTRA_ENV_FILE")
(( WEB_PORT > 0 )) && args+=(-p "$BIND_ADDR:$WEB_PORT:80/tcp")
(( PROXY_PORT > 0 )) && args+=(-p "$PROXY_BIND_ADDR:$PROXY_PORT:7890/tcp")
if (( DNS_PORT > 0 )); then
  args+=(-p "$BIND_ADDR:$DNS_PORT:6053/tcp" -p "$BIND_ADDR:$DNS_PORT:6053/udp")
fi
if [[ "$ENABLE_TUN" == "1" ]]; then
  args+=(--cap-add NET_ADMIN --device /dev/net/tun:/dev/net/tun)
fi

# 保留旧容器直到新容器通过启动检查；失败时自动恢复旧容器。
BACKUP_NAME="${CONTAINER_NAME}.rollback.$$"
HAD_OLD=0
NEW_STARTED=0
DEPLOY_OK=0
ROLLBACK_ARMED=0
restore_previous() {
  if (( NEW_STARTED )); then
    if docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
      docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || { log "错误：无法移除失败的新容器；保留旧容器备份 $BACKUP_NAME"; return 1; }
    fi
    NEW_STARTED=0
  fi
  if (( HAD_OLD )); then
    docker container inspect "$BACKUP_NAME" >/dev/null 2>&1 || { log "错误：找不到旧容器备份 $BACKUP_NAME；不会启动其他容器"; return 1; }
    docker rename "$BACKUP_NAME" "$CONTAINER_NAME" >/dev/null 2>&1 || { log "错误：无法恢复旧容器名称；备份仍保留：$BACKUP_NAME"; return 1; }
    HAD_OLD=0
    docker start "$CONTAINER_NAME" >/dev/null 2>&1 || { log "错误：旧容器已恢复名称但启动失败：$CONTAINER_NAME"; return 1; }
    log "已恢复原容器：$CONTAINER_NAME"
  fi
}
rollback_on_exit() { local status=$?; if (( DEPLOY_OK == 0 && ROLLBACK_ARMED == 1 )); then restore_previous || log "警告：自动回滚未能完整完成，请检查 $BACKUP_NAME"; fi; return "$status"; }
trap rollback_on_exit EXIT
deployment_failed() { local message="$1"; docker logs --tail 100 "$CONTAINER_NAME" 2>/dev/null || true; restore_previous || true; ROLLBACK_ARMED=0; die "$message"; }

if docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
  HAD_OLD=1
  log "暂存旧容器：$CONTAINER_NAME"
  docker stop "$CONTAINER_NAME" >/dev/null || die "停止旧容器失败，未替换现有服务。"
  if ! docker rename "$CONTAINER_NAME" "$BACKUP_NAME"; then
    docker start "$CONTAINER_NAME" >/dev/null 2>&1 || true
    HAD_OLD=0
    die "暂存旧容器失败，已取消部署。"
  fi
fi
ROLLBACK_ARMED=1

# 不要添加 --init：镜像使用 s6-overlay 的 /init 作为 PID 1。
args+=("$IMAGE")
log "启动新容器：$CONTAINER_NAME"
# docker run 失败时也可能留下已创建的容器，因此提前启用清理回滚。
NEW_STARTED=1
if ! docker "${args[@]}"; then
  deployment_failed "新容器创建失败，已回滚旧容器（如存在）。"
fi
NEW_STARTED=1

log "等待容器启动检查（最多 120 秒）..."
ready=0
for _ in $(seq 1 60); do
  state="$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || true)"
  health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CONTAINER_NAME" 2>/dev/null || true)"
  if [[ "$state" == "running" && ( "$health" == "healthy" || "$health" == "none" ) ]]; then
    ready=1
    break
  fi
  if [[ "$state" == "exited" || "$state" == "dead" || "$health" == "unhealthy" ]]; then
    deployment_failed "新容器启动或健康检查失败，已回滚旧容器（如存在）。"
  fi
  sleep 2
done
(( ready == 1 )) || deployment_failed "等待新容器启动超时，已回滚旧容器（如存在）。"

DEPLOY_OK=1
ROLLBACK_ARMED=0
if (( HAD_OLD )); then
  if docker rm "$BACKUP_NAME" >/dev/null; then HAD_OLD=0; else log "警告：新容器已运行，但旧容器暂存项未能删除：$BACKUP_NAME"; fi
fi

printf '\n===== 容器状态 =====\n'
docker ps --filter "name=^/${CONTAINER_NAME}$" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
printf '\n===== 已发布端口 =====\n'
docker port "$CONTAINER_NAME" || true
printf '\n===== 最近日志 =====\n'
docker logs --tail 40 "$CONTAINER_NAME" || true
printf '\n配置文件：%s\n数据目录：%s\n' "$CONFIG_FILE" "$DATA_DIR"
log "部署流程完成。"
