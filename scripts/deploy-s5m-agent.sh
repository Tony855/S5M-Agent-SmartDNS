#!/usr/bin/env bash
# /scripts/deploy-s5m-agent.sh
# 一键重建 s5m-agent（SmartDNS）容器
set -euo pipefail

# ================= 可修改配置 =================
CONTAINER_NAME="s5m-agent"
IMAGE="ghcr.io/tony855/s5m-agent-smartdns:dev"
DATA_DIR="/opt/s5m-agent/data"
TZ_VAL="Asia/Shanghai"
RESTART_POLICY="unless-stopped"

# 80 端口对外（Web UI），7890 只绑定宿主机回环，避免公网开放代理被滥用
# 外部机器需要用 7890 时，走 SSH 隧道：
#   ssh -L 7890:127.0.0.1:7890 root@<VPS_IP>
PORT_MAP=(
  "-p" "80:80/tcp"
  "-p" "127.0.0.1:7890:7890/tcp"
  "-p" "127.0.0.1:7890:7890/udp"
)

# 如需启用 TUN 透明代理，取消下面两行注释（宿主机需存在 /dev/net/tun）
# DEVICE_MAP=(
#   "--cap-add" "NET_ADMIN"
#   "--device" "/dev/net/tun"
# )
DEVICE_MAP=()

EXTRA_ENVS=()

# true = 彻底全新安装：删容器 + 删本地镜像（强制重拉）+ 删数据目录
# false = 走下面的 WIPE_DATA / CLEAN_LEGACY_IMAGES 细粒度控制
FULL_RESET="${FULL_RESET:-true}"

# 仅 FULL_RESET=false 时生效
WIPE_DATA="${WIPE_DATA:-true}"
CLEAN_LEGACY_IMAGES="${CLEAN_LEGACY_IMAGES:-false}"
# ==============================================

# FULL_RESET 强制覆盖细粒度开关
if [[ "$FULL_RESET" == "true" ]]; then
  WIPE_DATA="true"
fi

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }

# ---------- 0. 环境检查 ----------
if [[ $EUID -ne 0 ]]; then
  err "请用 root 运行"; exit 1
fi
command -v docker >/dev/null 2>&1 || { err "未找到 docker，请先安装"; exit 1; }
docker info >/dev/null 2>&1 || { err "docker 守护进程未运行"; exit 1; }

# ---------- 1. 停止并删除旧容器 ----------
if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  log "停止旧容器 $CONTAINER_NAME"
  docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
  log "删除旧容器 $CONTAINER_NAME"
  docker rm "$CONTAINER_NAME" >/dev/null 2>&1 || true
else
  warn "容器 $CONTAINER_NAME 不存在，跳过"
fi

# ---------- 2. 清理旧镜像 ----------
if [[ "$FULL_RESET" == "true" ]]; then
  log "删除本地镜像 ${IMAGE}（强制重新拉取）"
  if docker rmi -f "$IMAGE" >/dev/null 2>&1; then
    log "已删除本地镜像"
  else
    warn "删除镜像失败（可能被其他容器引用），继续尝试拉取"
  fi
fi

log "清理 dangling 镜像（<none>）"
docker image prune -f >/dev/null 2>&1 || true

if [[ "$CLEAN_LEGACY_IMAGES" == "true" ]]; then
  log "清理旧仓库 s5m-agent:local / s5m-agent:amd64-test"
  docker rmi -f s5m-agent:local s5m-agent:amd64-test >/dev/null 2>&1 || true
fi

# ---------- 3. 处理数据目录 ----------
if [[ "$WIPE_DATA" == "true" ]]; then
  if [[ -d "$DATA_DIR" ]]; then
    log "删除旧数据目录 $DATA_DIR"
    rm -rf "$DATA_DIR"
  fi
else
  warn "保留现有数据目录 $DATA_DIR"
fi
mkdir -p "$DATA_DIR"

# ---------- 4. 拉取最新镜像 ----------
log "拉取镜像 $IMAGE"
docker pull "$IMAGE"

# ---------- 5. 启动新容器 ----------
log "启动容器 $CONTAINER_NAME"
docker run -d \
  --name "$CONTAINER_NAME" \
  --restart "$RESTART_POLICY" \
  "${PORT_MAP[@]}" \
  ${DEVICE_MAP[@]+"${DEVICE_MAP[@]}"} \
  -v "$DATA_DIR:/data" \
  -e TZ="$TZ_VAL" \
  ${EXTRA_ENVS[@]+"${EXTRA_ENVS[@]}"} \
  "$IMAGE" >/dev/null

# ---------- 6. 验证 ----------
log "等待容器启动..."
sleep 5

log "当前状态："
docker ps --filter "name=^/${CONTAINER_NAME}$"

log "端口绑定（确认 7890 只在 127.0.0.1）："
docker port "$CONTAINER_NAME" || true

HEALTH="$(docker inspect "$CONTAINER_NAME" \
  --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}')"
log "Health: $HEALTH"

log "镜像 digest（确认是刚拉下来的最新版）："
docker image inspect "$IMAGE" --format '  {{.Id}}  {{index .RepoDigests 0}}' || true

log "最近 50 行日志："
docker logs --tail=50 "$CONTAINER_NAME" 2>&1 || true

log "监听端口："
ss -lntup 2>/dev/null | grep -E ':(80|7890|6053)\b' || echo "  （无匹配，稍后再查看）"

log "完成。数据目录：$DATA_DIR"
log "常用命令："
echo "  docker logs -f $CONTAINER_NAME"
echo "  docker restart $CONTAINER_NAME"
echo "  docker inspect $CONTAINER_NAME --format '{{.State.Health.Status}}'"
echo "  docker port $CONTAINER_NAME"
