#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG_FILE="${CONFIG_FILE:-/etc/default/s5m-agent-smartdns}"

log() { printf '[S5M-Agent] %s\n' "$*"; }
die() { printf '[S5M-Agent][ERROR] %s\n' "$*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || die "请使用 root 运行。"
command -v docker >/dev/null 2>&1 || die "未检测到 Docker，请先安装并启动 Docker。"

# 首次运行生成可编辑配置；随后继续使用默认值完成首次部署。
if [[ ! -f "$CONFIG_FILE" ]]; then
  install -d -m 0755 "$(dirname "$CONFIG_FILE")"
  cat >"$CONFIG_FILE" <<'CONFIG'
# S5M-Agent-SmartDNS 一键部署配置
IMAGE="ghcr.io/tony855/s5m-agent-smartdns:dev"
CONTAINER_NAME="s5m-agent"
S5M_HOSTNAME=""
BIND_IP="0.0.0.0"
WEB_PORT="80"
# 代理端口默认不映射，避免意外暴露无认证代理。确认认证/来源 IP 白名单后再设为 7890。
PROXY_PORT="0"
# SmartDNS 容器内部端口为 6053；默认不对宿主机发布。
DNS_PORT="0"
DATA_DIR="/opt/s5m-agent/data"
RESTART_POLICY="unless-stopped"
ENABLE_TUN="0"
# 可选 Docker env-file；只填写镜像实际支持的环境变量。留空表示不额外注入。
EXTRA_ENV_FILE=""
PULL_IMAGE="1"
CONFIG
  chmod 600 "$CONFIG_FILE"
  log "已生成配置文件：$CONFIG_FILE"
fi

# shellcheck disable=SC1090
source "$CONFIG_FILE"

IMAGE="${IMAGE:-ghcr.io/tony855/s5m-agent-smartdns:dev}"
CONTAINER_NAME="${CONTAINER_NAME:-s5m-agent}"
S5M_HOSTNAME="${S5M_HOSTNAME:-$(hostname)}"
BIND_IP="${BIND_IP:-0.0.0.0}"
WEB_PORT="${WEB_PORT:-80}"
PROXY_PORT="${PROXY_PORT:-0}"
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
[[ "$ENABLE_TUN" == "0" || "$ENABLE_TUN" == "1" ]] || die "ENABLE_TUN 只能是 0 或 1。"
[[ "$PULL_IMAGE" == "0" || "$PULL_IMAGE" == "1" ]] || die "PULL_IMAGE 只能是 0 或 1。"
[[ "$BIND_IP" =~ ^[0-9a-fA-F:.]+$ ]] || die "BIND_IP 格式不正确。"
[[ "$RESTART_POLICY" =~ ^(no|always|unless-stopped|on-failure(:[0-9]+)?)$ ]] || die "RESTART_POLICY 不合法。"

if [[ -n "$EXTRA_ENV_FILE" && ! -f "$EXTRA_ENV_FILE" ]]; then
  die "EXTRA_ENV_FILE 指定的文件不存在：$EXTRA_ENV_FILE"
fi
if [[ "$ENABLE_TUN" == "1" && ! -c /dev/net/tun ]]; then
  die "已启用 TUN，但宿主机不存在字符设备 /dev/net/tun。"
fi

install -d -m 0755 "$DATA_DIR"

if [[ "$PULL_IMAGE" == "1" ]]; then
  log "拉取镜像：$IMAGE"
  docker pull "$IMAGE"
fi

args=(run -d --name "$CONTAINER_NAME" --restart "$RESTART_POLICY")
args+=(-e "S5M_HOSTNAME=$S5M_HOSTNAME")
args+=(-v "$DATA_DIR:/data")
[[ -n "$EXTRA_ENV_FILE" ]] && args+=(--env-file "$EXTRA_ENV_FILE")

if (( WEB_PORT > 0 )); then
  args+=(-p "$BIND_IP:$WEB_PORT:80/tcp")
fi
if (( PROXY_PORT > 0 )); then
  args+=(-p "$BIND_IP:$PROXY_PORT:7890/tcp")
fi
if (( DNS_PORT > 0 )); then
  args+=(-p "$BIND_IP:$DNS_PORT:6053/tcp" -p "$BIND_IP:$DNS_PORT:6053/udp")
fi
if [[ "$ENABLE_TUN" == "1" ]]; then
  args+=(--cap-add NET_ADMIN --device /dev/net/tun:/dev/net/tun)
fi

# 只替换同名容器，不删除镜像和持久化数据目录。
if docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
  log "移除旧容器（保留数据目录）：$CONTAINER_NAME"
  docker rm -f "$CONTAINER_NAME" >/dev/null
fi

# 注意：不要添加 --init。该镜像以 s6-overlay /init 作为 PID 1。
args+=("$IMAGE")
log "启动容器：$CONTAINER_NAME"
docker "${args[@]}"

log "等待容器健康检查..."
for _ in $(seq 1 60); do
  state="$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || true)"
  health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CONTAINER_NAME" 2>/dev/null || true)"
  if [[ "$state" == "running" && ( "$health" == "healthy" || "$health" == "none" ) ]]; then
    log "容器已运行；health=$health"
    break
  fi
  if [[ "$state" == "exited" || "$state" == "dead" || "$health" == "unhealthy" ]]; then
    docker logs --tail 100 "$CONTAINER_NAME" || true
    die "容器启动失败，请检查上方日志。"
  fi
  sleep 2
done

state="$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || true)"
health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CONTAINER_NAME" 2>/dev/null || true)"
[[ "$state" == "running" ]] || { docker logs --tail 100 "$CONTAINER_NAME" || true; die "容器未能保持运行。"; }
[[ "$health" != "unhealthy" ]] || { docker logs --tail 100 "$CONTAINER_NAME" || true; die "容器健康检查失败。"; }

printf '\n===== 容器状态 =====\n'
docker ps --filter "name=^/${CONTAINER_NAME}$" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
printf '\n===== 已发布端口 =====\n'
docker port "$CONTAINER_NAME" || true
printf '\n===== 最近日志 =====\n'
docker logs --tail 40 "$CONTAINER_NAME" || true
printf '\n配置文件：%s\n数据目录：%s\n' "$CONFIG_FILE" "$DATA_DIR"
log "部署流程完成。"
