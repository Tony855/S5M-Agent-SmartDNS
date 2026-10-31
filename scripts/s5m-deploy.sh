#!/usr/bin/env bash
# S5M Agent 安全部署/更新：只替换 Agent 容器，保留数据和宿主机其他 Docker 资源
set -Eeuo pipefail

IMAGE_NAME="s5m-agent-linux-amd64.tar"
IMAGE_SRC="s5m-agent:amd64-test"
IMAGE_LOCAL="s5m-agent:local"
CONTAINER="s5m-agent"
DATA_DIR="/opt/s5m-agent/data"
PORT_WEB=80
PORT_PROXY=7890

log()  { echo -e "\033[32m[+]\033[0m $*"; }
warn() { echo -e "\033[33m[!]\033[0m $*"; }
die()  { echo -e "\033[31m[x]\033[0m $*"; exit 1; }

http_get() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 5 "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- -T 5 "$url"
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$url" <<'PYHTTP'
import sys
import urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=5) as response:
        sys.stdout.write(response.read().decode("utf-8", "replace"))
except Exception as exc:
    print("HTTP probe failed: " + str(exc), file=sys.stderr)
    sys.exit(1)
PYHTTP
  else
    warn "缺少 curl、wget 和 python3，跳过 HTTP 检查"
    return 127
  fi
}

http_head() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -sSI --max-time 5 "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -S --spider -T 5 "$url" 2>&1 | grep -E 'HTTP/[0-9.]+' | head -n1
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$url" <<'PYHEAD'
import sys
import urllib.request
request = urllib.request.Request(sys.argv[1], method="HEAD")
try:
    with urllib.request.urlopen(request, timeout=5) as response:
        print("HTTP", response.status, response.reason)
except Exception as exc:
    print("HTTP HEAD probe failed: " + str(exc), file=sys.stderr)
    sys.exit(1)
PYHEAD
  else
    warn "缺少 curl、wget 和 python3，跳过 HTTP 检查"
    return 127
  fi
}

find_image_tar() {
  local dirs=("$PWD" "$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" /root /tmp)
  local d
  for d in "${dirs[@]}"; do
    [ -n "$d" ] && [ -f "$d/$IMAGE_NAME" ] && { echo "$d/$IMAGE_NAME"; return 0; }
  done
  return 1
}

if [ -z "${IMAGE_TAR:-}" ]; then
  IMAGE_TAR="$(find_image_tar)" || IMAGE_TAR=""
fi
[ -n "$IMAGE_TAR" ] && [ -f "$IMAGE_TAR" ] || \
  die "未找到 $IMAGE_NAME。可指定：IMAGE_TAR=/path/to/$IMAGE_NAME $0"
[ "$(id -u)" -eq 0 ] || die "请用 root 运行"
log "使用镜像文件：$IMAGE_TAR"

# 确保 Docker 可用；绝不执行全局容器/镜像/卷清理。
if ! command -v docker >/dev/null 2>&1 || ! docker version >/dev/null 2>&1; then
  log "未检测到可用 Docker，正在安装 docker.io ..."
  apt-get update || die "apt-get update 失败"
  DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io || die "docker.io 安装失败"
fi
systemctl enable --now docker >/dev/null 2>&1 || die "Docker 服务启动失败"

# 保留现有数据目录和 Docker/containerd 状态，只导入指定镜像。
log "加载镜像 $IMAGE_TAR（不会删除旧镜像或重启 Docker）..."
ok=0
for i in 1 2 3; do
  if docker load -i "$IMAGE_TAR"; then ok=1; break; fi
  warn "第 $i 次加载失败，3 秒后重试..."
  sleep 3
done
[ "$ok" -eq 1 ] || die "docker load 失败；检查镜像文件、磁盘空间和权限"

docker tag "$IMAGE_SRC" "$IMAGE_LOCAL" 2>/dev/null || {
  src="$(docker images --format '{{.Repository}}:{{.Tag}}' | grep '^s5m-agent' | head -n1 || true)"
  [ -n "$src" ] && docker tag "$src" "$IMAGE_LOCAL" || die "找不到 s5m-agent 镜像"
}

log "保留持久化数据目录：$DATA_DIR"
install -d -m 0700 "$DATA_DIR"

# 只替换目标 Agent 容器；不触碰其他容器、镜像、卷或网络。
if docker container inspect "$CONTAINER" >/dev/null 2>&1; then
  log "停止并移除旧 Agent 容器（仅目标容器）..."
  docker rm -f "$CONTAINER" || die "移除旧 Agent 容器失败"
fi

log "启动容器 $CONTAINER ..."
# Keep Mihomo TUN routes inside the Agent container's network namespace.
# Do not use --network host: changing the host namespace's routes can lock out SSH.
docker run -d \
  --name "$CONTAINER" \
  --restart unless-stopped \
  --network bridge \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun:/dev/net/tun \
  -p "${PORT_WEB}:80" \
  -p "${PORT_PROXY}:7890" \
  -v "$DATA_DIR":/data \
  "$IMAGE_LOCAL" || die "容器启动失败"

# Runtime guard: fail closed if Docker did not keep the Agent in bridge mode.
network_mode="$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$CONTAINER")" || die "无法核实 Agent 容器网络模式"
if [ "$network_mode" != "bridge" ]; then
  warn "Agent 网络模式异常：$network_mode；仅停止并移除本次目标容器以避免影响宿主机网络"
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  die "拒绝保留非 bridge 网络模式的 Agent 容器；宿主机 SSH 安全检查未通过"
fi
log "网络隔离检查通过：Agent 使用 bridge 网络；容器 TUN 路由不应修改宿主机路由。"

sleep 3
echo
log "===== 部署结果 ====="
docker ps --filter "name=^/${CONTAINER}$" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
echo
log "容器日志（末 20 行）："
docker logs --tail 20 "$CONTAINER" 2>&1 || true
echo
log "machine-id："
http_get "http://127.0.0.1:${PORT_WEB}/api/machine-id" || warn "API 暂无响应，请检查容器日志"
echo
log "Web 探活："
http_head "http://127.0.0.1:${PORT_WEB}" || warn "80 端口未响应"
echo
log "部署脚本执行完毕。浏览器访问：http://<服务器公网IP>"
warn "请按需确认安全组/防火墙放行 ${PORT_WEB} 和 ${PORT_PROXY}"
echo
log "查看实时日志：docker logs -f $CONTAINER（Ctrl+C 只退出日志查看）"
