#!/usr/bin/env bash
# /root/deploy-s5m-agent.sh
# 交互式管理 s5m-agent（SmartDNS + Mihomo）容器
#   用法:
#     ./deploy-s5m-agent.sh          # 进入交互菜单
#     ./deploy-s5m-agent.sh deploy   # 直接执行自动部署（兼容原脚本行为）
set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/root/.s5m-agent.conf}"

# ================= 默认配置 =================
CONTAINER_NAME="s5m-agent"
IMAGE="ghcr.io/tony855/s5m-agent-smartdns:dev"
NO_SMARTDNS_IMAGE="ghcr.io/tony855/s5m-agent:dev"
DATA_DIR="/opt/s5m-agent/data"
TZ_VAL="Asia/Shanghai"
RESTART_POLICY="unless-stopped"

# 端口映射（数组内成对出现：参数 值 参数 值 ...）
PORT_MAP=(
  "-p" "80:80/tcp"
  "-p" "127.0.0.1:7890:7890/tcp"
  "-p" "127.0.0.1:7890:7890/udp"
)

# TUN 设备映射：宿主机 /dev/net/tun → 容器 /dev/net/tun
# 缺了它，Mihomo 会报 "configure tun interface: no such file or directory"
DEVICE_MAP=(
  "--device" "/dev/net/tun:/dev/net/tun"
)

# 容器 Capability：
#   NET_ADMIN —— 创建/管理 TUN 接口、修改路由（必需）
#   NET_RAW   —— 部分底层网络操作（建议，兼容 sniffer 等场景）
CAP_ADD=(
  "--cap-add" "NET_ADMIN"
  "--cap-add" "NET_RAW"
)

# 额外环境变量（成对: -e KEY=VALUE）
EXTRA_ENVS=()

# 若存在配置文件则加载（可持久化交互式修改）
if [[ -f "${CONFIG_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${CONFIG_FILE}"
fi

# 自动部署行为（仅 deploy 模式生效）
FULL_RESET="${FULL_RESET:-false}"
WIPE_DATA="${WIPE_DATA:-false}"
CLEAN_LEGACY_IMAGES="${CLEAN_LEGACY_IMAGES:-false}"
# ============================================

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }

validate_data_dir_path() {
  local path="${DATA_DIR}" current="" component
  local -a components=()
  if [[ -z "$path" || "$path" != /* || "$path" == "/" || "$path" == */ ||
        "$path" == *"//"* || "$path" == *"/./"* || "$path" == *"/." ||
        "$path" == *"/../"* || "$path" == *"/.." ]]; then
    err "拒绝不安全的数据目录路径：${path@Q}"
    return 1
  fi
  IFS='/' read -r -a components <<< "${path#/}"
  if (("${#components[@]}" < 2)); then
    err "数据目录必须是独立子目录，拒绝使用系统根目录"
    return 1
  fi
  for component in "${components[@]}"; do
    if [[ -z "$component" || "$component" == "." || "$component" == ".." ]]; then
      err "数据目录包含不安全路径组件：${path@Q}"
      return 1
    fi
    current+="/$component"
    if [[ -L "$current" ]]; then
      err "数据目录路径包含符号链接，拒绝继续：$current"
      return 1
    fi
    if [[ -e "$current" && ! -d "$current" ]]; then
      err "数据目录路径组件不是目录：$current"
      return 1
    fi
  done
}

# Destructive data removal is never the default. Interactive users must type
# the exact target path; automation must opt in and provide the same phrase.
ensure_no_data_dir_mounts() {
  local mount_targets mount_target
  if ! command -v findmnt >/dev/null 2>&1; then
    err "无法检查数据目录挂载点，拒绝递归清理"
    return 1
  fi
  mount_targets="$(findmnt -rn -o TARGET)" || {
    err "读取系统挂载表失败，拒绝递归清理"
    return 1
  }
  while IFS= read -r mount_target; do
    case "$mount_target" in
      "$DATA_DIR"|"$DATA_DIR"/*)
        err "数据目录包含挂载点，拒绝递归清理：$mount_target"
        return 1
        ;;
    esac
  done <<< "$mount_targets"
}

confirm_data_wipe() {
  validate_data_dir_path || return 1
  ensure_no_data_dir_mounts || return 1
  local expected="DELETE:${DATA_DIR}" confirmation=""
  if [[ -t 0 ]]; then
    read -r -p "警告：将永久删除数据目录 ${DATA_DIR}。输入 ${expected} 确认：" confirmation || return 1
  else
    if [[ "${ALLOW_DATA_WIPE:-false}" != "true" ]]; then
      err "非交互模式禁止删除数据；如确需清除，必须设置 ALLOW_DATA_WIPE=true"
      return 1
    fi
    confirmation="${CONFIRM_DATA_WIPE:-}"
  fi
  if [[ "${confirmation}" != "${expected}" ]]; then
    warn "数据清理确认不匹配，已取消"
    return 1
  fi
  return 0
}

# ---------- 环境检查 ----------
require_root() {
  if [[ $EUID -ne 0 ]]; then err "请用 root 运行"; exit 1; fi
  command -v docker >/dev/null 2>&1 || { err "未找到 docker，请先安装"; exit 1; }
  docker info >/dev/null 2>&1 || { err "docker 守护进程未运行"; exit 1; }
}

# ---------- 工具函数 ----------
container_exists() {
  docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "${CONTAINER_NAME}"
}

container_status() {
  if container_exists; then
    local st hl
    st=$(docker inspect "${CONTAINER_NAME}" --format '{{.State.Status}}' 2>/dev/null || echo unknown)
    hl=$(docker inspect "${CONTAINER_NAME}" \
         --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' 2>/dev/null || echo n/a)
    echo "${st} (${hl})"
  else
    echo "未创建"
  fi
}

ports_display() {
  local out=() p
  for p in "${PORT_MAP[@]+"${PORT_MAP[@]}"}"; do
    [[ "${p}" == "-p" ]] && continue
    out+=("${p}")
  done
  if [[ ${#out[@]} -eq 0 ]]; then
    echo "（无）"
  else
    echo "${out[*]}"
  fi
}

device_display() {
  if [[ ${#DEVICE_MAP[@]} -eq 0 ]]; then
    echo "（无）"
  else
    local out=() skip=0 d
    for d in "${DEVICE_MAP[@]}"; do
      if (( skip )); then out+=("${d}"); skip=0; else skip=1; fi
    done
    echo "${out[*]}"
  fi
}

caps_display() {
  if [[ ${#CAP_ADD[@]} -eq 0 ]]; then
    echo "（无）"
  else
    local out=() skip=0 c
    for c in "${CAP_ADD[@]}"; do
      if (( skip )); then out+=("${c}"); skip=0; else skip=1; fi
    done
    echo "${out[*]}"
  fi
}

# 宿主机 TUN 设备自检（仅提示，不阻断）
check_host_tun() {
  if [[ ! -e /dev/net/tun ]]; then
    warn "宿主机未找到 /dev/net/tun（TUN 模式将不可用）"
    warn "可尝试: modprobe tun  （持久化: echo tun > /etc/modules-load.d/tun.conf）"
    return 1
  fi
  log "宿主机 /dev/net/tun 存在 ✓"
  return 0
}

# 端口占用预检（host 端口是否被其他容器占用）
check_port_conflict() {
  local spec hp owner
  for spec in "${PORT_MAP[@]+"${PORT_MAP[@]}"}"; do
    [[ "${spec}" == "-p" ]] && continue
    hp="${spec%%/*}"      # 80:80          / 127.0.0.1:7890:7890
    hp="${hp%:*}"         # 80             / 127.0.0.1:7890
    hp="${hp##*:}"        # 80             / 7890
    owner=$(docker ps --format '{{.Names}}|{{.Ports}}' | \
      awk -F'|' -v p=":${hp}->" -v me="${CONTAINER_NAME}" \
        '$1!=me && index($2,p){print $1; exit}')
    if [[ -n "${owner}" ]]; then
      err "宿主机端口 ${hp} 已被容器 ${owner} 占用"
      err "请先停止/删除 ${owner}，或修改端口映射后重试"
      return 1
    fi
  done
  return 0
}

# ---------- 配置持久化 ----------
save_config() {
  {
    echo "# s5m-agent 配置文件（由 deploy-s5m-agent.sh 自动生成）"
    echo "CONTAINER_NAME=$(printf '%q' "${CONTAINER_NAME}")"
    echo "IMAGE=$(printf '%q' "${IMAGE}")"
    echo "DATA_DIR=$(printf '%q' "${DATA_DIR}")"
    echo "TZ_VAL=$(printf '%q' "${TZ_VAL}")"
    echo "RESTART_POLICY=$(printf '%q' "${RESTART_POLICY}")"
    echo "PORT_MAP=("
    local i
    if [[ ${#PORT_MAP[@]} -gt 0 ]]; then
      for i in "${PORT_MAP[@]}"; do echo "  $(printf '%q' "${i}")"; done
    fi
    echo ")"
    echo "DEVICE_MAP=("
    if [[ ${#DEVICE_MAP[@]} -gt 0 ]]; then
      for i in "${DEVICE_MAP[@]}"; do echo "  $(printf '%q' "${i}")"; done
    fi
    echo ")"
    echo "CAP_ADD=("
    if [[ ${#CAP_ADD[@]} -gt 0 ]]; then
      for i in "${CAP_ADD[@]}"; do echo "  $(printf '%q' "${i}")"; done
    fi
    echo ")"
    echo "EXTRA_ENVS=("
    if [[ ${#EXTRA_ENVS[@]} -gt 0 ]]; then
      for i in "${EXTRA_ENVS[@]}"; do echo "  $(printf '%q' "${i}")"; done
    fi
    echo ")"
  } > "${CONFIG_FILE}"
  log "配置已保存到 ${CONFIG_FILE}"
}

# ---------- 验证 ----------
verify_container() {
  log "等待容器进入健康状态（最多 120 秒）..."
  local deadline=$((SECONDS + 120)) state="unknown" health="unknown"
  while (( SECONDS < deadline )); do
    state="$(docker inspect "${CONTAINER_NAME}" --format '{{.State.Status}}' 2>/dev/null || echo missing)"
    health="$(docker inspect "${CONTAINER_NAME}" \
      --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' 2>/dev/null || echo unknown)"
    if [[ "${state}" != "running" ]]; then
      err "新容器未处于 running 状态：${state}"
      break
    fi
    case "${health}" in
      healthy|n/a) break ;;
      unhealthy) err "新容器健康检查失败"; break ;;
      starting) sleep 2 ;;
      *) err "无法读取容器健康状态：${health}"; break ;;
    esac
  done
  if [[ "${state}" != "running" || ( "${health}" != "healthy" && "${health}" != "n/a" ) ]]; then
    err "容器启动/健康验证失败（state=${state}, health=${health}）"
    docker logs --tail=80 "${CONTAINER_NAME}" 2>&1 || true
    return 1
  fi

  log "当前状态："
  docker ps --filter "name=^/${CONTAINER_NAME}$" || true
  log "Health: ${health}"
  log "容器设备与权限："
  docker inspect "${CONTAINER_NAME}" --format \
    '  Devices: {{json .HostConfig.Devices}}
  CapAdd : {{json .HostConfig.CapAdd}}' 2>/dev/null || true
  log "镜像 digest（确认是刚拉下来的最新版）："
  docker image inspect "${IMAGE}" \
    --format '  {{.Id}}  {{index .RepoDigests 0}}' 2>/dev/null || true
  log "最近 50 行日志："
  docker logs --tail=50 "${CONTAINER_NAME}" 2>&1 || true
  log "TUN 相关日志（若有）："
  docker logs "${CONTAINER_NAME}" 2>&1 | grep -iE 'tun|error|fatal' | tail -10 || true
  log "监听端口："
  ss -lntup 2>/dev/null | grep -E ':(80|7890|6053)\b' || echo "  （无匹配，稍后再查看）"
  log "完成。数据目录：${DATA_DIR}"
  return 0
}

# ---------- 拉取镜像 ----------
do_pull() {
  log "拉取镜像 ${IMAGE}"
  docker pull "${IMAGE}"
  docker image inspect "${IMAGE}" \
    --format '  当前镜像: {{.Id}}  {{index .RepoDigests 0}}' 2>/dev/null || true
}

# 拉取并切换到独立无 SmartDNS 镜像；不触碰现有容器和数据卷
do_pull_no_smartdns() {
  log "拉取无 SmartDNS 镜像 ${NO_SMARTDNS_IMAGE}"
  if ! docker pull "${NO_SMARTDNS_IMAGE}"; then
    err "无 SmartDNS 镜像拉取失败，当前镜像选择保持不变"
    return 1
  fi

  if ! docker image inspect "${NO_SMARTDNS_IMAGE}" >/dev/null 2>&1; then
    err "镜像拉取后本地检查失败"
    return 1
  fi

  IMAGE="${NO_SMARTDNS_IMAGE}"
  log "已切换当前部署镜像为：${IMAGE}"
  save_config
  warn "当前运行中的容器不会被更改；如需使用无 SmartDNS 镜像，请执行“2) 重新部署”"
  warn "重新部署会保留 ${DATA_DIR} 中的数据"
}

# A failed docker stop must never be treated as success. Verify the
# daemon's observed state before renaming a container or deleting its data.
stop_container_checked() {
  local name="$1" state
  if ! docker stop "${name}" >/dev/null 2>&1; then
    state="$(docker inspect "${name}" --format '{{.State.Status}}' 2>/dev/null)" || {
      err "停止命令失败且无法确认容器状态：${name}"
      return 1
    }
    if [[ "${state}" != "exited" && "${state}" != "created" ]]; then
      err "停止容器失败，当前状态为 ${state}：${name}"
      return 1
    fi
  fi
  state="$(docker inspect "${name}" --format '{{.State.Status}}' 2>/dev/null)" || {
    err "停止后无法确认容器状态：${name}"
    return 1
  }
  [[ "${state}" == "exited" || "${state}" == "created" ]] || {
    err "容器仍未停止（${state}）：${name}"
    return 1
  }
}

# ---------- 重建 / 部署 ----------
restore_previous_container() {
  local backup_container="$1"
  [[ -n "${backup_container}" ]] || return 0
  if ! docker inspect "${backup_container}" >/dev/null 2>&1; then
    return 0
  fi
  warn "新容器部署失败，正在恢复旧容器 ${backup_container}"
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  if ! docker rename "${backup_container}" "${CONTAINER_NAME}"; then
    err "旧容器重命名恢复失败，请手动恢复：${backup_container}"
    return 1
  fi
  if ! docker start "${CONTAINER_NAME}" >/dev/null; then
    err "旧容器恢复启动失败，请检查容器日志"
    return 1
  fi
  log "旧容器已恢复并启动"
  return 0
}

do_recreate() {
  local remove_image="${1:-false}"
  local wipe_data="${2:-false}"
  local backup_container=""

  # Validate every existing path component before mkdir, bind-mount, or deletion.
  validate_data_dir_path || return 1

  # Confirm destructive intent before touching the current container or data.
  if [[ "${wipe_data}" == "true" ]] && ! confirm_data_wipe; then
    return 1
  fi
  if [[ ${#DEVICE_MAP[@]} -gt 0 ]]; then
    check_host_tun || warn "宿主机 TUN 不可用，Mihomo 的 TUN 模式可能无法启动（其余功能不受影响）"
  fi

  # Validate ports and pull the candidate image while the current service is
  # still running. Registry/network failure must never take the old Agent offline.
  if ! check_port_conflict; then
    err "端口预检失败，已中止"
    return 1
  fi
  log "拉取镜像 ${IMAGE}"
  if ! docker pull "${IMAGE}"; then
    err "拉取镜像失败，现有容器保持不变"
    return 1
  fi

  if [[ "${wipe_data}" == "true" ]]; then
    if container_exists; then
      log "停止并删除旧容器（已明确确认数据清除）"
      if ! stop_container_checked "${CONTAINER_NAME}"; then
        err "无法确认旧容器已停止；为保护数据，取消清理"
        return 1
      fi
      if ! docker rm "${CONTAINER_NAME}" >/dev/null 2>&1; then
        err "删除旧容器失败；为保护数据，保留数据目录并取消清理"
        return 1
      fi
      if docker inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
        err "旧容器删除后仍可被检查到；为保护数据，保留数据目录并取消清理"
        return 1
      fi
    fi
    if [[ -d "${DATA_DIR}" || -L "${DATA_DIR}" ]]; then
      log "删除旧数据目录 ${DATA_DIR}"
      rm -rf -- "${DATA_DIR}"
    fi
    install -d -m 0700 -- "${DATA_DIR}"
  else
    warn "保留现有数据目录 ${DATA_DIR}"
    if ! install -d -m 0700 -- "${DATA_DIR}"; then
      err "无法创建数据目录，现有容器保持不变"
      return 1
    fi
    if container_exists; then
      backup_container="${CONTAINER_NAME}-rollback-$(date +%s)-$"
      log "停止旧容器并保留回滚副本：${backup_container}"
      if ! stop_container_checked "${CONTAINER_NAME}"; then
        err "无法确认旧容器已停止，已取消部署且保留原容器"
        return 1
      fi
      if ! docker rename "${CONTAINER_NAME}" "${backup_container}"; then
        docker start "${CONTAINER_NAME}" >/dev/null 2>&1 || true
        err "无法保留旧容器回滚副本，已取消部署"
        return 1
      fi
      local backup_state
      backup_state="$(docker inspect "${backup_container}" --format '{{.State.Status}}' 2>/dev/null)" || backup_state="unknown"
      if [[ "${backup_state}" != "exited" && "${backup_state}" != "created" ]]; then
        err "旧容器暂存后状态不是已停止（${backup_state}），取消部署并恢复旧容器"
        restore_previous_container "${backup_container}" || true
        return 1
      fi
    fi
  fi

  log "启动新容器 ${CONTAINER_NAME}"
  if ! docker run -d \
      --name "${CONTAINER_NAME}" \
      --restart "${RESTART_POLICY}" \
      "${PORT_MAP[@]}" \
      "${DEVICE_MAP[@]}" \
      "${CAP_ADD[@]}" \
      -v "${DATA_DIR}:/data" \
      -e TZ="${TZ_VAL}" \
      "${EXTRA_ENVS[@]}" \
      "${IMAGE}" >/dev/null; then
    err "启动新容器失败"
    if docker ps -a --format '{{.Names}}' | grep -qx "${CONTAINER_NAME}"; then
      docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    fi
    restore_previous_container "${backup_container}" || true
    return 1
  fi

  if ! verify_container; then
    err "新容器健康检查未通过"
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    restore_previous_container "${backup_container}" || true
    return 1
  fi

  if [[ -n "${backup_container}" ]]; then
    log "新容器健康，删除回滚副本 ${backup_container}"
    docker rm "${backup_container}" >/dev/null 2>&1 || warn "回滚副本未能清理，可手动删除"
  fi
  if [[ "${remove_image}" == "true" ]]; then
    log "清理旧的 dangling 镜像"
    docker image prune -f >/dev/null 2>&1 || true
  fi
  return 0
}

# ---------- 生命周期控制 ----------
do_start() {
  if ! container_exists; then warn "容器 ${CONTAINER_NAME} 不存在，请先部署"; return 1; fi
  log "启动 ${CONTAINER_NAME}"
  docker start "${CONTAINER_NAME}"
}

do_stop() {
  if ! container_exists; then warn "容器 ${CONTAINER_NAME} 不存在"; return 1; fi
  log "停止 ${CONTAINER_NAME}"
  docker stop "${CONTAINER_NAME}"
}

do_restart() {
  if ! container_exists; then warn "容器 ${CONTAINER_NAME} 不存在，请先部署"; return 1; fi
  log "重启 ${CONTAINER_NAME}"
  docker restart "${CONTAINER_NAME}"
}

do_remove() {
  if ! container_exists; then warn "容器 ${CONTAINER_NAME} 不存在"; return 1; fi
  read -rp "确认删除容器 ${CONTAINER_NAME}？（数据目录将保留）[y/N]: " ans
  [[ "${ans}" =~ ^[Yy]$ ]] || { warn "已取消"; return 1; }
  docker stop "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  docker rm "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  log "已删除容器 ${CONTAINER_NAME}"
}

# ---------- 查看：日志 / 详情 / 镜像 / 容器 ----------
do_logs_follow() {
  if ! container_exists; then warn "容器 ${CONTAINER_NAME} 不存在"; return 1; fi
  echo "按 Ctrl+C 停止查看日志，返回菜单"
  local pid
  docker logs -f --tail=100 "${CONTAINER_NAME}" &
  pid=$!
  trap "kill ${pid} 2>/dev/null || true" INT
  wait "${pid}" 2>/dev/null || true
  trap - INT
  echo
}

do_logs_tail() {
  if ! container_exists; then warn "容器 ${CONTAINER_NAME} 不存在"; return 1; fi
  docker logs --tail=200 "${CONTAINER_NAME}" 2>&1 || true
}

do_inspect() {
  if ! container_exists; then warn "容器 ${CONTAINER_NAME} 不存在"; return 1; fi
  docker inspect "${CONTAINER_NAME}" | sed -n '1,200p'
}

do_list_images() {
  log "本地镜像列表："
  echo
  docker images \
    --format 'table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedSince}}' \
    || { warn "获取镜像列表失败"; return 1; }
  echo
  if docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    log "当前配置镜像：${IMAGE}（本地已存在）"
    docker image inspect "${IMAGE}" --format \
'  ID     : {{.Id}}
  Digest : {{index .RepoDigests 0}}
  Size   : {{.Size}}
  Created: {{.Created}}'
  else
    warn "当前配置镜像：${IMAGE}（本地不存在，需先拉取）"
  fi
}

do_list_containers() {
  log "全部容器（含已停止）："
  echo
  docker ps -a \
    --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' \
    || { warn "获取容器列表失败"; return 1; }
  echo
  if container_exists; then
    log "当前管理容器 ${CONTAINER_NAME} 状态：$(container_status)"
  else
    warn "当前管理容器 ${CONTAINER_NAME} 不存在"
  fi
}

# ---------- 交互式修改配置 ----------
change_name() {
  read -rp "新容器名称 [${CONTAINER_NAME}]: " input
  [[ -z "${input}" ]] && { warn "未修改"; return; }
  CONTAINER_NAME="${input}"
  log "容器名称已更新（需重建容器生效）"
  warn "提示：要长期生效请选 19) 保存配置"
}

change_image() {
  read -rp "新镜像地址 [${IMAGE}]: " input
  [[ -z "${input}" ]] && { warn "未修改"; return; }
  IMAGE="${input}"
  log "镜像已更新（需重建容器生效）"
  warn "提示：要长期生效请选 19) 保存配置"
}

change_data_dir() {
  read -rp "新数据目录 [${DATA_DIR}]: " input
  [[ -z "${input}" ]] && { warn "未修改"; return; }
  DATA_DIR="${input}"
  log "数据目录已更新（需重建容器生效）"
  warn "提示：要长期生效请选 19) 保存配置"
}

change_ports() {
  echo "当前端口映射: $(ports_display)"
  echo "请输入新的端口映射，用空格分隔，带协议（例如: 80:80/tcp 127.0.0.1:7890:7890/tcp 127.0.0.1:7890:7890/udp）"
  read -rp "> " input
  [[ -z "${input}" ]] && { warn "未修改"; return; }
  local new_ports=() m
  for m in ${input}; do
    new_ports+=("-p" "${m}")
  done
  PORT_MAP=("${new_ports[@]}")
  log "端口映射已更新（需重建容器生效）"
  warn "提示：要长期生效请选 19) 保存配置"
}

change_tz() {
  read -rp "新时区 [${TZ_VAL}]: " input
  [[ -z "${input}" ]] && { warn "未修改"; return; }
  TZ_VAL="${input}"
  log "时区已更新（需重建容器生效）"
  warn "提示：要长期生效请选 19) 保存配置"
}

change_restart_policy() {
  echo "可选: no | on-failure | always | unless-stopped"
  read -rp "新重启策略 [${RESTART_POLICY}]: " input
  [[ -z "${input}" ]] && { warn "未修改"; return; }
  case "${input}" in
    no|on-failure|always|unless-stopped) RESTART_POLICY="${input}"; log "重启策略已更新（需重建容器生效）" ;;
    *) warn "无效的重启策略" ;;
  esac
  warn "提示：要长期生效请选 19) 保存配置"
}

# 切换 TUN 映射（设备 + 权限）
toggle_tun() {
  echo "当前 TUN 设备映射: $(device_display)"
  echo "当前 Capability  : $(caps_display)"
  read -rp "启用 TUN 设备映射与 NET_ADMIN/NET_RAW？[Y/n]: " ans
  if [[ "${ans}" =~ ^[Nn]$ ]]; then
    DEVICE_MAP=()
    CAP_ADD=()
    log "已关闭 TUN 映射与相关 Capability（需重建容器生效）"
  else
    DEVICE_MAP=( "--device" "/dev/net/tun:/dev/net/tun" )
    CAP_ADD=( "--cap-add" "NET_ADMIN" "--cap-add" "NET_RAW" )
    log "已开启 TUN 映射与 NET_ADMIN/NET_RAW（需重建容器生效）"
    check_host_tun || true
  fi
  warn "提示：要长期生效请选 19) 保存配置"
}

# ---------- 菜单 ----------
show_menu() {
  echo
  echo "════════════════════════════════════════════════════"
  echo "            s5m-agent 容器管理"
  echo "════════════════════════════════════════════════════"
  printf "  容器名称 : %s\n" "${CONTAINER_NAME}"
  printf "  镜像     : %s\n" "${IMAGE}"
  printf "  数据目录 : %s\n" "${DATA_DIR}"
  printf "  端口映射 : %s\n" "$(ports_display)"
  printf "  TUN 设备 : %s\n" "$(device_display)"
  printf "  Capability: %s\n" "$(caps_display)"
  printf "  时区     : %s\n" "${TZ_VAL}"
  printf "  重启策略 : %s\n" "${RESTART_POLICY}"
  printf "  状态     : %s\n" "$(container_status)"
  echo "────────────────────────────────────────────────────"
  echo "  ── 部署 / 生命周期 ──"
  echo "  1)  完整重建（删容器 + 删镜像 + 删数据 + 重拉 + 启动）"
  echo "  2)  重新部署（删容器 + 保留数据 + 重拉 + 启动）"
  echo "  3)  拉取最新镜像"
  echo "  4)  启动容器"
  echo "  5)  停止容器"
  echo "  6)  重启容器"
  echo "  7)  删除容器（保留数据）"
  echo "  ── 查看 ──"
  echo "  8)  查看日志（实时，Ctrl+C 退出）"
  echo "  9)  查看最近 200 行日志"
  echo "  10) 显示当前容器详情（inspect）"
  echo "  11) 查看本地镜像列表（含当前镜像详情）"
  echo "  12) 查看全部容器列表（含已停止）"
  echo "  ── 修改配置 ──"
  echo "  13) 修改容器名称"
  echo "  14) 修改镜像"
  echo "  15) 修改数据目录"
  echo "  16) 修改端口映射"
  echo "  17) 修改时区"
  echo "  18) 修改重启策略"
  echo "  19) 保存配置到文件（${CONFIG_FILE}）"
  echo "  20) 切换 TUN 映射（--device /dev/net/tun + NET_ADMIN/NET_RAW）"
  echo "  21) 拉取并选择无 SmartDNS 镜像（ghcr.io/tony855/s5m-agent:dev）"
  echo "  0)  退出"
  echo "════════════════════════════════════════════════════"
}

main_menu() {
  require_root
  while true; do
    show_menu
    read -rp "请选择操作: " choice || break
    case "${choice}" in
      1)  do_recreate true true   || warn "操作失败" ;;
      2)  do_recreate false false || warn "操作失败" ;;
      3)  do_pull                 || warn "拉取失败" ;;
      4)  do_start                || true ;;
      5)  do_stop                 || true ;;
      6)  do_restart              || true ;;
      7)  do_remove               || true ;;
      8)  do_logs_follow          || true ;;
      9)  do_logs_tail            || true ;;
      10) do_inspect              || true ;;
      11) do_list_images          || true ;;
      12) do_list_containers      || true ;;
      13) change_name ;;
      14) change_image ;;
      15) change_data_dir ;;
      16) change_ports ;;
      17) change_tz ;;
      18) change_restart_policy ;;
      19) save_config ;;
      20) toggle_tun ;;
      21) do_pull_no_smartdns || warn "无 SmartDNS 镜像拉取/切换失败" ;;
      0|q|Q|exit) log "退出"; break ;;
      *) warn "无效选项，请重新选择" ;;
    esac
  done
}

# ---------- 自动化部署（兼容原脚本） ----------
exec_deploy_auto() {
  require_root

  local remove_image="false"
  local wipe="${WIPE_DATA}"

  if [[ "${FULL_RESET}" == "true" ]]; then
    remove_image="true"
    wipe="true"
  fi

  if [[ "${CLEAN_LEGACY_IMAGES}" == "true" ]]; then
    log "清理旧仓库 s5m-agent:local / s5m-agent:amd64-test"
    docker rmi -f s5m-agent:local s5m-agent:amd64-test >/dev/null 2>&1 || true
  fi

  do_recreate "${remove_image}" "${wipe}"

  log "常用命令："
  echo "  docker logs -f ${CONTAINER_NAME}"
  echo "  docker restart ${CONTAINER_NAME}"
  echo "  docker inspect ${CONTAINER_NAME} --format '{{.State.Health.Status}}'"
  echo
  echo "提示：不带参数运行本脚本可进入交互式管理菜单"
}

# ---------- 入口 ----------
case "${1:-menu}" in
  deploy|--auto|auto)
    exec_deploy_auto
    ;;
  menu|"")
    main_menu
    ;;
  -h|--help|help)
    cat <<EOF
用法: $0 [menu|deploy]
  menu   交互式管理菜单（默认）
  deploy 直接执行自动部署（读取环境变量 FULL_RESET / WIPE_DATA / CLEAN_LEGACY_IMAGES）

配置文件: ${CONFIG_FILE}（保存后下次启动自动加载）
EOF
    ;;
  *)
    err "未知参数: $1"
    echo "使用 '$0 --help' 查看帮助"
    exit 1
    ;;
esac
