#!/usr/bin/env bash
set -Eeuo pipefail

LOG_PREFIX="[S5M]"
log_info()    { printf "%s [INFO]  %s\n" "$LOG_PREFIX" "$*"; }
log_success() { printf "%s [OK]    %s\n" "$LOG_PREFIX" "$*"; }
log_error()   { printf "%s [ERROR] %s\n" "$LOG_PREFIX" "$*" >&2; }
die()         { log_error "$1"; exit "${2:-1}"; }

REPO_URL="https://github.com/Tony855/S5M-Agent-SmartDNS.git"
REPO_BRANCH="main"
REPO_DIR="/root/S5M-Agent-SmartDNS"
INSTALLER="$REPO_DIR/scripts/install-server.sh"

[[ $EUID -eq 0 ]] || die "需要 root 权限。请执行：sudo bash scripts/install.sh"

if ! command -v git >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || die "apt-get update 失败，无法安装 Git。"
  apt-get install -y -qq git ca-certificates curl >/dev/null || die "Git/CA 证书安装失败。"
fi

if [[ ! -e "$REPO_DIR" ]]; then
  log_info "首次获取 S5M-Agent-SmartDNS 主控安装源：$REPO_URL"
  git clone --branch "$REPO_BRANCH" --single-branch "$REPO_URL" "$REPO_DIR" ||
    die "克隆 S5M-Agent-SmartDNS 仓库失败。"
else
  [[ -d "$REPO_DIR/.git" ]] ||
    die "$REPO_DIR 已存在但不是 Git 仓库；为避免覆盖现有文件，停止安装。"

  origin_url="$(git -C "$REPO_DIR" remote get-url origin 2>/dev/null || true)"
  case "$origin_url" in
    "$REPO_URL"|"https://github.com/Tony855/S5M-Agent-SmartDNS") ;;
    *) die "$REPO_DIR 的 origin 不匹配（${origin_url:-未配置}），拒绝切换仓库。" ;;
  esac

  current_branch="$(git -C "$REPO_DIR" branch --show-current)"
  [[ "$current_branch" == "$REPO_BRANCH" ]] ||
    die "$REPO_DIR 当前分支为 ${current_branch:-detached}，预期 $REPO_BRANCH。"

  [[ -z "$(git -C "$REPO_DIR" status --porcelain)" ]] ||
    die "$REPO_DIR 存在未提交修改；为避免覆盖本地代码，停止更新。"

  log_info "获取 S5M-Agent-SmartDNS 最新主控安装代码..."
  git -C "$REPO_DIR" fetch --prune origin "$REPO_BRANCH" ||
    die "获取 S5M-Agent-SmartDNS 最新代码失败。"
  git -C "$REPO_DIR" merge-base --is-ancestor HEAD "origin/$REPO_BRANCH" ||
    die "本地仓库与远程 main 已分叉或领先，拒绝强制覆盖。"
  git -C "$REPO_DIR" merge --ff-only "origin/$REPO_BRANCH" ||
    die "S5M-Agent-SmartDNS 快进更新失败。"
fi

[[ -s "$INSTALLER" ]] || die "缺少主控安装程序：$INSTALLER"
[[ -s "$REPO_DIR/server/main.go" && -s "$REPO_DIR/server/go.mod" ]] ||
  die "仓库缺少 server/ 主控源码，拒绝执行安装。"

log_success "安装源已更新：$(git -C "$REPO_DIR" rev-parse --short HEAD)"
log_info "开始安装 S5M-Server 主控；不会安装 Agent 镜像、SmartDNS 容器或 Docker。"
log_info "源码目录：$REPO_DIR/server"
log_info "运行目录：/opt/S5M-Server（仅部署主控二进制及必要运行状态文件）"

exec bash "$INSTALLER" "$@"
