#!/usr/bin/env bash
set -Eeuo pipefail

LOG_PREFIX="[S5M]"
log_info()    { printf "%s [INFO]  %s\\n" "$LOG_PREFIX" "$*"; }
log_success() { printf "%s [OK]    %s\\n" "$LOG_PREFIX" "$*"; }
log_error()   { printf "%s [ERROR] %s\\n" "$LOG_PREFIX" "$*" >&2; }
die()         { log_error "$1"; exit "${2:-1}"; }

# This repository contains the Agent/SmartDNS image. Its installer entry point
# intentionally installs ONLY the independent S5M Master controller.
MASTER_REPO="https://github.com/Tony855/S5M-Master.git"
MASTER_BRANCH="main"
MASTER_DIR="/root/S5M-Master"

[[ $EUID -eq 0 ]] || die "需要 root 权限。请执行：sudo bash scripts/install.sh"

if ! command -v git >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || die "apt-get update 失败，无法安装 Git。"
  apt-get install -y -qq git >/dev/null || die "Git 安装失败。"
fi

log_info "同步独立 S5M 主控源码：$MASTER_REPO（$MASTER_BRANCH）"

if [[ ! -e "$MASTER_DIR" ]]; then
  git clone --branch "$MASTER_BRANCH" --single-branch "$MASTER_REPO" "$MASTER_DIR" ||
    die "克隆 S5M-Master 主控源码失败。"
else
  [[ -d "$MASTER_DIR/.git" ]] ||
    die "$MASTER_DIR 已存在但不是 Git 仓库；为避免覆盖文件，停止安装。"

  origin_url="$(git -C "$MASTER_DIR" remote get-url origin 2>/dev/null || true)"
  case "$origin_url" in
    "$MASTER_REPO"|"https://github.com/Tony855/S5M-Master") ;;
    *) die "$MASTER_DIR 的 origin 不匹配（${origin_url:-未配置}），拒绝切换仓库。" ;;
  esac

  current_branch="$(git -C "$MASTER_DIR" branch --show-current)"
  [[ "$current_branch" == "$MASTER_BRANCH" ]] ||
    die "$MASTER_DIR 当前分支为 ${current_branch:-detached}，预期 $MASTER_BRANCH。"

  [[ -z "$(git -C "$MASTER_DIR" status --porcelain)" ]] ||
    die "$MASTER_DIR 存在未提交修改；为避免覆盖本地代码，停止更新。"

  git -C "$MASTER_DIR" fetch --prune origin "$MASTER_BRANCH" ||
    die "获取 S5M-Master 最新代码失败。"
  git -C "$MASTER_DIR" merge-base --is-ancestor HEAD "origin/$MASTER_BRANCH" ||
    die "本地主控源码与远程 main 已分叉或领先，拒绝强制覆盖。"
  git -C "$MASTER_DIR" merge --ff-only "origin/$MASTER_BRANCH" ||
    die "S5M-Master 快进更新失败。"
fi

[[ -s "$MASTER_DIR/scripts/install.sh" && -s "$MASTER_DIR/source/main.go" && -s "$MASTER_DIR/source/go.mod" ]] ||
  die "S5M-Master 仓库结构不完整，缺少主控安装脚本或 Go 源码。"

log_success "主控源码已同步：$(git -C "$MASTER_DIR" rev-parse --short HEAD)"
log_info "开始执行 S5M 主控原生安装程序；本脚本不会安装 Agent 或 SmartDNS 容器。"

# Preserve caller-provided environment variables and all installer arguments.
exec bash "$MASTER_DIR/scripts/install.sh" "$@"
