#!/usr/bin/env bash
set -Eeuo pipefail

APP="S5M-Server"
UNIT="s5m-server"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# 定位源码目录
if [[ -f "$ROOT/server/main.go" && -f "$ROOT/server/go.mod" ]]; then SRC="$ROOT/server"; elif [[ -f "$ROOT/main.go" && -f "$ROOT/go.mod" ]]; then SRC="$ROOT"; else echo "❌ 缺少 server/ 主控源码（main.go/go.mod）" >&2; exit 1; fi

# 全局路径与变量
ENV_FILE="/etc/s5m-server.env"
OLD_ENV_FILE="/etc/s5m-server/server.env"
DB_DIR="/var/lib/s5m-server"
S5M_DOMAIN="${S5M_DOMAIN:-}"
S5M_EMAIL="${S5M_EMAIL:-}"
REQUESTED_DOMAIN="$S5M_DOMAIN"
HTTPS_ALREADY_CONFIGURED=0
NGINX_SITE="/etc/nginx/sites-available/s5m-server"
NGINX_ENABLED="/etc/nginx/sites-enabled/s5m-server"
if [[ -n "${1:-}" && -z "$REQUESTED_DOMAIN" ]]; then
  REQUESTED_DOMAIN="$1"
  S5M_DOMAIN="$REQUESTED_DOMAIN"
fi

[[ $EUID -eq 0 ]] || { echo "请使用 sudo bash scripts/install.sh" >&2; exit 1; }

# [修复 P1-7] 先补齐基础依赖，再检测现有 HTTPS
# 原因：原脚本在 apt 安装前就用 python3/openssl，最小化系统会漏检现有证书
export DEBIAN_FRONTEND=noninteractive
_bootstrap_deps=()
for c in curl python3 openssl; do
  command -v "$c" >/dev/null 2>&1 || _bootstrap_deps+=("$c")
done
[[ -d /etc/ssl/certs ]] || _bootstrap_deps+=(ca-certificates)
if [[ ${#_bootstrap_deps[@]} -gt 0 ]]; then
  echo "ℹ️ 缺少基础依赖：${_bootstrap_deps[*]}，正在安装..."
  if ! apt-get update -qq; then
    echo "❌ apt-get update 失败，请检查网络或 apt 源配置" >&2
    exit 1
  fi
  if ! apt-get install -y -qq "${_bootstrap_deps[@]}" >/dev/null; then
    echo "❌ 基础依赖安装失败：${_bootstrap_deps[*]}" >&2
    exit 1
  fi
fi

# 解析 nginx -T 输出，查找已存在的 S5M HTTPS 虚拟主机
# 只复用 443+ssl+proxy_pass 127.0.0.1:8080 且证书有效的 server 块
if command -v nginx >/dev/null 2>&1; then
  while IFS=$'\t' read -r detected_domain cert_path key_path source_file; do
    [[ -n "$detected_domain" && -n "$cert_path" && -n "$key_path" ]] || continue
    [[ "$detected_domain" != "_" && "$detected_domain" != *'*'* ]] || continue
    [[ -z "$REQUESTED_DOMAIN" || "$REQUESTED_DOMAIN" == "$detected_domain" ]] || continue
    [[ -s "$cert_path" && -s "$key_path" ]] || continue
    command -v openssl >/dev/null 2>&1 || continue
    # 校验证书是否匹配域名且未过期
    openssl x509 -in "$cert_path" -noout -checkhost "$detected_domain" >/dev/null 2>&1 || continue
    openssl x509 -in "$cert_path" -noout -checkend 0 >/dev/null 2>&1 || continue
    if nginx -t >/dev/null 2>&1; then
      S5M_DOMAIN="$detected_domain"
      HTTPS_ALREADY_CONFIGURED=1
      echo "🔐 检测到现有 S5M HTTPS 配置：$S5M_DOMAIN（$source_file），复用现有证书，不重新询问域名或签发证书。"
      break
    fi
  done < <(nginx -T 2>/dev/null | python3 -c '
import re, sys
text = re.sub(r"(?m)^\s*#.*$", "", sys.stdin.read())
# 按大括号切分 server 块
for match in re.finditer(r"(?m)^\s*server\s*\{", text):
    start = match.end()
    depth = 1
    i = start
    while i < len(text) and depth:
        if text[i] == "{": depth += 1
        elif text[i] == "}": depth -= 1
        i += 1
    block = text[start:i-1]
    listen = re.search(r"(?m)^\s*listen\s+(?:\[::\]:)?443\s+[^;]*\bssl\b[^;]*;", block)
    proxy = re.search(r"(?m)^\s*proxy_pass\s+http://127\.0\.0\.1:8080(?:[/;\s]|$)", block)
    cert = re.search(r"(?m)^\s*ssl_certificate\s+([^;]+);", block)
    key = re.search(r"(?m)^\s*ssl_certificate_key\s+([^;]+);", block)
    names = re.search(r"(?m)^\s*server_name\s+([^;]+);", block)
    if not (listen and proxy and cert and key and names): continue
    cert_path, key_path = cert.group(1).strip(), key.group(1).strip()
    for domain in names.group(1).split():
        if domain != "_" and "*" not in domain and not domain.startswith("$"):
            print("\t".join((domain, cert_path, key_path, "nginx -T server block")))
')
fi

# 未检测到现有 HTTPS 且是交互终端时，才询问域名
if [[ -z "$S5M_DOMAIN" && "$HTTPS_ALREADY_CONFIGURED" -eq 0 && -t 0 ]]; then
  echo "尚未检测到可复用的 S5M HTTPS 配置。"
  read -r -p "请输入面板域名（留空则暂不配置 HTTPS）: " S5M_DOMAIN
  if [[ -n "$S5M_DOMAIN" ]]; then
    read -r -p "Let's Encrypt 邮箱 [v2wallid@gmail.com]: " S5M_EMAIL
    S5M_EMAIL="${S5M_EMAIL:-v2wallid@gmail.com}"
  fi
fi

# 域名格式校验
if [[ -n "$S5M_DOMAIN" && ! "$S5M_DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]; then
  echo "❌ S5M_DOMAIN 格式无效：$S5M_DOMAIN" >&2
  exit 1
fi
if [[ -n "$S5M_DOMAIN" && "$HTTPS_ALREADY_CONFIGURED" -eq 0 && -z "$S5M_EMAIL" ]]; then
  S5M_EMAIL="v2wallid@gmail.com"
fi
BIN="/opt/S5M-Server/S5M-Server"

# 检测是否已存在 S5M Next，避免覆盖
if systemctl is-active --quiet s5m-next 2>/dev/null || [[ -x /opt/s5m-next/bin/s5m-next ]]; then
  echo "检测到现有 S5M Next 部署。为防止覆盖数据库/服务，安装器已停止。" >&2
  exit 2
fi

# 检查前端资源是否完整
for f in web/index.html web/app.js web/vendor/vue.global.prod.js web/vendor/element-plus.full.js web/vendor/element-plus.css; do
  if [[ ! -s "$SRC/$f" ]]; then echo "❌ 缺少前端资源: $SRC/$f" >&2; exit 1; fi
done

# 安装系统依赖（含可选的 nginx/certbot）
apt_packages=(ca-certificates curl git build-essential golang-go sqlite3 libcap2-bin openssl python3 gzip)
if [[ -n "$S5M_DOMAIN" ]]; then apt_packages+=(nginx certbot python3-certbot-nginx); fi
# [修复 P2-8] apt 失败时给出明确提示
if ! apt-get update -qq; then
  echo "❌ apt-get update 失败，请检查网络或 apt 源配置" >&2
  exit 1
fi
if ! apt-get install -y -qq "${apt_packages[@]}" > /dev/null; then
  echo "❌ apt-get install 失败：${apt_packages[*]}" >&2
  exit 1
fi

# 判断 S5M 后端监听端口
PORT_TO_USE=""
if [[ -n "$S5M_DOMAIN" ]]; then
  # HTTPS 模式下固定走 127.0.0.1:8080
  PORT_TO_USE=8080
elif [[ -r "$ENV_FILE" ]]; then
  # 无域名但已有 env：沿用原 S5M_ADDR 端口
  EXISTING_ADDR="$(sed -n 's/^S5M_ADDR=//p' "$ENV_FILE" | tail -n1)"
  if [[ "$EXISTING_ADDR" =~ :([0-9]+)$ ]]; then PORT_TO_USE="${BASH_REMATCH[1]}"; fi
fi
if [[ -z "$PORT_TO_USE" ]]; then
  if command -v nginx >/dev/null 2>&1 && systemctl is-active --quiet nginx 2>/dev/null; then
    PORT_TO_USE=8080
  else
    PORT_TO_USE=80
  fi
fi

# 端口冲突检测，识别占用进程
if ss -lntp 2>/dev/null | grep -Eq "[:.]${PORT_TO_USE}[[:space:]]"; then
    echo "⚠️ S5M 后端端口 ${PORT_TO_USE} 已被占用，正在识别进程..."
    OLD_PID="$(ss -lntp 2>/dev/null | grep -E "[:.]${PORT_TO_USE}[[:space:]]" | grep -oP 'pid=\K[0-9]+' | head -n1 || true)"
    OLD_CMD="$(ps -p "$OLD_PID" -o comm= 2>/dev/null || true)"
    if [[ "$OLD_CMD" == *"S5M-Server"* ]]; then
        echo "ℹ️ 检测到现有 S5M-Server（PID: $OLD_PID），保留进程，不强制停止。"
    elif [[ "$OLD_CMD" == *"nginx"* && "$PORT_TO_USE" == "80" ]]; then
        echo "ℹ️ 端口 80 是现有 Nginx 的公共入口；不将其误判为 S5M 后端冲突。"
    else
        echo "❌ S5M 后端端口 ${PORT_TO_USE} 被其他程序 ($OLD_CMD, PID: ${OLD_PID:-未知}) 占用！" >&2
        echo "为避免中断现有服务，安装器停止操作；请先确认后端端口配置。" >&2
        exit 1
    fi
fi

# 确保主控 Mihomo 存在；已存在的正常版本直接复用
MIHOMO_DIR="/opt/mihomo"
MIHOMO_BIN="$MIHOMO_DIR/mihomo"
ensure_mihomo() {
  if [[ -e "$MIHOMO_BIN" ]]; then
    if [[ -x "$MIHOMO_BIN" ]] && "$MIHOMO_BIN" -v >/tmp/s5m-mihomo-version.txt 2>&1; then
      echo "✅ 检测到主控 Mihomo 已安装：$(head -n 1 /tmp/s5m-mihomo-version.txt)"
      echo "   按要求跳过内核下载与替换。"
      return 0
    fi
    echo "❌ 检测到 $MIHOMO_BIN 已存在，但无法成功执行版本检查。" >&2
    echo "   为避免覆盖现有内核，安装器不会自动替换；请先检查文件和权限。" >&2
    return 1
  fi

  local arch asset_url release_tag tmpdir archive candidate
  # 识别 CPU 架构
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      echo "❌ 当前架构 $(uname -m) 暂不支持自动安装 Mihomo（仅支持 amd64/arm64）。" >&2
      return 1
      ;;
  esac

  echo "ℹ️ 未检测到主控 Mihomo，正在查询 GitHub 最新稳定版..."
  # 拉取 GitHub 最新 release 信息
  local release_json
  release_json="$(curl -fsSL --retry 3 --connect-timeout 10 --max-time 60 \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    https://api.github.com/repos/MetaCubeX/mihomo/releases/latest)" || {
      echo "❌ 无法读取 Mihomo 最新稳定版发布信息。" >&2
      return 1
    }

  # 按发行标签严格匹配资产名，不猜测
  read -r release_tag asset_url < <(python3 -c '
import json, re, sys
d=json.load(sys.stdin)
tag=d.get("tag_name", "")
assets=d.get("assets", [])
arch=sys.argv[1]
if arch == "amd64":
    expected = f"mihomo-linux-amd64-v1-{tag}.gz" if tag else ""
elif arch == "arm64":
    expected = f"mihomo-linux-arm64-{tag}.gz" if tag else ""
else:
    expected = ""
matches=[a.get("browser_download_url", "") for a in assets
         if a.get("name", "") == expected and a.get("browser_download_url", "").startswith("https://github.com/")]
if not tag or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag) or len(matches) != 1:
    print("", "")
else:
    print(tag, matches[0])
' "$arch" <<<"$release_json")

  if [[ -z "$release_tag" || -z "$asset_url" ]]; then
    echo "❌ 最新稳定版中未找到名称与发行标签严格匹配的 Linux $arch 二进制包。" >&2
    echo "   请检查 GitHub Releases 资产命名；为避免下载错误架构或变体，安装器不会猜测资产。" >&2
    python3 -c '
import json, sys
d=json.load(sys.stdin)
print("   发行标签:", d.get("tag_name", "(缺失)"))
print("   可用 Linux 资产:")
for a in d.get("assets", []):
    n=a.get("name", "")
    if n.startswith("mihomo-linux-"):
        print("    -", n)
' <<<"$release_json" >&2
    return 1
  fi

  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir:-}"' RETURN
  archive="$tmpdir/mihomo.gz"
  candidate="$tmpdir/mihomo"
  echo "⬇️ 正在下载 Mihomo $release_tag（linux/$arch）..."
  if ! curl -fL --retry 3 --connect-timeout 10 --max-time 180 "$asset_url" -o "$archive"; then
    echo "❌ Mihomo 下载失败。" >&2
    return 1
  fi
  # 校验并解压
  if ! gzip -t "$archive" || ! gzip -dc "$archive" > "$candidate"; then
    echo "❌ Mihomo 压缩包校验或解压失败。" >&2
    return 1
  fi
  chmod 0755 "$candidate"
  # 试运行确认可执行
  if ! "$candidate" -v >/tmp/s5m-mihomo-candidate-version.txt 2>&1; then
    echo "❌ 下载的 Mihomo 二进制无法运行，拒绝安装。" >&2
    cat /tmp/s5m-mihomo-candidate-version.txt >&2 || true
    return 1
  fi

  install -d -o root -g root -m 0755 "$MIHOMO_DIR"
  install -o root -g root -m 0755 "$candidate" "$MIHOMO_BIN"
  if ! "$MIHOMO_BIN" -v >/tmp/s5m-mihomo-version.txt 2>&1; then
    echo "❌ Mihomo 安装后版本检查失败。" >&2
    rm -f "$MIHOMO_BIN"
    return 1
  fi
  echo "✅ 已安装主控 Mihomo：$(head -n 1 /tmp/s5m-mihomo-version.txt)"
}
ensure_mihomo

# 创建 s5m-server 系统用户和私有目录
if ! getent passwd s5m-server >/dev/null; then useradd --system --home-dir "$DB_DIR" --shell /usr/sbin/nologin s5m-server; fi
install -d -o s5m-server -g s5m-server -m 0750 "$DB_DIR" "$DB_DIR/backups"
install -d -m 0755 /opt/S5M-Server
chown -R s5m-server:s5m-server "$DB_DIR"
chmod -R go-rwx "$DB_DIR"

# ===== 备份快照 =====
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="/var/backups/s5m-server-install-$STAMP"
install -d -m 0700 "$BACKUP"
[[ -f "$DB_DIR/s5m.db" ]] && sqlite3 "$DB_DIR/s5m.db" ".backup '$BACKUP/s5m.db'"
# 标记文件区分“原本不存在”和“存在但为空”
if [[ -e "$ENV_FILE" ]]; then cp -a "$ENV_FILE" "$BACKUP/s5m-server.env"; else : > "$BACKUP/env-file-absent"; fi
if [[ -e "$OLD_ENV_FILE" ]]; then cp -a "$OLD_ENV_FILE" "$BACKUP/legacy-server.env"; else : > "$BACKUP/legacy-env-absent"; fi
if [[ -e "$DB_DIR/config.yaml" ]]; then cp -a "$DB_DIR/config.yaml" "$BACKUP/config.yaml"; else : > "$BACKUP/config-file-absent"; fi
if [[ -f "$BIN" ]]; then cp -a "$BIN" "$BACKUP/S5M-Server.bin"; else : > "$BACKUP/server-bin-absent"; fi
if [[ -f /etc/systemd/system/s5m-server.service ]]; then
  cp -a /etc/systemd/system/s5m-server.service "$BACKUP/s5m-server.service"
else
  : > "$BACKUP/server-service-absent"
fi
if [[ -f /etc/systemd/system/mihomo.service ]]; then  cp -a /etc/systemd/system/mihomo.service "$BACKUP/mihomo.service"
else
  : > "$BACKUP/mihomo-service-absent"
fi

# 首次配置 HTTPS 前也备份 nginx 站点文件
if [[ -n "$S5M_DOMAIN" && "$HTTPS_ALREADY_CONFIGURED" -eq 0 ]]; then
  if [[ -e "$NGINX_SITE" || -L "$NGINX_SITE" ]]; then
    cp -a "$NGINX_SITE" "$BACKUP/nginx-s5m-server.conf"
  else
    : > "$BACKUP/nginx-site-absent"
  fi
  if [[ -e "$NGINX_ENABLED" || -L "$NGINX_ENABLED" ]]; then
    cp -a "$NGINX_ENABLED" "$BACKUP/nginx-s5m-server.enabled"
  else
    : > "$BACKUP/nginx-enabled-absent"
  fi
fi

# 回滚函数：快照存在后任何失败都调用它
rollback_install() {
  local reason="${1:-unknown failure}"
  echo "❌ 安装失败：${reason}，正在恢复安装前的文件和服务配置..." >&2
  systemctl stop "$UNIT" 2>/dev/null || true
  if [[ -f "$BACKUP/S5M-Server.bin" ]]; then
    install -o root -g root -m 0755 "$BACKUP/S5M-Server.bin" "$BIN"
    setcap cap_net_bind_service=+ep "$BIN" 2>/dev/null || true
  elif [[ -f "$BACKUP/server-bin-absent" ]]; then
    rm -f "$BIN"
  fi
  if [[ -f "$BACKUP/s5m-server.service" ]]; then
    cp -a "$BACKUP/s5m-server.service" /etc/systemd/system/s5m-server.service
  elif [[ -f "$BACKUP/server-service-absent" ]]; then
    rm -f /etc/systemd/system/s5m-server.service
  fi
  if [[ -f "$BACKUP/mihomo.service" ]]; then
    cp -a "$BACKUP/mihomo.service" /etc/systemd/system/mihomo.service
  elif [[ -f "$BACKUP/mihomo-service-absent" ]]; then
    rm -f /etc/systemd/system/mihomo.service
  fi
  if [[ -f "$BACKUP/s5m-server.env" ]]; then cp -a "$BACKUP/s5m-server.env" "$ENV_FILE"; elif [[ -f "$BACKUP/env-file-absent" ]]; then rm -f "$ENV_FILE"; fi
  if [[ -f "$BACKUP/legacy-server.env" ]]; then install -d -m 0750 "$(dirname "$OLD_ENV_FILE")"; cp -a "$BACKUP/legacy-server.env" "$OLD_ENV_FILE"; elif [[ -f "$BACKUP/legacy-env-absent" ]]; then rm -f "$OLD_ENV_FILE"; fi
  if [[ -f "$BACKUP/config.yaml" ]]; then cp -a "$BACKUP/config.yaml" "$DB_DIR/config.yaml"; elif [[ -f "$BACKUP/config-file-absent" ]]; then rm -f "$DB_DIR/config.yaml"; fi
  if [[ -n "$S5M_DOMAIN" ]]; then
    if [[ -f "$BACKUP/nginx-s5m-server.conf" ]]; then
      rm -f "$NGINX_SITE"
      cp -a "$BACKUP/nginx-s5m-server.conf" "$NGINX_SITE"
    elif [[ -f "$BACKUP/nginx-site-absent" ]]; then
      rm -f "$NGINX_SITE"
    fi
    if [[ -e "$BACKUP/nginx-s5m-server.enabled" || -L "$BACKUP/nginx-s5m-server.enabled" ]]; then
      rm -f "$NGINX_ENABLED"
      cp -a "$BACKUP/nginx-s5m-server.enabled" "$NGINX_ENABLED"
    elif [[ -f "$BACKUP/nginx-enabled-absent" ]]; then
      rm -f "$NGINX_ENABLED"
    fi
    if command -v nginx >/dev/null 2>&1 && nginx -t; then
      systemctl reload nginx 2>/dev/null || true
    fi
  fi
  systemctl daemon-reload
  if [[ -f "$BACKUP/mihomo.service" ]]; then
    systemctl restart mihomo || echo "❌ Mihomo 回滚启动失败，请检查 journalctl -u mihomo" >&2
  else
    systemctl stop mihomo 2>/dev/null || true
  fi
  if [[ -f "$BACKUP/S5M-Server.bin" ]]; then
    systemctl start "$UNIT" || echo "❌ 旧版 S5M-Server 启动失败，请检查 journalctl -u $UNIT" >&2
  else
    systemctl stop "$UNIT" 2>/dev/null || true
  fi
  # 提示数据库备份位置，供人工恢复
  echo "ℹ️ 安装前数据库备份保留在：$BACKUP/s5m.db（若存在），供人工恢复使用。" >&2
}

# 迁移旧路径 env 文件
if [[ -f "$OLD_ENV_FILE" && ! -f "$ENV_FILE" ]]; then mv "$OLD_ENV_FILE" "$ENV_FILE"
elif [[ -f "$OLD_ENV_FILE" && -f "$ENV_FILE" ]]; then mv "$OLD_ENV_FILE" "$OLD_ENV_FILE.unused.$STAMP"; fi

# [修复 P0-2] 新 env 的 S5M_ADDR 必须与 PORT_TO_USE 一致
if [[ ! -f "$ENV_FILE" ]]; then
  ADMIN_PASS="$(openssl rand -hex 24)"
  if [[ -n "$S5M_DOMAIN" ]]; then
    S5M_ADDR_DEFAULT="127.0.0.1:${PORT_TO_USE}"
  else
    S5M_ADDR_DEFAULT=":${PORT_TO_USE}"
  fi
  cat > "$ENV_FILE" <<ENVEOF
S5M_ADDR=$S5M_ADDR_DEFAULT
S5M_DB=$DB_DIR/s5m.db
S5M_CONFIG=$DB_DIR/config.yaml
S5M_BACKUP=$DB_DIR/backups
S5M_ADMIN_USER=admin
S5M_ADMIN_PASSWORD=$ADMIN_PASS
S5M_JWT_SECRET=$(openssl rand -hex 32)
MIHOMO_API=http://127.0.0.1:8088
MIHOMO_SECRET=$(openssl rand -hex 24)
MIHOMO_CONFIG_PATH=$DB_DIR/config.yaml
ENVEOF
  chmod 0600 "$ENV_FILE"
  printf '用户名: admin\n密码: %s\n' "$ADMIN_PASS" > /root/S5M-Server-credentials.txt
  chmod 0600 /root/S5M-Server-credentials.txt
fi

# 旧 env 补齐字段；HTTPS 模式下强制 S5M_ADDR 指向本地后端端口
if [[ -n "$S5M_DOMAIN" ]]; then
  if grep -qE '^S5M_ADDR=' "$ENV_FILE"; then
    sed -i "s#^S5M_ADDR=.*#S5M_ADDR=127.0.0.1:${PORT_TO_USE}#" "$ENV_FILE"
  else
    printf '\nS5M_ADDR=127.0.0.1:%s\n' "$PORT_TO_USE" >> "$ENV_FILE"
  fi
fi
for entry in \
  "S5M_ADDR=:${PORT_TO_USE}" \
  "S5M_DB=$DB_DIR/s5m.db" \
  "S5M_CONFIG=$DB_DIR/config.yaml" \
  "S5M_BACKUP=$DB_DIR/backups" \
  "S5M_ADMIN_USER=admin"; do
  key="${entry%%=*}"
  if ! grep -qE "^${key}=" "$ENV_FILE"; then
    printf '%s\n' "$entry" >> "$ENV_FILE"
  fi
done
chmod 0600 "$ENV_FILE"

# 保留旧 config 里的 secret / external-controller，避免升级破坏 API
EXISTING_MIHOMO_SECRET=""
EXISTING_MIHOMO_CONTROLLER=""
if [[ -s "$DB_DIR/config.yaml" ]]; then
  EXISTING_MIHOMO_SECRET="$(sed -nE 's/^secret:[[:space:]]*["'\''"]?([^"'\''"[:space:]]+)["'\''"]?[[:space:]]*$/\1/p' "$DB_DIR/config.yaml" | head -n1)"
  EXISTING_MIHOMO_CONTROLLER="$(sed -nE 's/^external-controller:[[:space:]]*["'\''"]?([^"'\''"[:space:]]+)["'\''"]?[[:space:]]*$/\1/p' "$DB_DIR/config.yaml" | head -n1)"
fi
if ! grep -qE '^MIHOMO_API=' "$ENV_FILE"; then
  if [[ -n "$EXISTING_MIHOMO_CONTROLLER" ]]; then
    case "$EXISTING_MIHOMO_CONTROLLER" in
      http://*|https://*) API_DEFAULT="$EXISTING_MIHOMO_CONTROLLER" ;;
      *) API_DEFAULT="http://$EXISTING_MIHOMO_CONTROLLER" ;;
    esac
  else
    API_DEFAULT="http://127.0.0.1:8088"
  fi
  printf '\nMIHOMO_API=%s\n' "$API_DEFAULT" >> "$ENV_FILE"
fi
if ! grep -qE '^MIHOMO_SECRET=' "$ENV_FILE"; then
  if [[ -n "$EXISTING_MIHOMO_SECRET" ]]; then
    SECRET_DEFAULT="$EXISTING_MIHOMO_SECRET"
  else
    SECRET_DEFAULT="$(openssl rand -hex 24)"
  fi
  printf '\nMIHOMO_SECRET=%s\n' "$SECRET_DEFAULT" >> "$ENV_FILE"
fi
chmod 0600 "$ENV_FILE"
MIHOMO_API_URL="$(awk -F= '/^MIHOMO_API=/ { sub(/^[^=]*=/, ""); value=$0 } END { print value }' "$ENV_FILE")"
MIHOMO_PORT="$(printf '%s' "$MIHOMO_API_URL" | sed -nE 's#^https?://[^/:]+:([0-9]+)(/.*)?$#\1#p')"
MIHOMO_PORT="${MIHOMO_PORT:-8088}"
MIHOMO_SECRET_VALUE="$(awk -F= '/^MIHOMO_SECRET=/ { sub(/^[^=]*=/, ""); value=$0 } END { print value }' "$ENV_FILE")"

# [修复 P0-1] 默认 mixed-port 改为 7890，避免与 S5M 的 127.0.0.1:8080 冲突
if [[ ! -s "$DB_DIR/config.yaml" ]]; then
  cat > "$DB_DIR/config.yaml" <<MIHOMO_CONFIG_EOF
mode: rule
mixed-port: 7890
log-level: info
allow-lan: true
find-process-mode: "off"
proxies: []
rules:
  - MATCH,DIRECT
MIHOMO_CONFIG_EOF
fi

# 给旧 config 补 external-controller / secret，绑定到回环地址
if ! grep -qE '^external-controller[[:space:]]*:' "$DB_DIR/config.yaml"; then
  printf '\nexternal-controller: "127.0.0.1:%s"\n' "$MIHOMO_PORT" >> "$DB_DIR/config.yaml"
fi
if ! grep -qE '^secret[[:space:]]*:' "$DB_DIR/config.yaml"; then
  printf 'secret: "%s"\n' "$MIHOMO_SECRET_VALUE" >> "$DB_DIR/config.yaml"
fi

# config.yaml 权限收紧
chown s5m-server:s5m-server "$DB_DIR/config.yaml"
chmod 0600 "$DB_DIR/config.yaml"

# 写入 mihomo.service
cat > /etc/systemd/system/mihomo.service <<MIHOMO_SERVICE_EOF
[Unit]
Description=Mihomo Proxy Core (S5M main controller)
After=network-online.target
Wants=network-online.target
ConditionPathExists=$MIHOMO_BIN
ConditionPathExists=$DB_DIR/config.yaml

[Service]
Type=simple
User=root
Group=root
ExecStart=$MIHOMO_BIN -d $DB_DIR -f $DB_DIR/config.yaml
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$DB_DIR
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE
LockPersonality=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
MIHOMO_SERVICE_EOF

# 只在临时构建目录准备源码；/opt/S5M-Server 仅保留运行所需的主控二进制。
# source/main.go 使用 go:embed 将 web 资源编入二进制，运行时不需要源码或前端文件。
BUILD_DIR="$(mktemp -d /tmp/s5m-server-build.XXXXXX)"
trap 'rm -rf "$BUILD_DIR"' EXIT
cp -a "$SRC/." "$BUILD_DIR/"

# 拉依赖、完整测试并编译；任何一步失败都不触碰现有主控二进制。
cd "$BUILD_DIR"
if ! go mod download; then
  echo "❌ go mod download 失败（旧版本未受影响），备份在 $BACKUP" >&2
  exit 1
fi
if [[ "${SKIP_TEST:-0}" != "1" ]]; then
  if ! go test ./...; then
    echo "❌ go test 失败（旧二进制未替换，服务仍在运行），备份在 $BACKUP" >&2
    echo "   如需跳过测试重新安装，可使用：SKIP_TEST=1 sudo -E bash scripts/install.sh" >&2
    exit 1
  fi
fi
if ! go build -trimpath -ldflags='-s -w' -o "$BUILD_DIR/S5M-Server.new" .; then
  echo "❌ go build 失败（旧版本未受影响，服务仍在运行），备份在 $BACKUP" >&2
  exit 1
fi
install -o root -g root -m 0755 "$BUILD_DIR/S5M-Server.new" "$BIN"
setcap cap_net_bind_service=+ep "$BIN" || true

# 写入 s5m-server.service
cat > /etc/systemd/system/s5m-server.service <<SERVICEEOF
[Unit]
Description=S5M-Server Control Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=s5m-server
Group=s5m-server
SupplementaryGroups=systemd-journal
EnvironmentFile=$ENV_FILE
ExecStart=$BIN
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DB_DIR
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LockPersonality=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable mihomo
# [修复 P1-4] 只有 unit 或 config 变化（或服务未运行）才重启 mihomo，避免断线
MIHOMO_CONFIG_HASH="$(md5sum "$DB_DIR/config.yaml" 2>/dev/null | awk '{print $1}')"
MIHOMO_HASH_FILE="/opt/S5M-Server/.mihomo-config.md5"
MIHOMO_UNIT_CHANGED=0
if [[ ! -f "$BACKUP/mihomo.service" ]] || ! cmp -s /etc/systemd/system/mihomo.service "$BACKUP/mihomo.service"; then
  MIHOMO_UNIT_CHANGED=1
fi
if ! systemctl is-active --quiet mihomo \
   || [[ "$MIHOMO_UNIT_CHANGED" == "1" ]] \
   || [[ "$MIHOMO_CONFIG_HASH" != "$(cat "$MIHOMO_HASH_FILE" 2>/dev/null || true)" ]]; then
  if ! systemctl restart mihomo; then
    echo "❌ 主控 Mihomo 服务启动失败。请检查：journalctl -u mihomo -n 100 --no-pager" >&2
    systemctl status mihomo --no-pager -l >&2 || true
    rollback_install "主控 Mihomo 启动失败"
    exit 1
  fi
  printf '%s\n' "$MIHOMO_CONFIG_HASH" > "$MIHOMO_HASH_FILE"
  echo "ℹ️ 已重启主控 Mihomo（配置或服务单元有变化）。"
else
  echo "✅ 主控 Mihomo 配置未变化，跳过重启，保持现有代理连接。"
fi
systemctl enable "$UNIT"
if ! systemctl restart "$UNIT"; then
  echo "❌ S5M-Server 服务启动失败。请检查：journalctl -u $UNIT -n 100 --no-pager" >&2
  systemctl status "$UNIT" --no-pager -l >&2 || true
  rollback_install "S5M-Server 启动失败"
  exit 1
fi

# 解析端口并做健康检查（最多 20 秒）
ADDR="$(grep -E '^S5M_ADDR=' "$ENV_FILE" | cut -d= -f2-)"
PORT="${ADDR##*:}"
[[ -z "$PORT" ]] && PORT=80

HEALTH_OK=0
for _ in $(seq 1 20); do
  if curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/api/v1/health" >/tmp/s5m-server-health.json 2>/dev/null; then HEALTH_OK=1; break; fi
  sleep 1
done

if [[ "$HEALTH_OK" -ne 1 ]] || ! grep -q '"status":"ok"' /tmp/s5m-server-health.json 2>/dev/null; then
  echo "❌ 健康检查失败（端口 $PORT），正在恢复安装前状态..." >&2
  rollback_install "健康检查失败（端口 $PORT）"
  exit 1
fi

# 首次配置 HTTPS：写 nginx 站点 + certbot 签发
if [[ -n "$S5M_DOMAIN" && "$HTTPS_ALREADY_CONFIGURED" -eq 0 ]]; then

  cat > "$NGINX_SITE" <<NGINXEOF
server {
    listen 80;
    listen [::]:80;
    server_name $S5M_DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:${PORT_TO_USE};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
    }
}
NGINXEOF
  ln -sfn "$NGINX_SITE" "$NGINX_ENABLED"
  # 保留默认站点，S5M 按 server_name 匹配
  if ! nginx -t || ! systemctl enable --now nginx; then
    rollback_install "Nginx HTTPS 反向代理配置失败"
    exit 1
  fi
  if ! certbot --nginx --non-interactive --agree-tos --redirect --email "$S5M_EMAIL" -d "$S5M_DOMAIN"; then
    echo "❌ Let's Encrypt 证书签发失败。请确认域名 DNS 已指向本机，且 TCP 80/443 可从公网访问。" >&2
    rollback_install "HTTPS 证书签发失败"
    exit 1
  fi
  # 显式启用并校验自动续期
  if ! systemctl enable --now certbot.timer || ! systemctl is-active --quiet certbot.timer; then
    echo "❌ HTTPS 证书已签发，但 certbot.timer 未能启动，无法确认自动续期已启用。" >&2
    rollback_install "Certbot 自动续期服务启动失败"
    exit 1
  fi
  if ! certbot certificates 2>/dev/null | grep -Fq "Domains: $S5M_DOMAIN"; then
    echo "❌ Certbot 未列出 $S5M_DOMAIN 的有效证书。" >&2
    rollback_install "HTTPS 证书登记校验失败"
    exit 1
  fi
  if ! curl -fsS --max-time 10 "https://$S5M_DOMAIN/api/v1/health" >/tmp/s5m-server-https-health.json; then
    rollback_install "HTTPS 端点健康检查失败"
    exit 1
  fi
  echo "🔐 HTTPS 证书已签发并配置自动续期： https://$S5M_DOMAIN"
elif [[ -n "$S5M_DOMAIN" && "$HTTPS_ALREADY_CONFIGURED" -eq 1 ]]; then
  # 已有 HTTPS：只做健康检查，不改配置
  if ! curl -fsS --max-time 10 "https://$S5M_DOMAIN/api/v1/health" >/tmp/s5m-server-https-health.json; then
    echo "❌ 检测到现有 HTTPS 配置，但 HTTPS 健康检查失败；为避免覆盖现有配置，安装器停止。请检查 Nginx/证书/服务状态。" >&2
    exit 1
  fi
  echo "✅ 复用现有 HTTPS 配置，不重新签发证书： https://$S5M_DOMAIN"
fi

# 成功输出
echo "✅ S5M-Server 安装成功"
echo "   服务: $UNIT（端口 $PORT）"
echo "   健康: $(cat /tmp/s5m-server-health.json)"
if [[ -n "$S5M_DOMAIN" ]]; then echo "   HTTPS: https://$S5M_DOMAIN"; else echo "   HTTPS: 未配置（设置 S5M_DOMAIN 与 S5M_EMAIL 可启用 Let's Encrypt）"; fi