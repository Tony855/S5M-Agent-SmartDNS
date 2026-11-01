# S5M-Agent-SmartDNS 一键部署

## 运行方式

在 Debian/Ubuntu 主机上以 root 执行：

```bash
curl -fsSL https://raw.githubusercontent.com/Tony855/S5M-Agent-SmartDNS/main/scripts/deploy-agent.sh -o /usr/local/sbin/s5m-agent-deploy
chmod 0755 /usr/local/sbin/s5m-agent-deploy
/usr/local/sbin/s5m-agent-deploy
```

首次运行会生成 `/etc/default/s5m-agent-smartdns`，随后按默认配置拉取并启动容器。修改配置后，再次运行脚本即可应用配置。

## 可配置项

| 变量 | 默认值 | 说明 |
|---|---|---|
| `IMAGE` | `ghcr.io/tony855/s5m-agent-smartdns:dev` | Agent 镜像 |
| `CONTAINER_NAME` | `s5m-agent` | 容器名称 |
| `S5M_HOSTNAME` | 空（自动使用系统 hostname） | Agent 上报主机名 |
| `BIND_IP` | `0.0.0.0` | 宿主机端口监听地址 |
| `WEB_PORT` | `80` | 映射容器 Web 端口；设为 `0` 禁用 |
| `PROXY_PORT` | `0` | 映射容器代理端口 7890；设为 `0` 禁用 |
| `DNS_PORT` | `0` | 将同一宿主机端口映射到容器 6053 TCP/UDP；设为 `0` 禁用 |
| `DATA_DIR` | `/opt/s5m-agent/data` | 持久化数据目录 |
| `RESTART_POLICY` | `unless-stopped` | Docker 重启策略 |
| `ENABLE_TUN` | `0` | 设为 `1` 时添加 NET_ADMIN 和 /dev/net/tun |
| `EXTRA_ENV_FILE` | 空 | 可选 Docker env-file 路径 |
| `PULL_IMAGE` | `1` | 是否先拉取镜像；设为 `0` 使用本地镜像 |

## 自定义环境变量

将镜像代码已经实现并识别的环境变量写入独立文件，例如：

```bash
install -m 600 /dev/null /etc/s5m-agent-smartdns.env
nano /etc/s5m-agent-smartdns.env
```

然后在 `/etc/default/s5m-agent-smartdns` 中设置：

```bash
EXTRA_ENV_FILE="/etc/s5m-agent-smartdns.env"
```

只有 Agent 镜像实际支持的变量才会生效；任意自定义名称不会自动改变程序行为。不要把密码、Token 等秘密提交到 Git。

## 安全注意事项

- 代理端口默认不发布（`PROXY_PORT=0`）。只有确认已配置代理认证或来源 IP 白名单后，才建议将其改为 `7890` 并开放防火墙。
- Web 端口默认绑定所有网卡的 80 端口。公网管理页面应配置 HTTPS 和访问控制；如仅本机访问，可将 `BIND_IP` 改为 `127.0.0.1`。
- Agent 内部 API 端口 8088 不会映射到宿主机。
- SmartDNS 默认不对宿主机发布；需要提供 DNS 服务时再配置 `DNS_PORT`，并限制来源网络。
- TUN 默认关闭。启用前确认宿主机存在 `/dev/net/tun`，并了解 NET_ADMIN 权限影响。
- 脚本不会删除 `DATA_DIR`。升级时会先暂存同名旧容器；新容器启动检查失败时会尝试移除新容器并恢复旧容器。
- 回滚只恢复旧容器及其容器配置，不会撤销镜像拉取或数据目录内由新版本写入的数据；升级前仍应备份持久化数据。
- 配置文件与额外 env 文件会设置为仅 root 可读写（权限 0600），并拒绝符号链接；持久化目录权限为 0700。IPv6 的 BIND_IP 会自动使用 Docker 端口映射所需的方括号格式。
- **不要添加 Docker `--init` 参数**：镜像使用 s6-overlay 的 `/init` 作为 PID 1。

## 卸载容器（保留数据）

```bash
docker rm -f s5m-agent
```

持久化数据默认位于 `/opt/s5m-agent/data`，需要保留时不要删除该目录。
