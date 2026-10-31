# S5M Agent 详细部署教程（Ubuntu/Debian 与 MikroTik RouterOS）

本文用于部署已经由 GitHub Actions 构建的完整 S5M Agent 容器镜像。镜像基于 Alpine Linux，内置 Agent、Mihomo、默认配置、启动脚本和健康检查；Agent 文件位于容器内 `/app`，Mihomo 可执行文件位于 `/usr/local/bin/mihomo`。本教程同时覆盖主控安装、镜像包获取、Ubuntu/Debian Docker 部署、RouterOS 容器部署、绑定、验证、升级和故障排查。

> **重要：** 当前工作流生成 GitHub Actions 构建产物（tar 镜像包），不依赖 GHCR 登录或拉取权限。先在仓库 Actions 中确认两个架构的构建与镜像 smoke test 均成功，再下载产物。不要把“工作流已启动”当作构建成功。

## 1. 部署结构和端口

| 组件 | 端口 | 用途 |
| --- | ---: | --- |
| S5M 主控 Web/API | 80/TCP（默认） | 管理界面、节点注册、配置下发 |
| Agent 绑定页面/API | 80/TCP | 初次绑定和 Agent 管理 |
| Mihomo 代理 | 7890/TCP | 节点代理入口；按实际用途决定是否开放 |
| Mihomo 控制 API | 8088/TCP | 仅供容器内部 Agent 使用，**不要映射到公网** |

建议拓扑：主控部署在 Debian/Ubuntu；每台代理节点运行一个 Agent 容器；Agent 主动连接主控地址。跨公网时优先使用 HTTPS 或 VPN/管理网。端口 80 应限制为管理员或主控管理网来源。

## 2. 部署前准备

准备以下信息：

- 主控服务器公网或管理网 IP/域名，例如 `http://203.0.113.10` 或 `https://s5m.example.com`（请替换为自己的地址）。
- 主控节点管理页面可用，并能创建/查看 Agent 注册授权密钥。
- 每个 Agent 节点的 CPU 架构：`x86_64` 通常对应 `amd64`；`aarch64` 通常对应 `arm64`。
- Agent 节点能访问主控 HTTP(S) 端口；DNS、系统时间和防火墙规则正常。
- 代理节点需要保留的本地配置目录。不要把 Agent 的 `/data` 当作临时目录。

## 3. 安装 S5M 主控（Debian/Ubuntu 原生方式）

在全新 Debian/Ubuntu 服务器上以 root 或 sudo 执行：

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git
git clone https://github.com/Tony855/S5M-Master.git
cd S5M-Master
sudo bash scripts/install.sh
```

检查服务状态和健康接口：

```bash
sudo systemctl status s5m-server --no-pager -l
sudo systemctl status mihomo --no-pager -l
curl -fsS http://127.0.0.1/api/v1/health
sudo journalctl -u s5m-server -n 100 --no-pager
sudo journalctl -u mihomo -n 100 --no-pager
```

健康接口应返回成功状态的 JSON。安装脚本首次为新环境生成的管理员凭据通常保存在 `/root/S5M-Server-credentials.txt`；立即登录并修改密码。该文件和 `/etc/s5m-server.env` 可能含有敏感信息，不要粘贴到公开工单或聊天中。

主控关键路径：

- 程序：`/opt/S5M-Server/S5M-Server`
- 环境配置：`/etc/s5m-server.env`
- 数据和 Mihomo 配置：`/var/lib/s5m-server/`
- 服务：`s5m-server.service`、`mihomo.service`

如果主控已部署且健康检查通过，可以跳过本节。

## 4. 从 GitHub Actions 下载完整镜像包

1. 打开仓库的 [Actions 工作流](https://github.com/Tony855/S5M-Master/actions/workflows/agent-images.yml)。
2. 选择最近一次对应当前代码提交的 **S5M Agent multi-arch images** 工作流运行记录。
3. 确认 `Build and publish multi-arch image`（amd64）和 `Build ARM64 RouterOS archive` 两个 job 都成功；各自的 smoke test 必须成功。
4. 在该运行记录的 **Artifacts** 区域分别下载：
   - `s5m-agent-linux-amd64`：适用于常见 x86_64 Ubuntu/Debian 主机。
   - `s5m-agent-linux-arm64`：适用于 ARM64 设备；用于 RouterOS 前必须确认 RouterOS 设备本身支持 ARM64 容器。
5. 每个下载项是 ZIP 产物包。解压后应找到对应的 `.tar` 镜像归档和 `.tar.sha256` 校验文件。注意：这里的 `.tar` 才是容器镜像，不是源代码压缩包。

在下载文件所在目录执行校验（文件名按实际解压结果填写）：

```bash
sha256sum -c s5m-agent-linux-amd64.tar.sha256
# ARM64 设备则校验：
sha256sum -c s5m-agent-linux-arm64.tar.sha256
```

如果校验文件和 tar 不在同一目录，先把两者放在一起再校验。校验失败时不要导入镜像，重新下载产物并确认文件名。

## 5. Ubuntu/Debian：导入并运行镜像

### 5.1 安装 Docker Engine

使用 Docker 官方针对当前发行版的安装文档安装 Docker Engine；安装后确认：

```bash
sudo systemctl enable --now docker
sudo docker version
sudo docker info
uname -m
```

请确保 Docker 服务正常，且主机 CPU 与下载镜像架构匹配。

### 5.2 将镜像包传到 Agent 服务器

例如从管理电脑用 SCP 传输（把 IP、路径替换为实际值）：

```bash
scp s5m-agent-linux-amd64.tar user@AGENT_SERVER_IP:/tmp/
scp s5m-agent-linux-amd64.tar.sha256 user@AGENT_SERVER_IP:/tmp/
```

在 Agent 服务器上校验并导入：

```bash
cd /tmp
sha256sum -c s5m-agent-linux-amd64.tar.sha256
sudo docker load -i s5m-agent-linux-amd64.tar
sudo docker image ls
```

确认 `docker load` 输出的镜像名称/标签。Actions 导出的归档标签可能是构建专用标签 `s5m-agent:amd64-test`；以 `docker image ls` 的实际输出为准。为了后续部署命令统一，可以手动打一个本地标签：

```bash
sudo docker tag s5m-agent:amd64-test s5m-agent:local
```

如果导入后镜像标签与示例不同，将上面的源标签替换为实际标签。

### 5.3 创建数据目录并启动容器

```bash
sudo install -d -m 0700 /opt/s5m-agent/data
sudo docker run -d \
  --name s5m-agent \
  --restart unless-stopped \
  --init \
  -e S5M_HOSTNAME="$(hostname)" \
  -p 80:80 \
  -p 7890:7890 \
  -v /opt/s5m-agent/data:/data \
  s5m-agent:local
```

如果使用仓库内的 `s5m-agent/docker-compose.yml` 而不是上面的 `docker run` 命令，启动前先在同一个 Shell 中导出宿主机名，否则 Compose 中的 `S5M_HOSTNAME` 可能为空：

```bash
export S5M_HOSTNAME="$(hostname)"
cd s5m-agent
docker compose up -d
```

如果用 systemd、面板或其他自动化工具启动 Compose，请在其环境配置中显式设置 `S5M_HOSTNAME` 为宿主机的真实 hostname。

注意：

- `/data` 是持久化目录，保存 `config.yaml`、绑定凭据等；不要在普通升级时删除。
- 不要添加 `-p 8088:8088`。Mihomo 控制 API 不应暴露到宿主机公网。
- 如果该节点不需要给其他设备提供代理服务，可删掉 `-p 7890:7890`。
- 若端口 80 已被占用，可改成 `-p 18080:80`，随后通过 `http://节点IP:18080/` 访问。
- 若 Docker 守护进程以 root 运行，宿主机目录权限应允许容器运行用户写入。若日志报 `permission denied`，先检查目录权限和容器日志，不要直接将目录权限改为全局可写。

### 5.4 验证 Agent 容器

```bash
sudo docker ps --filter name=s5m-agent
sudo docker logs --tail 200 s5m-agent
sudo docker inspect s5m-agent --format '{{json .State.Health}}'
sudo docker exec s5m-agent /usr/local/bin/mihomo -v
curl -fsS http://127.0.0.1:80/api/machine-id
curl -fsS http://127.0.0.1:80/api/hostname
curl -fsS http://127.0.0.1:80/api/config
```

确认容器处于运行状态、日志中没有持续重启或配置解析错误，并且 Mihomo 能输出版本信息。健康检查状态可能需要等待启动周期后才显示。若 `curl` 失败，先检查 `docker ps`、端口映射和日志。

### 5.5 防火墙

只向管理网或可信管理员 IP 开放 80/TCP；7890/TCP 是否开放取决于代理用途。示例（UFW，先确认 SSH 管理端口已放行，避免锁死远程连接）：

```bash
sudo ufw allow from ADMIN_PUBLIC_IP to any port 80 proto tcp
# 只有确实需要对外提供代理时才开放：
sudo ufw allow 7890/tcp
sudo ufw status numbered
```

还要同步检查云厂商安全组。容器端口发布可能绕过部分基于 UFW 的预期限制，应在云安全组/上游防火墙一并限制来源。

## 6. RouterOS：导入 ARM64 镜像归档

> RouterOS 容器功能受设备架构、RouterOS 版本、容器设置、存储空间和设备硬件限制。请先确认目标设备支持容器功能及 ARM64 容器；x86_64 RouterOS 应使用 amd64 镜像，ARM64 RouterOS 使用 arm64 镜像。**不要把 amd64 tar 导入 ARM64 设备，反之亦然。** 容器导入命令可能随 RouterOS 版本变化，请以设备当前版本的官方 Container 文档和 CLI 的命令补全为准。

### 6.1 在 RouterOS 上准备

1. 在 RouterOS 中启用容器功能，并按该设备/版本的官方文档完成容器所需的安全设置。
2. 准备足够的持久化存储空间。镜像 tar、解包后的 rootfs 和 `/data` 配置目录都会占用存储；不要把可写数据放到会随容器重建而清除的位置。
3. 在管理电脑上从 Actions 下载 `s5m-agent-linux-arm64`（ARM64 设备）或 `s5m-agent-linux-amd64`（x86_64 设备），解压 ZIP，并确认 tar 和 SHA256 文件齐全。
4. 使用 WinBox 的 **Files** 或 SCP/SFTP（以设备已启用且支持的传输方式为准）将 tar 镜像和校验文件传到 RouterOS 可访问的存储位置。RouterOS 不一定具备 `sha256sum` 命令，请在上传前于 Linux/macOS/WSL 上完成校验。

### 6.2 建立网络接口和持久化目录

容器需要一个可用的 VETH 接口，并将其接入正确的 bridge/LAN；IP 地址、网关和防火墙规则应按现有网络规划设置。不要直接照抄示例 IP，以免与现网冲突。

以下为配置思路，不是可直接在所有 RouterOS 设备执行的完整脚本：

- 创建 VETH，例如 `veth-s5m`，为它分配一个未占用的 LAN IP/前缀；
- 将 VETH 加入目标 bridge，并配置必要的路由和防火墙；
- 在持久化磁盘目录下建立独立的容器 root directory 与数据目录；
- 建立挂载映射，把宿主持久化目录挂载到容器 `/data`；
- 通过 RouterOS Container 菜单/CLI 的本地镜像导入功能导入 tar，再创建容器并指定 VETH、root directory、`/data` 挂载和开机启动。

不同 RouterOS 版本的本地镜像导入参数存在差异。先在 CLI 输入 `/container/import-image ?` 和 `/container/add ?` 查看设备实际支持的参数，再按官方文档执行；不要假设 Linux 的 `docker load` 命令可在 RouterOS 上运行。

### 6.3 端口与管理

- 在 VETH/LAN 防火墙中仅允许管理网访问 Agent 的 80/TCP。
- 7890/TCP 仅在需要向其他设备提供代理服务时开放。
- 不要把 8088/TCP 转发到公网或不可信 LAN。
- 从管理电脑访问 `http://ROUTEROS_AGENT_IP:80/`，确认页面可打开。
- 检查 RouterOS 容器状态与日志；如果容器立即退出，优先检查镜像架构、容器支持状态、root directory 可写性、`/data` 挂载以及启动日志。

RouterOS 设备 CPU/内存和闪存资源差异很大。Mihomo 规则集和配置可能明显增加内存/存储消耗；部署前应先在目标设备上验证启动、流量和重启恢复行为，再投入生产。

## 7. Agent 与主控绑定

1. 登录 S5M 主控管理界面，进入 Agent/节点管理，创建或查看该节点的注册授权密钥。
2. 在浏览器打开 Agent 地址：`http://节点IP:80/`（若自定义宿主端口，请使用对应端口）。
3. 注册页面会在机器码上方显示主机名。Linux/Docker 部署请传入宿主机的 `S5M_HOSTNAME` 环境变量（见第 5.3 节）；否则默认值可能是容器自身的 hostname/容器 ID。\n4. 在绑定页面填写主控完整地址，例如 `http://主控IP` 或配置 TLS 后的 `https://主控域名`，以及节点注册授权密钥，然后提交。
4. 回到主控节点列表，确认该节点已出现。
5. 等待至少一个心跳周期（约 30 秒），查看主控在线状态与 Agent 日志，确认心跳和状态上报持续正常。

主控地址不要包含用户名/密码、查询参数或 URL fragment。不要将授权密钥、JWT、管理员密码或 Mihomo secret 发到公开 issue。绑定凭据已保存并不代表主控网络通信一定成功；必须继续验证在线状态。

## 8. 升级与回滚

升级前备份 Agent 数据目录：

Ubuntu/Debian：

```bash
sudo tar -C /opt/s5m-agent -czf /root/s5m-agent-data-$(date +%F-%H%M).tar.gz data
sudo docker inspect s5m-agent --format '{{.Config.Image}}'
```

下载并校验新版本 tar 后，先导入镜像。保留现有容器配置和 `/data` 卷，停止旧容器后使用新镜像重建：

```bash
sudo docker stop s5m-agent
sudo docker rm s5m-agent
# 先按 docker image ls 中的实际名称给新镜像打标签，再执行：
sudo docker run -d \
  --name s5m-agent \
  --restart unless-stopped \
  --init \
  -e S5M_HOSTNAME="$(hostname)" \
  -p 80:80 \
  -p 7890:7890 \
  -v /opt/s5m-agent/data:/data \
  s5m-agent:local
```

重建前确认新镜像已成功导入并打好标签。回滚时使用之前保存的镜像标签重新创建容器。不要删除 `/opt/s5m-agent/data`。

## 9. 故障排查

| 现象 | 检查方法 |
| --- | --- |
| Actions 没有 Artifacts | 检查两个构建 job 是否成功；失败的运行不会产生完整归档 |
| SHA256 校验失败 | 重新下载 ZIP 和 tar；不要导入校验失败的文件 |
| `docker load` 失败 | 检查 tar 是否完整、是否误把 ZIP 当成 tar、磁盘空间是否充足 |
| 容器立即退出 | `docker logs --tail 200 s5m-agent`；检查 Mihomo 配置语法、目录权限和 CPU 架构 |
| 80 页面无法打开 | 检查容器状态、端口映射、主机防火墙/云安全组及 RouterOS VETH/bridge |
| Agent 页面打开但主控离线 | 检查主控健康接口、Agent 日志、主控地址、路由/DNS/时间、注册授权密钥 |
| Mihomo 无法启动 | 查看容器日志和 `/data/config.yaml`；确认配置可被当前 Mihomo 版本接受 |
| RouterOS 无法导入/启动 | 确认设备支持容器、架构匹配、空间足够，并以当前 RouterOS 版本的官方文档核对本地导入流程 |

## 10. 上线前检查表

- [ ] 主控 `s5m-server` 和 `mihomo` 服务正常，健康接口成功。
- [ ] GitHub Actions 对应提交的 amd64、arm64 构建和 smoke test 全部成功。
- [ ] 下载的 tar 已通过 SHA256 校验。
- [ ] Agent 容器运行稳定，Mihomo 版本可显示。
- [ ] `/data` 使用持久化存储，重启容器后配置仍在。
- [ ] Agent 绑定主控，持续心跳并显示在线。
- [ ] 80/TCP 仅对管理网开放；8088/TCP 没有映射或公网暴露。
- [ ] 已验证重启恢复、升级和回滚流程。
