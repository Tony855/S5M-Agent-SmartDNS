# S5M RouterOS 原生 Container Agent（RouterOS 7.21.5）

构建目标与通用 Linux 版的区别、镜像标签及发布流程见：[S5M Agent 构建与发布矩阵](S5M_AGENT_BUILD_MATRIX_CN.md)。

本方案让 S5M Agent 与 Mihomo 作为一个 Linux 容器运行在 RouterOS 的原生 `/container` 子系统中。主控仍只负责 Agent 注册、心跳、节点 Mihomo YAML 同步及受支持架构的 Mihomo 内核更新；**不提供、也不恢复主控远程管理 RouterOS 容器的页面或 API**。

## 支持范围

- RouterOS 目标版本：7.21.5（必须在实际设备验证）。
- CPU：AMD64/x86_64 或 ARM64/aarch64。
- 存储：内部存储；容器 root-dir 和持久化 `/data` 挂载都必须位于可写的内部存储路径。
- Linux 用户态：Alpine Linux 3.24 amd64/arm64；使用 s6-overlay v3（当前固定版本 3.2.3.2）作为 PID 1 和进程监督器。这不是 RouterOS 原生二进制，而是 RouterOS 容器中的 Linux 用户态。
- Mihomo 更新：amd64 和 arm64 使用官方 Linux 发布资产，主控下发的版本和 SHA-256 校验仍有效；更新后的内核写入持久化 `/data/bin/mihomo`，重建容器后仍保留。只有保持同一 `/data` 挂载且目标内核可在设备上运行时才保证持久化。
- TUN：默认关闭。RouterOS 容器环境对 TUN、NET_ADMIN、设备访问和策略路由的支持受设备/版本限制；不要默认认为 Linux TUN 能在 RouterOS 容器中可用。基础代理和节点注册/心跳应先在不启用 TUN 的配置下验证。

## 构建与 CI

工作流使用 `s5m-agent/Dockerfile.routeros` 分别构建 amd64、arm64 镜像，并导出 Docker image tar 和 SHA256 文件。RouterOS 镜像和通用 Linux Agent 镜像统一使用 s6-overlay v3：由 `/init` 作为 PID 1，Mihomo 与 Agent 作为独立的 longrun 服务监督；初始化脚本只负责初始化持久化内核与配置，不承担后台进程循环。CI smoke test 检查镜像架构、`/init`、服务定义、Agent 与 Mihomo 二进制和默认配置；GitHub-hosted runner 不等于真实 RouterOS，因此 CI 成功不代表设备导入、启动、硬件性能或 TUN 已通过验证。

## RouterOS 设备准备

1. 先备份 RouterOS 配置；确认该型号支持容器功能、内部存储有足够空间，并确认容器功能/安全设置符合 MikroTik 官方文档。
2. 执行 `/system/resource/print`，确认 `architecture-name` 是 `x86_64` 或 `arm64` 对应的设备架构。不要按 CPU 厂商猜测；RouterOS 字段通常显示 `x86_64` 或 `arm64`。
3. 在 GitHub Actions 下载与架构匹配的 `s5m-agent-routeros-amd64` 或 `s5m-agent-routeros-arm64` artifact，解压并在 Linux/macOS/WSL 上执行对应 `sha256sum -c`。
4. 上传 `.tar` 到 RouterOS 内部存储。不要把 tar 直接放到外接盘路径，也不要把 AMD64 镜像导入 ARM64 设备。
5. 创建位于内部存储的 root-dir 与独立数据目录。通过 `/container/import-image ?`、`/container/add ?` 查看 RouterOS 7.21.5 当前设备实际参数，再按设备支持的语法导入镜像、设置 root-dir、VETH、mounts 和 start-on-boot。不同设备的目录前缀和导入参数可能不同，不能盲目复制另一台设备的绝对路径。

## 数据挂载与端口

将 RouterOS 内部存储中的持久化目录挂载到容器 `/data`。至少需要持久化：
- `/data/agent.json`：主控地址和专属注册 Token；
- `/data/machine-id`：在容器无可用系统 machine-id 时生成的稳定机器码；
- `/data/config.yaml`：Mihomo 配置；
- `/data/bin/mihomo`：Agent 更新后的内核。

将容器网络接入一个受控的 LAN/管理网段。只允许管理终端访问 Agent 注册页 TCP/80；只有确实需要为其他设备提供代理时才开放 TCP/7890。Mihomo 控制 API 8088 仅监听容器回环地址，不要转发到 RouterOS 或公网。

## 注册、心跳与配置同步

1. 从可信管理终端打开 `http://<Agent-VETH-IP>/`，输入主控 URL 和该机器码的专属授权 Token。
2. 主控节点列表出现该节点后，等待一个心跳周期（约 30 秒），确认 online、CPU 架构、Mihomo 版本、连接数和流量统计等状态持续更新。
3. 在主控配置该节点独立 Mihomo YAML；配置必须包含非空 `secret`、`tun` 和 `dns` 块。建议先使用 `tun.enable: false`。
4. Agent 下次拉取时校验 YAML、保留本地 Mihomo API secret、先备份旧配置，再校验并应用新配置。查看主控状态中的 `config_sha256` 和 `last_error` 判断同步是否成功。
5. 主控 Mihomo 更新流程只对 Agent 报告的 Linux amd64/arm64 运行时提供官方 Linux 内核资产。若主控未识别到正确的容器运行时架构或节点未报告健康的 Mihomo 版本，应先排查心跳，不要强制更新。

## 升级、回滚和内部存储

- 正常重建容器时，必须复用同一内部存储 `/data` 目录；否则授权、机器码、配置和持久化内核都会丢失。
- Mihomo 更新命令会先下载、校验 SHA-256、执行 `-v` 与当前配置校验，再将旧内核改名备份；健康检查失败时恢复旧内核。
- 不要删除 `/data/bin/mihomo.previous` 来手工处理异常更新；先查看 Agent 命令结果与容器日志。s6-overlay 的初始化脚本会在服务启动前检查并恢复残留的旧内核备份。
- RouterOS 内部闪存写入寿命和空间都有限。持续更新规则集、写日志或频繁更换内核会产生额外写入；确保内部存储剩余空间充足，并先在非生产设备验证重启与回滚。

## 验收清单

- [ ] 镜像架构与 `/system/resource/print` 输出一致。
- [ ] 镜像导入成功，容器可持续运行且开机自启。
- [ ] `/data` 指向内部存储，重启/重建后机器码、Token、配置保持不变。
- [ ] Agent 注册成功，主控心跳连续更新。
- [ ] 主控发布节点 YAML 后，Agent 成功同步并显示对应配置 SHA-256。
- [ ] amd64/arm64 Mihomo 内核更新与回滚在目标设备实测成功。
- [ ] 8088 未暴露；80/7890 仅按需开放。
- [ ] TUN 未验证前保持关闭。
