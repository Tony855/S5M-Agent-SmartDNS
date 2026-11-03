# S5M Agent 构建与发布矩阵

本文明确区分通用 Linux 版与 RouterOS 原生容器版。两者共用 `s5m-agent/main.go` 等业务代码，但不是同一个运行配置，也不应互相替换发布产物。

## 版本与产物

| 目标 | 构建定义 | 发布产物 | 适用环境 |
|---|---|---|---|
| 通用 Linux 容器 | `s5m-agent/Dockerfile` | `ghcr.io/tony855/s5m-agent:dev`、版本标签及 SHA 标签 | 标准 Linux Docker/兼容容器运行时 |
| RouterOS AMD64 | `s5m-agent/Dockerfile.routeros` | `s5m-agent-routeros-amd64.tar` 和 SHA-256 文件 | RouterOS `/container`，仅 AMD64/x86_64 |
| RouterOS ARM64 | `s5m-agent/Dockerfile.routeros` | `s5m-agent-routeros-arm64.tar` 和 SHA-256 文件 | RouterOS `/container`，仅 ARM64/aarch64 |

## 为什么不共用一个镜像配置

- 两个目标的 CPU 架构可以相同，但初始化脚本、目录约定和服务配置不同。
- 通用 Linux 版使用 `/usr/local/bin/mihomo`；RouterOS 版将可升级内核放在持久化目录 `/data/bin/mihomo`。
- RouterOS 版使用专门的初始化脚本和 s6 服务定义，并设置 `S5M_ROUTEROS=1`。
- RouterOS 导入文件必须与设备架构匹配。AMD64 归档不能导入 ARM64 设备，反之亦然。
- 两个版本都应复用同一套 Agent 注册、鉴权、心跳、配置同步和内核更新业务逻辑；环境差异集中在 Dockerfile、启动脚本和明确的运行时适配中。

## 发布流程

1. 在功能分支开发，先运行 Agent 测试、服务端测试、静态检查和构建。
2. CI 分别构建通用 Linux 多架构镜像，以及 RouterOS AMD64/ARM64 归档。
3. 每个 RouterOS 归档必须附带 SHA-256 文件；导入前先验证校验和。
4. 只有通过 CI 的候选版本才能进入稳定发布流程。RouterOS 设备的实际导入、启动、持久化、网络与重启测试仍须在目标设备上完成。
5. GitHub Actions 的 Linux Runner 成功，不代表真实 RouterOS 设备已验收；TUN 在设备实测前保持关闭。

## 使用原则

- Linux Docker 主机：使用 GHCR 上的通用 Linux 镜像。
- RouterOS：使用与设备架构匹配的 RouterOS 专用 `.tar` 归档，不要直接拿通用 Linux 标签替代。
- 升级前备份配置并保留现有持久化 `/data`；重建容器时不要误删数据目录。
- 两个版本共享源码不等于共享发布物。版本号应保持可追踪，问题修复应在共同源码中完成，再由两条构建路径分别验证。
