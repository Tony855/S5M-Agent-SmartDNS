# SmartDNS per-client DNS 入站架构决策记录（ADR）

状态：Draft / 待真实网络实验
日期：2026-11-13
关联：Issue #213、PR #217、PR #218

## 1. 问题与目标

目标是让终端客户端 CIDR 映射到唯一的 Mihomo 代理出口，并由 SmartDNS 根据实际 DNS 请求来源选择对应 DoT 上游组。必须满足：
- SmartDNS 收到的来源地址可验证地代表被映射的客户端身份；
- 每个 CIDR 只能使用其绑定的代理，不得回落到其他客户端组或 DIRECT；
- UDP/TCP DNS、IPv4/IPv6 均有明确行为；
- 不把 SmartDNS、Mihomo 控制 API 或显式代理端口暴露到公网；
- 保留现有 shared DNS 路径和旧 Agent 兼容性；
- 任何不能证明来源身份的拓扑都必须 fail-closed。

## 2. 已确认的现有数据路径

1. Agent 默认启用 Mihomo TUN，DNS hijack 同时包含 any:53 与 tcp://any:53。
2. Mihomo 普通 DNS nameserver 被控制器改写为 127.0.0.1:6053；国内策略可使用 127.0.0.1:6054。
3. SmartDNS 默认只监听 IPv4/IPv6 loopback 的 6053，国内专用监听 6054；Agent 运行时校验也拒绝其他 bind 地址。
4. Docker Agent 使用 bridge 网络。TUN 首先接管 Agent 容器网络命名空间内的流量；仅授予容器 NET_ADMIN 和 /dev/net/tun 并不会自动接管宿主机或其他 LAN 客户端。
5. 部署脚本 DNS_PORT=0 默认不发布 SmartDNS 端口。显式设置 DNS_PORT 时，当前脚本把宿主机指定地址/端口映射到容器 6053 TCP/UDP，但 SmartDNS 实际只监听容器 loopback；这不能作为可用 LAN 入站方案。
6. 因此，当前 Mihomo → loopback SmartDNS 链路只证明本机 resolver 转发，不证明 SmartDNS 可以观察原始 LAN 终端 IP。也没有证据证明 TUN DNS hijack 会把原始终端 IP 传递给 loopback 上游。

## 3. 方案评估

### A. 显式 DNS ingress + Docker bridge 默认 NAT 发布（已发现 SNAT，不作为 per-client 实现）

新增独立 SmartDNS ingress listener（建议容器内专用端口 6055），由运维显式启用。部署层仅将宿主机明确指定的 LAN 地址和端口发布到容器 6055 TCP/UDP；不得默认发布到 0.0.0.0。宿主机防火墙必须按可信客户端 CIDR 限制来源。

优点：
- DNS 客户端可直接查询 Agent ingress，避免先经过 Mihomo DNS 再由 loopback 重新发起查询；
- SmartDNS 可按到达 ingress socket 的来源地址执行 group-match -client-ip；
- 与现有 Mihomo → loopback shared 路径分离，避免改变 shared 默认行为。

风险/必须实验：
- Docker bridge 的 DNAT、userland-proxy、IPv4/IPv6、不同 Docker/iptables/nftables 后端可能改变 SmartDNS 看到的 peer IP；不能假定所有部署都保留源地址。
- 需要确认端口发布只绑定用户指定 LAN 地址，不允许公网绑定；防火墙规则需要在部署/升级/回滚中原子维护。
- SmartDNS 的 per-client 监听必须与 Mihomo TUN 路由避免环路；DoT upstream 通过生成的 loopback SOCKS listener 走指定代理。
- 需要检测宿主机 LAN 地址变更、容器重建、端口冲突和防火墙规则漂移。

结论：默认 bridge + published-port NAT 仅作为负向基线，不作为 per-client 实现。PR #221 的 GitHub-hosted Docker 实验已观察到两个不同 bridge 客户端的 UDP/TCP 源地址均被改写为宿主机默认 bridge 网关 172.17.0.1。该结果只覆盖跨 Docker bridge 到宿主机发布端口的测试拓扑，不代表物理 LAN 入站结果。

### B. 独立 resolver 实例 + 源地址分流

为每个 CIDR 启动独立 SmartDNS 实例/监听端口，再由宿主机或容器入口按源 CIDR 将 UDP/TCP DNS 流量分配到对应实例。

优点：每个 resolver 可固定一组上游，隔离边界更直观。

风险：
- 仍然依赖入口层保留来源地址；如果入口先做 SNAT，多个实例也无法知道终端身份。
- 增加进程、监听端口、健康检查、资源限制、事务回滚和生命周期复杂度。
- IPv4/IPv6、UDP/TCP 与 TUN 的分流规则必须完全一致。

结论：作为 A 无法满足隔离或未来多租户隔离要求时的备选，不作为第一实现。

### C. 继续通过 Mihomo loopback nameserver

客户端 DNS → Mihomo DNS/TUN → SmartDNS loopback。

结论：仅用于 shared 模式。不能将其作为 per-client 源地址识别路径，除非未来引入并验证可传递客户端身份的专用协议/元数据机制。普通 loopback DNS 转发不能满足当前验收条件。

## 4. 拓扑支持矩阵（目标行为）

| 客户端接入方式 | 能否直接按终端 CIDR 匹配 | 处理要求 |
|---|---|---|
| 终端直接查询 Agent 的受控 DNS ingress，未经过 SNAT | PoC 验证通过后支持 | 以 SmartDNS 实际 peer IP 为准 |
| 路由器仅做无 SNAT 的四层 DNAT/转发 | 逐设备/固件验证后支持 | 抓包确认原始源 IP |
| 路由器自身作为 DNS forwarder/cache | 通常只能识别路由器地址 | 不得冒充识别终端；明确标记不支持终端 CIDR |
| 客户端 DNS 被 Mihomo TUN 劫持后转发到 127.0.0.1 | 当前不支持 per-client | 仅保留 shared 模式 |
| Agent 宿主机/容器本机 DNS 请求 | 不属于 LAN 客户端 CIDR | 使用独立本机/shared 策略 |

## 5. 安全与配置契约

- 新 ingress 默认关闭；shared 现有 loopback 监听不变。
- ingress 必须绑定显式配置的 LAN 地址/接口和专用端口；拒绝空地址、通配公网绑定、端口冲突和未授权 CIDR。
- Docker 发布规则必须显式绑定指定宿主机 LAN IP；防火墙仅允许配置的可信 CIDR；升级失败必须恢复旧容器、旧端口映射和旧防火墙规则。
- SmartDNS 只接受生成器管理的 per-client group-match 与对应 DoT 上游；DoT 必须保留 SNI 和证书主机名验证。
- 未匹配来源、来源地址不可信、映射重叠、代理不存在/未启用、Listener 缺失或探测失败时，必须拒绝请求/配置，不能退回其他组或 DIRECT。
- Mihomo 的 per-client SOCKS Listener 和 SmartDNS group 必须由同一映射集合一次生成；禁止两次独立分配端口。
- 现有 loopback 6053/6054 校验只能在 ingress 实现后按“共享监听 + 显式 ingress listener”扩展，不能简单放宽为任意 bind。

## 6. 必须完成的实验矩阵

每项都要记录客户端源地址、容器入口抓包、SmartDNS peer/client IP、命中 group、Mihomo 代理 Listener、实际外部出口 IP。

| 维度 | 最低覆盖 |
|---|---|
| 地址族 | IPv4、IPv6 |
| 传输 | UDP/53、TCP/53 |
| Docker | bridge DNAT；启用/禁用 userland-proxy；iptables 与 nftables 环境（可用时） |
| 入站 | 终端直连；路由器无 SNAT 转发；路由器 DNS forwarder（验证其限制） |
| TUN | ENABLE_TUN=1/0；确认 ingress 不被 DNS hijack 误接管或递归 |
| 安全 | 非授权 CIDR、伪造/异常来源、未映射客户端、端口冲突、公网接口不可达 |
| 生命周期 | 容器升级/回滚、主机重启、LAN IP 变更、防火墙恢复 |
| 出站 | 两个不同 CIDR 分别绑定两个代理；通过外部测试端点确认出口 IP 不串线 |
| 故障 | 代理离线、SmartDNS 退出、配置 hash 不匹配、WS 断线/重连、Master 重启 |

单元测试、YAML 断言和容器内 loopback dig 不能替代以上网络验收。

## 7. 实施顺序与合并门槛

1. 在隔离测试主机完成 A 方案 PoC：发布独立端口、从不同客户端网段发起 UDP/TCP 查询，抓包并记录 SmartDNS 实际 peer IP。
2. 若 A 无法在目标 Docker/IPv6 网络中稳定保留来源地址，停止该实现并评估 macvlan/ipvlan 或 B；不得用 SNAT 后的地址继续宣称 per-client。
3. 在 PoC 成功后再实现配置模型、Agent 安全校验、部署端口/防火墙事务、健康检查和恢复。
4. 再接入 PR #217 的 WebSocket 双配置事务与 PR #218 UI；在真实 Agent 验收前，两者继续 Draft。
5. 通过 Server/Agent/race/vet、AMD64/ARM64、installer 和真实网络验收后，才移除 per_client fail-closed guard 并合并。

## 8. 当前结论

本 ADR 不批准立即开放 per_client。首选开展 A 方案源地址保留 PoC。当前生产配置保持 loopback-only、DNS_PORT 默认关闭、per_client fail-closed。


## 9. PR #221 实验结果与候选拓扑修订（2026-11-13）

### 9.1 已实测的负向结果

PR #221 在 GitHub-hosted Linux Docker runner 上创建两个客户端 bridge 网络：
- 172.30.10.0/24，客户端 172.30.10.10
- 172.30.20.0/24，客户端 172.30.20.10

两个客户端分别通过宿主机默认 bridge gateway 的已发布端口发起 DNS-shaped UDP 与 TCP 请求。测试接收容器四次均观察到来源 172.17.0.1，而不是客户端地址。自动化实验已合并到 main。

因此：跨 Docker bridge → 宿主机默认 bridge gateway → published port 这条路径存在源地址 SNAT，不能用于按原始客户端 CIDR 匹配。该结果不能外推到物理 LAN 客户端直达宿主机 LAN 接口的路径。

### 9.2 新的首选 PoC：routed bridge + direct routing（不经过 host published-port NAT）

Docker 官方文档说明，bridge network 的 gateway mode 可设置为 routed：不设置 NAT/masquerading，容器出站使用容器地址；外部客户端必须具有到容器网段、经 Docker 宿主机 LAN 地址的路由。对特定网络接口可使用 trusted_host_interfaces 限定允许 direct routing 的入站接口。

候选实验：
1. 创建独立 Docker bridge 网络，分别设置 IPv4/IPv6 gateway mode 为 routed（按目标主机 Docker Engine 版本支持情况配置）。
2. 将 Agent/SmartDNS 专用 ingress 绑定到容器在该网络中的明确地址和专用端口，不使用宿主机 -p published-port 转发。
3. 在 LAN 路由器/客户端侧配置到 Docker ingress 子网的静态路由，下一跳为宿主机 LAN 地址。
4. 使用 bridge network 的 trusted_host_interfaces 将 direct routing 限定在指定 LAN 接口；不使用全局 allow-direct-routing，除非目标 Docker 版本/拓扑无法使用接口级约束且已评估风险。
5. 在宿主机防火墙按真实客户端 CIDR、协议和专用端口限制入站；同时验证 Docker 管理的 firewall 规则不会绕过预期策略。
6. 从两个真实 LAN 客户端网段发起 UDP/TCP 查询，同时在宿主机 LAN 接口、容器 ingress 接口抓包，并记录 SmartDNS socket peer IP。
7. 只有客户端源 IP 在容器内保持不变，才进入 SmartDNS group-match + Mihomo SOCKS + 外部出口 IP 联合验收。

参考：
- Docker port publishing/direct routing/gateway modes: https://docs.docker.com/engine/network/port-publishing/
- Docker bridge trusted host interfaces and routed gateway modes: https://docs.docker.com/engine/network/drivers/bridge/
- Docker macvlan limitations and host communication: https://docs.docker.com/engine/network/drivers/macvlan/

### 9.3 方案限制与回退

- routed bridge 需要 LAN 路由器/网络允许到容器子网的路由；云厂商、VPS 网络或上游交换网络可能不允许。
- Docker Engine 版本、iptables/nftables 后端、IPv4/IPv6 路由和宿主机转发策略必须实测；不得假设配置项在所有发行版均可用。
- 若 routed bridge 无法在目标网络中安全部署，评估 macvlan/ipvlan L2 或 host-level DNS ingress proxy；macvlan 需评估交换机多 MAC、云平台限制和 host-container 通信限制。
- 不能退回普通 published-port NAT 并将 SNAT 后的宿主机地址伪装成客户端地址。
- 在真实 LAN 抓包验收之前，per_client 继续 fail-closed；PR #217/#218 继续 Draft。


### 9.4 Routed bridge PoC 结果（GitHub Actions Docker Engine 29.4.2）

PR #223 的同主机 Linux 网络命名空间实验已通过：
- 两个模拟 LAN 客户端分别使用 192.168.50.10 与 192.168.50.20；
- 客户端通过宿主机 LAN bridge 的三层路由访问 routed-mode Docker 容器地址 172.31.0.10；
- 目标 Docker bridge 设置 gateway_mode_ipv4=routed，并将 trusted_host_interfaces 限定为模拟 LAN bridge；
- UDP 与 TCP 两种请求均在接收容器内观察到原始来源地址 192.168.50.10 / 192.168.50.20，没有被改写为宿主机地址。

结论：在 Docker Engine 29.4.2、同主机 Linux netns 模拟 LAN 的实验拓扑中，routed bridge + trusted_host_interfaces 可保留两个客户端的源地址；默认 published-port NAT 对照组仍将两客户端都改写为 172.17.0.1。

该结果提升了 routed bridge 作为首选实现的可信度，但仍不是生产验收：未经过物理 LAN 交换机/路由器、未测试 IPv6、iptables/nftables 多环境、真实 Agent SmartDNS peer IP、SmartDNS group-match、Mihomo SOCKS 选择和外部代理出口。生产实现仍需在目标部署环境重复。


### 9.5 真实 SmartDNS daemon + 双网络 + 分组到 SOCKS 监听验证（PR #224/#225/#229/#231）

在同一隔离 Linux runner 中，现已完成比 Python 接收器更接近运行时的集成实验：
- 使用 Agent 镜像所固定的 SmartDNS 源码版本构建并启动真实 SmartDNS daemon。
- SmartDNS 容器同时连接普通 Docker bridge 与第二张 routed-mode ingress bridge；容器默认路由仍指向普通 bridge gateway，LAN 模拟客户端通过第二张 routed bridge 访问 172.31.0.10:6055。
- 普通 bridge 出站路径未被 ingress 网络替换；宿主机发布端口只绑定 127.0.0.1 临时端口，LAN 模拟客户端直接路由到容器 ingress IP。
- 两个映射客户端 192.168.50.10/32 与 192.168.50.20/32 分别通过 UDP/TCP 查询，真实 SmartDNS 返回各自分组的确定性答案。
- 第三个未映射客户端 192.168.50.30/32 通过 UDP/TCP 查询，没有得到 A 记录；每个 per-client DoT upstream 使用 `-exclude-default-group`，避免被默认组继承。
- 两个 loopback SOCKS5 observer 分别监听生成配置中的代理端口。对未命中静态 address 规则的上游查询，客户端 A 只触发其对应 SOCKS listener 的 CONNECT，客户端 B 只触发另一监听；未映射客户端不会触发任何一个监听。
- 真实 SmartDNS parser 还验证了生成器的语法要求：`group-match -client-ip` 必须处于 `group-begin` / `group-end` 作用域；原先在顶层输出 `group-match ... -g ...` 会被 daemon 报 `invalid parameter`，现已修正为组内规则。

重要限制：
- SOCKS observer 在记录 CONNECT 后故意拒绝隧道；它验证 SmartDNS 的 group-to-SOCKS 选择，不是实际 Mihomo 进程，也不证明代理服务器可用或公网出口 IP。
- 该实验仍是同主机 IPv4 netns/Docker 模拟，不等同于物理 LAN/真实路由器验收。
- 尚未验证生产 Agent 部署脚本的双网络生命周期、持久化来源 CIDR 防火墙、真实路由器静态路由、IPv6、Agent 运行时配置校验/状态上报，以及真实 Mihomo 出口 IP 的端到端相关性。

因此，routed bridge + SmartDNS group-match + 命名 SOCKS listener 已有同主机 IPv4 自动化证据；但生产 per-client 功能仍不批准启用。Server API 继续拒绝保存 per_client 模式，Agent validator 继续拒绝未经 ingress provisioning 的配置，PR #217/#218 继续 Draft。
