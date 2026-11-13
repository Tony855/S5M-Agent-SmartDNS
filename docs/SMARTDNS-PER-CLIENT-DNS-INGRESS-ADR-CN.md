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

### A. 显式 DNS ingress + Docker bridge DNAT（优先实验，不直接上线）

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

结论：作为首选 PoC。只有真实抓包证明 SmartDNS socket peer IP 与终端源 IP 一致，并验证出站代理后，才能允许 per_client。

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
