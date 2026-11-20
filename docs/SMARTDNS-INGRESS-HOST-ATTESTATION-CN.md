# SmartDNS per-client：宿主机 ingress attestation 合同

## 当前实现状态（2026-11-15，PR #242）

仓库已包含 Agent 对 host attestation 的安全读取、root-only nftables controller、独立 routed Docker network lifecycle helper、物理抓包证据 verifier，以及 Master/Agent 的 readiness 和事务校验。PR #242 仍为 Draft；本文件描述的是代码合同，不表示目标生产主机或真实 LAN 已验收。

**代码提供 IPv4 per-client ingress，并提供显式 opt-in 的双栈 IPv4/IPv6 provisioning 路径；IPv6 默认关闭且尚未通过生产现场验收。** 两个部署入口和 network lifecycle helper 都实现了 IPv6 前置条件、loopback-only `::1` host mapping、routed `::` 空 HostPort、IPv6 默认出口路由校验和失败回滚。不要把 GitHub Actions/namespace 试验当成真实 LAN 源地址证明；现场验收完成前必须保持生产 IPv6 ingress 关闭。

## 文件位置与权限

宿主机路径：/run/s5m-agent-ingress/ingress.json。Agent 以只读 bind mount 读取同一路径。

文件必须满足：

- root 所有者、普通文件、不可为符号链接；
- group/world 不可写，生产 writer 使用 mode 0600；
- JSON 不超过 8 KiB；
- updated_at 为 Unix 秒，Agent 要求 attestation 在 90 秒内刷新，并容忍有限时钟偏差；
- host controller 通过同目录临时文件、fsync 和 rename 原子写入；
- controller 每次 reconcile 前先使旧 attestation 失效，失败时不得残留 ready=true。

示例字段（以下是 IPv4-only 示例；双栈 opt-in 时可填写 IPv6 地址并配置 IPv6 CIDR）：

- version：合同版本 1；
- updated_at：最近一次 host controller reconcile 时间；
- interface：实际接收 LAN 流量的宿主机物理接口；
- ipv4_address：Agent routed ingress endpoint 的固定 IPv4；
- ipv6_address：IPv4-only 时为 null；双栈 opt-in 时为专用 routed IPv6 endpoint 地址；
- client_cidrs：与启用的 ingress 地址族精确匹配、规范化且互不重叠的可信 IPv4/IPv6 客户端 CIDR 集合；
- source_ip_preserved、firewall_ready、firewall_persistent、udp_ready、tcp_ready：只能由 host controller 根据实际状态和已验证证据生成，不能由部署配置或人工布尔值代替。

## 证明来源

host controller 的职责是：

1. 校验 root-owned 配置、接口状态、地址族和精确 CIDR 集合；
2. 只管理专属 inet s5m_agent_ingress nftables table；
3. 对每个配置的 client CIDR，仅允许从指定物理接口进入、目标为精确 ingress IP、协议为 UDP/TCP、目标端口为 6055 的流量；对同一 ingress IP 的其他来源/接口/端口流量执行 drop；
4. read-back 比较完整 owned table，拒绝额外 chain、set、object 或任何未识别规则；
5. 仅当 systemd timer 的 is-enabled 输出精确为 enabled 且 timer active 时，才报告持久化 firewall readiness；
6. 读取 host 专属 root-only HMAC key 和物理验收 evidence，核对 evidence v3 签名、配置 SHA256、CIDR 覆盖、capture 时间窗、当前 Agent immutable container ID、运行时 PID、Docker State.StartedAt 和 routed Docker network ID；
7. 每 30 秒刷新 attestation；物理 evidence 最长有效 7 天，配置、容器、网络或 endpoint 身份变化会使旧 evidence 失效。

firewall_ready 表示 live nftables allowlist 已精确应用；firewall_persistent 表示 systemd timer 会持久刷新。source_ip_preserved、udp_ready 和 tcp_ready 只有在真实 LAN 客户端的 UDP 与 TCP 数据包同时出现在宿主机物理接口和 Agent network namespace，且两侧源/目的地址与端口完全一致后才可为 true。单机 Docker namespace lab、宿主机本地探测、期望配置、socket 存在或手工设置布尔值都不能生成物理证明。

物理 evidence v3 由 scripts/lab/smartdns-dns-ingress/physical-ingress-verify.py 根据双端 pcap、capture manifest v3 和实际客户端 probe JSONL 生成；签名同时绑定 Agent container ID、PID 与 Docker State.StartedAt。Agent 容器每次重启都会使旧证明失效，即使 Docker container ID、network ID 和 ingress IP 保持不变，也必须重新抓包验收。证据使用该主机安装时创建的 evidence.key 签名。不得跨主机复制 key/evidence，不得手工编辑 evidence JSON。

## Routed Docker ingress 生命周期

network-lifecycle.py 是独立的 root-only helper，与 nftables controller 共用 flock：

- 创建/复用带所有权标签且配置完全匹配的专用 IPv4 routed bridge；满足显式双栈条件时可同时配置 IPv6 routed subnet；
- 设置固定 ingress IPv4、trusted_host_interfaces 和较低 gateway priority；
- attach 前调用 controller 的只读 verify，要求 live nft table、接口、attestation、timer 均满足 provisioning 条件；
- attach 后验证 Agent 仍只有普通 Docker bridge 作为默认 IPv4 egress route；
- 重复 provision 幂等；attach/route 验证失败时回滚本次新增 endpoint/network；
- uninstall 只移除确认为本项目所有、且没有意外容器连接的 routed endpoint/network；
- 输出上游路由器静态路由命令，但不登录或修改路由器。

部署脚本的 per-client 开关默认关闭。启用 IPv4 后，6055/TCP 和 UDP 的宿主机随机端口映射仅绑定 127.0.0.1；routed endpoint 对应的 Docker HostPort 必须为空。远端 LAN 客户端通过路由器到 Docker ingress subnet 的静态路由直达容器 ingress IP，不经过 published-port NAT。6053 仍为容器内部共享 SmartDNS loopback 端口，DNS_PORT 保持 0；不得发布公网 DNS 端口。Agent 不挂载 Docker socket。

路由器静态路由必须由管理员按 helper 输出手动配置。示例目标是 Docker ingress subnet，下一跳是 Docker host 在可信 LAN interface 上的地址；不能把 client CIDR 错当成目标路由网段。

## Agent 与 Master 的二次验证

Agent 不把 Master 合同中的 Ready=true 当成证据。每次 per-client 联合配置事务在任何文件/服务 mutation 前，重新读取 root-owned 新鲜 host attestation，要求 source-IP、firewall、持久化、UDP/TCP 物理证明为真，并将 ingress IP、CIDR 集合与 Master contract 精确比较；随后独立枚举 Agent namespace 的活动非 loopback 接口。候选配置启动后、写入事务 committed marker 前再次读取 attestation 和 interface state；若期间 proof 过期或地址消失，事务必须回滚。

Agent 还会检查 SmartDNS 6055 UDP/TCP socket inode 确实由同一个 SmartDNS PID 持有，并只允许绑定合同中的精确 ingress IP，不允许 wildcard。s6 service 在启动前验证持久化 per-client 配置，并运行期间定期复查；attestation 过期或地址丢失时停止 SmartDNS child process。shared-mode 使用原有 validator/runtime，不因 per-client 功能放宽全局校验。

Master 保留现有 ingress readiness gate：普通 per-client 发布必须有新鲜 Agent 心跳、source-IP proof、精确防火墙 CIDR、持久化状态、地址族和 SmartDNS exact bind。WebSocket 的 provisioning recovery 只允许在完整 host proof 存在时下发合同；直接 SmartDNS command path 仍走完整 readiness gate。Master 通用设置 API 目前仍拒绝用户保存 per_client；在现场验收和发布批准前不得移除此拒绝。PR #217/#218 保持 Draft。

## 必须完成的现场验收

以下项目不能由 GitHub Actions 或同机 namespace 模拟替代：

1. 在目标 Docker 主机安装 controller，检查 nftables 规则、systemd timer、provision/uninstall 和主机重启后的恢复；
2. 在实际上游 LAN 路由器添加 helper 输出的静态路由；
3. 从每个实际启用的 IPv4/IPv6 client CIDR 至少一台真实设备发起 UDP 与 TCP probe，确认 host LAN pcap 和 Agent namespace pcap 的源 IP/端口完全一致；
4. 在 SmartDNS 启用后，从每个真实客户端验证 A/AAAA、UDP/TCP、预期 CIDR group 和未映射客户端 fail-closed；
5. 对真实 Mihomo listener 执行代理 CONNECT，验证真实 DoT 上游路径和外部出口 IP 与预期代理逐一对应；
6. 完成 TUN on/off、SmartDNS enable/disable、Agent 断线重连、Master/Agent 重启、重复命令、配置事务中断和 rollback 矩阵。

**IPv6 代码路径为 opt-in，不代表生产可用。** 只有显式启用 `ENABLE_PER_CLIENT_INGRESS_IPV6=1` 且 Docker default bridge、可信 host interface、`network.json`、loopback-only `::1` mappings、routed `::` empty-HostPort mappings 和默认 IPv6 egress 全部通过实时检查时，helper 才会尝试 provision。任一检查失败必须 fail-closed 并回滚。生产环境仍须保持 IPv6 关闭，直到真实路由器静态路由、LAN 客户端 IPv6 UDP/TCP 双端抓包、SmartDNS group、代理 CONNECT/DoT 和外部出口均完成现场验收。

CI 的 Server tests/race/vet、Agent tests/race/vet、AMD64/ARM64 build/runtime smoke、installer validation、host lifecycle lab 和 real SmartDNS daemon lab 只证明代码与隔离 runner 行为。它们不证明物理 LAN 路由、真实代理 CONNECT/DoT 或公网出口 IP。
