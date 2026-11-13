# SmartDNS per-client：宿主机 ingress attestation 合同

本文定义 Agent 容器只读挂载的宿主机证明文件。它是后续受限 host controller 的接口合同，不代表 host controller 已安装，也不代表 per-client 已可用。

## 文件位置与权限

宿主机路径：`/run/s5m-agent-ingress/ingress.json`

Agent 容器只读挂载到相同路径。文件必须满足：

- root 所有者、普通文件、不可为符号链接；
- group/world 不可写，建议 mode `0600`；
- JSON 大小不超过 8 KiB；
- `updated_at` 是 Unix 秒，必须在 90 秒内刷新（允许最多 30 秒时钟偏差）；
- 写入必须通过同目录临时文件 + fsync + rename 原子替换。

## JSON schema 示例

```json
{
  "version": 1,
  "updated_at": 1794560000,
  "interface": "eth1",
  "ipv4_address": "172.31.0.10",
  "ipv6_address": "2001:db8:31::10",
  "client_cidrs": ["192.168.50.0/24", "2001:db8:50::/64"],
  "source_ip_preserved": false,
  "firewall_ready": true,
  "firewall_persistent": true,
  "udp_ready": true,
  "tcp_ready": true
}
```

地址族可按实际客户端 CIDR 省略。CIDR 必须规范化、不可重复或重叠；拒绝默认路由、loopback、link-local、multicast、unspecified 和 IPv4-mapped IPv6。

## 证明含义

- `firewall_ready`：宿主机 nftables 规则只允许配置 CIDR 到该 Agent ingress IP 的 UDP/TCP 6055。
- `firewall_persistent`：重启后由 systemd 持久恢复，且规则集已成功应用。
- `udp_ready` / `tcp_ready`：routed Docker ingress 的对应协议链路已配置；这不是 SmartDNS 进程监听证明。
- `source_ip_preserved`：必须由真实 LAN 客户端发起 UDP 与 TCP 探测，并在 Agent 容器侧观测到完全相同的客户端源 IP 后才能设为 true。仅 Docker 同机模拟、宿主机本地探测、socket 存在或防火墙规则存在都不能设为 true。

Agent 会独立枚举容器网络接口并读取 `/proc/net/udp{,6}` 与 `/proc/net/tcp{,6}`，确认 SmartDNS 6055 已绑定到合同中的精确地址。Master 还会验证新鲜心跳、精确 CIDR 集合、地址族和 SmartDNS bind 地址。

## 安全状态机

1. Host controller 先配置 routed Docker network 和持久防火墙，写入 provisioning attestation；`source_ip_preserved=false` 时 Master 仍拒绝 provisioning。
2. 完成真实 LAN UDP/TCP 源地址验证后，host controller 才能写入 `source_ip_preserved=true`。
3. Master 下发包含合同的 Mihomo + SmartDNS 联合事务；Agent 严格验证配置，应用后确认 6055 UDP/TCP socket 精确绑定，再提交事务。
4. Agent 新心跳报告 listener ready 后，Master 才允许常规 per-client 配置发布。
5. 任何 attestation 过期、CIDR 变化、接口/地址变化、firewall 失效或监听丢失均必须 fail closed。

**注意：当前仓库已实现 Agent 对该文件的安全读取和状态合并，并新增受限 nftables host controller。`source_ip_preserved`、`udp_ready`、`tcp_ready` 只有在物理 LAN verifier 生成的 root-owned 证据文件与当前配置 SHA256 匹配且未超过 7 天时才会置 true。routed Docker lifecycle 和外部路由器静态路由仍未完成；没有真实 LAN 抓包证据时 per-client 必须保持禁用。**


## 受限宿主机防火墙控制器（新增）

仓库中的 `scripts/host-ingress/` 提供独立 systemd timer/service 和 nftables allowlist reconcile。它只管理专属 `inet s5m_agent_ingress` 表，不创建 Docker network、不改宿主机路由，也不接触 Docker socket。安装前必须由管理员按该目录 README 创建 root-owned `0600` 配置。

该组件只管理专属 nftables allowlist。`firewall_persistent` 取决于 systemd timer enabled/active；`udp_ready`、`tcp_ready`、`source_ip_preserved` 由七天有效期的物理验收证据驱动。它不会创建 routed Docker network 或配置外部路由器静态路由；这两项仍是独立阻断项。
