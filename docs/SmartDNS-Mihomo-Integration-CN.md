# SmartDNS 缓存接入说明（S5M / Mihomo）

本方案把 SmartDNS 作为可选的本地缓存上游；Mihomo 仍然是客户端 DNS 入口和 Fake-IP/TUN 路由控制器。

## 推荐拓扑

## S5M 自动配置策略

- SmartDNS 健康检查同时执行本机 UDP 和 TCP DNS A 查询；只有进程、配置策略和两种查询均正常时，主控才将 Agent 的普通 `dns.nameserver` 切换到 `127.0.0.1:6053`。
- SmartDNS 不健康时，下一次 Agent WebSocket 配置同步自动恢复节点原有 `dns.nameserver`；运行时切换不写回节点持久配置。
- SmartDNS 默认使用 Cloudflare/Google 的 DNS-over-TLS 上游，连接端点使用字面 IP 和明确 TLS 主机名，避免 Bootstrap DNS 递归。
- 共享出口模式下，Mihomo 可使用 `find-process-mode: strict` 和 `PROCESS-NAME,smartdns,<代理名>` 为整个 SmartDNS 进程选择同一个出口；这不能区分客户端，不能用于按客户端独立出口。按客户端模式必须由 SmartDNS 的 `group-match -client-ip` 选择独立组，并让各组的加密上游通过各自命名的 SOCKS5 `proxy-server` 出口。Agent 当前仍拒绝这些尚未接入完整运行时的指令。
- TUN 同时劫持 UDP/TCP 53；默认只排除本地/私有网段和代理节点出口地址，不再把公共 bootstrap DNS 地址自动加入 `route-exclude-address`，避免强制它们绕过 TUN。
- SmartDNS 不健康时，自动回退的普通 DNS 上游改为 Cloudflare/Google DoH，而不是自动降级到明文 UDP DNS。
- Agent 拒绝明文 SmartDNS 上游 `server` / `server-tcp`，并在下发配置前做语法预检；配置替换失败会恢复旧文件、重启旧服务并重新验证 UDP/TCP。


共享模式：客户端 → Mihomo DNS（Fake-IP / TUN 劫持）→ SmartDNS（127.0.0.1:6053）→ 单一共享加密 DNS 出口。按客户端模式需要 SmartDNS 根据客户端源 IP 分组，并由每组使用独立 SOCKS5 代理；该运行时尚未开放。

SmartDNS 示例配置见 `smartdns-cache.conf.example`。请按安装包版本核对指令兼容性。

## Mihomo 配置片段

在完整配置的 `dns` 部分，将需要缓存的上游配置为：

```yaml
dns:
  enable: true
  listen: 127.0.0.1:5353
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  respect-rules: true
  proxy-server-nameserver:
    - https://dns.alidns.com/dns-query
  nameserver:
    - 127.0.0.1:6053
```

这是集成示例，不应不经验证直接覆盖现有生产配置。保留当前 `tun.dns-hijack`、`auto-route`、`strict-route` 设置，并确认节点域名解析在代理启动前可用，避免 DNS/代理互相依赖。

## 防泄露必须满足的条件

1. SmartDNS 只监听 loopback（示例为 `127.0.0.1:6053`），不直接暴露到公网或不可信 LAN。
2. SmartDNS 只配置可信的 DoH/DoT 上游；不要加入普通明文 DNS `server x.x.x.x` 项。
3. **加密不等于经过代理。** SmartDNS 进程通常会自行建立上游连接；Mihomo 的 `respect-rules` 不会自动把 SmartDNS 进程发出的连接转入代理。因此，必须通过主机策略路由/防火墙/受控网络命名空间，验证上游连接确实按预期出口发送。
4. 禁止客户端绕过 Mihomo 直接访问外部 TCP/UDP 53；按实际平台测试 TCP DNS、IPv6 DNS 和应用内置 DoH 的绕过情况。
5. 不要把 `MATCH,DIRECT` 误认为全局代理。共享模式可通过进程规则将 SmartDNS 的连接统一交给一个代理，但代理不可用时仍可能直连，除非另有网络层 fail-closed 限制。按客户端独立出口不能使用单一进程规则，必须依靠 SmartDNS 的客户端 IP 分组与各组命名代理，并在运行时验证。
6. `default-nameserver` / `proxy-server-nameserver` 是 Mihomo 启动和解析代理节点域名所需的 bootstrap。当前 `default-nameserver` 与 `proxy-server-nameserver` 使用 `tls://` 加密 DNS，并以字面 IP 作为 DoT 端点，避免明文 bootstrap 和域名解析循环。Mihomo 文档明确支持 `default-nameserver` 使用加密 DNS，示例包含 `tls://`；仍需在目标 Mihomo 版本验证证书/SNI 与连接行为。不能简单把 bootstrap 指向 SmartDNS，否则会形成启动循环。
6. 先在测试节点运行 DNS 泄漏测试、抓包并检查上游连接出口，再逐步推广。仅靠 YAML 无法保证零泄露。

## SmartDNS 故障回退与 Bootstrap 边界

当 SmartDNS 健康检查失败，主控运行时配置会把普通 `dns.nameserver` 切换到 Cloudflare/Google DoH；这能避免自动回退到普通 UDP DNS，但 DoH 域名的初始解析仍依赖 bootstrap resolver。bootstrap resolver 现在使用 DoT 字面 IP 端点，不再发送普通明文 DNS 查询；但仍会暴露与 DoT 服务端的连接元数据，且是否成功连接取决于网络可达性和 TLS 验证。不要将此描述成绝对零泄露。

## 为什么 SmartDNS 不是防泄露的唯一措施？

SmartDNS 的缓存可以减少重复查询，但它不会自动接管客户端流量，也不会自动遵循 Mihomo 规则。DoH/DoT 能加密客户端到 DNS 服务商之间的查询内容，却不隐藏 DNS 服务商看到的查询，也不自动隐藏连接的公网源 IP。若不能可靠地把 SmartDNS 上游连接经代理路由，建议暂时使用 Mihomo 原生 DoH + Fake-IP + TUN 严格路由，而不要把 SmartDNS 设为默认上游。
