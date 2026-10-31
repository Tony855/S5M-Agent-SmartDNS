# SmartDNS 缓存接入说明（S5M / Mihomo）

本方案把 SmartDNS 作为可选的本地缓存上游；Mihomo 仍然是客户端 DNS 入口和 Fake-IP/TUN 路由控制器。

## 推荐拓扑

客户端 → Mihomo DNS（Fake-IP / TUN 劫持）→ SmartDNS（127.0.0.1:6053）→ 加密 DNS 上游

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
5. 不要把 `MATCH,DIRECT` 误认为全局代理。若目标是所有外部 DNS 上游都从代理出口出去，必须确保相关上游连接的出站策略确实走代理。
6. 先在测试节点运行 DNS 泄漏测试、抓包并检查上游连接出口，再逐步推广。仅靠 YAML 无法保证零泄露。

## 为什么 SmartDNS 不是防泄露的唯一措施？

SmartDNS 的缓存可以减少重复查询，但它不会自动接管客户端流量，也不会自动遵循 Mihomo 规则。DoH/DoT 能加密客户端到 DNS 服务商之间的查询内容，却不隐藏 DNS 服务商看到的查询，也不自动隐藏连接的公网源 IP。若不能可靠地把 SmartDNS 上游连接经代理路由，建议暂时使用 Mihomo 原生 DoH + Fake-IP + TUN 严格路由，而不要把 SmartDNS 设为默认上游。
