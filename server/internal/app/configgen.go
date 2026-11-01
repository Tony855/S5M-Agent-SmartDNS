package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const baseTemplate = `mode: rule
mixed-port: 8080
allow-lan: false
log-level: info
find-process-mode: strict
ipv6: false
external-controller: 127.0.0.1:8088
secret: "__S5M_MIHOMO_SECRET__"
profile:
    store-selected: true
    store-fake-ip: true
dns:
    enable: true
    ipv6: false
    listen: 127.0.0.1:5353
    enhanced-mode: fake-ip
    fake-ip-range: 198.18.0.1/16
    fake-ip-filter:
        - '*.lan'
        - '*.local'
        - '+.v2net.cc'
        - 'geosite:private'
    default-nameserver:
        - 223.5.5.5
        - 119.29.29.29
    proxy-server-nameserver:
        - 223.5.5.5
        - 119.29.29.29
    nameserver:
        - 127.0.0.1:6053
    fallback:
        - https://dns.cloudflare.com/dns-query
        - https://dns.google/dns-query
    fallback-filter:
        geoip: true
        geoip-code: CN
tun:
    enable: true
    stack: system
    auto-route: true
    auto-detect-interface: true
    dns-hijack:
        - 'any:53'
        - 'tcp://any:53'
proxies:__PROXIES__
rules:__RULES__`

type proxyOut struct {
	Name   string         `yaml:"name"`
	Type   string         `yaml:"type"`
	Server string         `yaml:"server"`
	Port   int            `yaml:"port"`
	Extra  map[string]any `yaml:",inline"`
}

// normalizeAgentProxyConfig applies the Agent policy until the serialized YAML reaches a stable fixed point.
// This keeps persisted configuration and its SHA-256 stable across repeated WebSocket requests.
func normalizeAgentProxyConfig(yml string) (string, error) {
	current := yml
	for attempt := 0; attempt < 8; attempt++ {
		next, err := normalizeAgentProxyConfigOnce(current)
		if err != nil {
			return "", err
		}
		if next == current {
			return next, nil
		}
		current = next
	}
	return "", fmt.Errorf("Agent Mihomo 配置归一化未能在 8 次内收敛")
}

// normalizeAgentProxyConfigOnce performs one policy-normalization pass.
func normalizeAgentProxyConfigOnce(yml string) (string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(yml), &doc); err != nil {
		return "", fmt.Errorf("解析 Agent Mihomo 配置失败: %w", err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return "", fmt.Errorf("Agent Mihomo 配置必须是 YAML 对象")
	}
	root := doc.Content[0]
	setScalar := func(mapping *yaml.Node, key, value, tag string) {
		for i := 0; i+1 < len(mapping.Content); i += 2 {
			if mapping.Content[i].Value == key {
				mapping.Content[i+1].Kind = yaml.ScalarNode
				mapping.Content[i+1].Tag = tag
				mapping.Content[i+1].Value = value
				mapping.Content[i+1].Content = nil
				return
			}
		}
		mapping.Content = append(mapping.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value},
		)
	}
	mappingValue := func(mapping *yaml.Node, key string) *yaml.Node {
		for i := 0; i+1 < len(mapping.Content); i += 2 {
			if mapping.Content[i].Value == key {
				return mapping.Content[i+1]
			}
		}
		return nil
	}
	deleteKeys := map[string]bool{"mixed-port": true, "port": true, "socks-port": true, "redir-port": true, "tproxy-port": true, "listeners": true, "allow-lan": true, "external-controller": true}
	filtered := make([]*yaml.Node, 0, len(root.Content))
	for i := 0; i+1 < len(root.Content); i += 2 {
		if !deleteKeys[root.Content[i].Value] {
			filtered = append(filtered, root.Content[i], root.Content[i+1])
		}
	}
	root.Content = filtered
	// Expose the Agent mixed proxy listener to the LAN, but require credentials.
	// Reuse the per-Agent Mihomo secret as the proxy password; keep the API
	// controller loopback-only and strip every other listener form.
	setScalar(root, "mixed-port", "7890", "!!int")
	setScalar(root, "allow-lan", "true", "!!bool")
	secret := mappingValue(root, "secret")
	if secret == nil || secret.Kind != yaml.ScalarNode || strings.TrimSpace(secret.Value) == "" {
		return "", fmt.Errorf("Agent Mihomo 配置缺少代理认证密钥，拒绝开启 LAN 监听")
	}
	auth := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "s5m:" + secret.Value},
	}}
	foundAuth := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "authentication" {
			root.Content[i+1] = auth
			foundAuth = true
			break
		}
	}
	if !foundAuth {
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "authentication"}, auth)
	}
	setScalar(root, "external-controller", "127.0.0.1:8088", "!!str")
	// PROCESS-NAME rules route SmartDNS DoT sockets through the selected proxy.
	setScalar(root, "find-process-mode", "strict", "!!str")

	// Keep the controller's own hostname out of fake-IP answers to avoid breaking
	// Agent registration/heartbeats when strict-route TUN is enabled.
	dns := mappingValue(root, "dns")
	if dns == nil || dns.Kind != yaml.MappingNode {
		dns = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "dns"}
		root.Content = append(root.Content, setNode, dns)
	}
	filter := mappingValue(dns, "fake-ip-filter")
	if filter == nil || filter.Kind != yaml.SequenceNode {
		filter = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for i := 0; i+1 < len(dns.Content); i += 2 {
			if dns.Content[i].Value == "fake-ip-filter" {
				dns.Content[i+1] = filter
				break
			}
		}
		if mappingValue(dns, "fake-ip-filter") == nil {
			dns.Content = append(dns.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "fake-ip-filter"}, filter)
		}
	}
	// Disable AAAA answers and keep local/private/controller names out of fake-IP.
	setScalar(dns, "ipv6", "false", "!!bool")
	for _, pattern := range []string{"*.lan", "*.local", "geosite:private", "+.v2net.cc"} {
		found := false
		for _, item := range filter.Content {
			if item.Value == pattern {
				found = true
				break
			}
		}
		if !found {
			filter.Content = append(filter.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: pattern})
		}
	}

	// Resolve DoH endpoint hostnames through explicit bootstrap DNS servers.
	defaultDNS := mappingValue(dns, "default-nameserver")
	if defaultDNS == nil || defaultDNS.Kind != yaml.SequenceNode {
		defaultDNS = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		found := false
		for i := 0; i+1 < len(dns.Content); i += 2 {
			if dns.Content[i].Value == "default-nameserver" {
				dns.Content[i+1] = defaultDNS
				found = true
				break
			}
		}
		if !found {
			dns.Content = append(dns.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "default-nameserver"}, defaultDNS)
		}
	}
	// Bootstrap resolvers must be literal IP addresses, never hostnames or the
	// SmartDNS loopback endpoint. This keeps proxy endpoint resolution independent
	// from SmartDNS and from a proxy connection that has not been established yet.
	filterLiteralBootstrap := func(sequence *yaml.Node) {
		kept := make([]*yaml.Node, 0, len(sequence.Content))
		for _, item := range sequence.Content {
			if item.Kind != yaml.ScalarNode || net.ParseIP(strings.Trim(item.Value, "[]")) == nil ||
				item.Value == "127.0.0.1" || item.Value == "127.0.0.1:6053" {
				continue
			}
			kept = append(kept, item)
		}
		sequence.Content = kept
	}
	filterLiteralBootstrap(defaultDNS)
	for _, server := range []string{"223.5.5.5", "119.29.29.29"} {
		found := false
		for _, item := range defaultDNS.Content {
			if item.Value == server { found = true; break }
		}
		if !found { defaultDNS.Content = append(defaultDNS.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: server}) }
	}

	// Resolve proxy endpoint hostnames through explicit bootstrap DNS servers rather
	// than fake-IP answers. Preserve existing entries and append missing defaults.
	proxyDNS := mappingValue(dns, "proxy-server-nameserver")
	if proxyDNS == nil || proxyDNS.Kind != yaml.SequenceNode {
		proxyDNS = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		found := false
		for i := 0; i+1 < len(dns.Content); i += 2 {
			if dns.Content[i].Value == "proxy-server-nameserver" {
				dns.Content[i+1] = proxyDNS
				found = true
				break
			}
		}
		if !found {
			dns.Content = append(dns.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "proxy-server-nameserver"}, proxyDNS)
		}
	}
	// Proxy endpoint bootstrap follows the same literal-IP-only policy.
	filterLiteralBootstrap(proxyDNS)
	for _, server := range []string{"223.5.5.5", "119.29.29.29"} {
		found := false
		for _, item := range proxyDNS.Content {
			if item.Value == server { found = true; break }
		}
		if !found { proxyDNS.Content = append(proxyDNS.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: server}) }
	}

	// Use independent international DoH resolvers as fallback. Preserve any
	// configured fallback endpoints and append defaults only when missing.
	fallback := mappingValue(dns, "fallback")
	if fallback == nil || fallback.Kind != yaml.SequenceNode {
		fallback = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		found := false
		for i := 0; i+1 < len(dns.Content); i += 2 {
			if dns.Content[i].Value == "fallback" {
				dns.Content[i+1] = fallback
				found = true
				break
			}
		}
		if !found {
			dns.Content = append(dns.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "fallback"}, fallback)
		}
	}
	for _, server := range []string{"https://dns.cloudflare.com/dns-query", "https://dns.google/dns-query"} {
		found := false
		for _, item := range fallback.Content {
			if item.Value == server {
				found = true
				break
			}
		}
		if !found {
			fallback.Content = append(fallback.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: server})
		}
	}
	fallbackFilter := mappingValue(dns, "fallback-filter")
	if fallbackFilter == nil || fallbackFilter.Kind != yaml.MappingNode {
		fallbackFilter = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		dns.Content = append(dns.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "fallback-filter"}, fallbackFilter)
	}
	if mappingValue(fallbackFilter, "geoip") == nil {
		fallbackFilter.Content = append(fallbackFilter.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "geoip"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
	}
	if mappingValue(fallbackFilter, "geoip-code") == nil {
		fallbackFilter.Content = append(fallbackFilter.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "geoip-code"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "CN"})
	}

	// Exclude private/local ranges from TUN route capture and also exclude literal
	// proxy endpoint IPs so TUN cannot recursively route its own upstream transport.
	excluded := []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
		"192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
		// Keep bootstrap DNS outside the TUN so resolver bootstrap never
		// loops back through the local DNS listener or SmartDNS.
		"223.5.5.5/32", "119.29.29.29/32",
	}
	seen := make(map[string]bool, len(excluded))
	for _, cidr := range excluded {
		seen[cidr] = true
	}
	if proxies := mappingValue(root, "proxies"); proxies != nil && proxies.Kind == yaml.SequenceNode {
		for _, proxy := range proxies.Content {
			if proxy.Kind != yaml.MappingNode {
				continue
			}
			server := mappingValue(proxy, "server")
			if server == nil || server.Kind != yaml.ScalarNode {
				continue
			}
			ip := net.ParseIP(strings.Trim(server.Value, "[]"))
			if ip == nil {
				continue
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			cidr := fmt.Sprintf("%s/%d", ip.String(), bits)
			if !seen[cidr] {
				excluded = append(excluded, cidr)
				seen[cidr] = true
			}
		}
	}
	tun := mappingValue(root, "tun")
	if tun == nil || tun.Kind != yaml.MappingNode {
		tun = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tun"}, tun)
	}
	dnsHijack := mappingValue(tun, "dns-hijack")
	if dnsHijack == nil || dnsHijack.Kind != yaml.SequenceNode {
		dnsHijack = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		found := false
		for i := 0; i+1 < len(tun.Content); i += 2 {
			if tun.Content[i].Value == "dns-hijack" {
				tun.Content[i+1] = dnsHijack
				found = true
				break
			}
		}
		if !found {
			tun.Content = append(tun.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "dns-hijack"}, dnsHijack)
		}
	}
	foundDNSHijack := false
	for _, item := range dnsHijack.Content {
		if item.Value == "any:53" {
			foundDNSHijack = true
			break
		}
	}
	if !foundDNSHijack {
		dnsHijack.Content = append(dnsHijack.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "any:53"})
	}
	// TCP DNS must be intercepted as well as UDP; otherwise clients can bypass
	// the local resolver by switching transports while TUN is enabled.
	foundTCPDNSHijack := false
	for _, item := range dnsHijack.Content {
		if item.Value == "tcp://any:53" {
			foundTCPDNSHijack = true
			break
		}
	}
	if !foundTCPDNSHijack {
		dnsHijack.Content = append(dnsHijack.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tcp://any:53"})
	}

	routeExclude := mappingValue(tun, "route-exclude-address")
	if routeExclude == nil || routeExclude.Kind != yaml.SequenceNode {
		routeExclude = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		found := false
		for i := 0; i+1 < len(tun.Content); i += 2 {
			if tun.Content[i].Value == "route-exclude-address" {
				tun.Content[i+1] = routeExclude
				found = true
				break
			}
		}
		if !found {
			tun.Content = append(tun.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "route-exclude-address"}, routeExclude)
		}
	}
	for _, cidr := range excluded {
		found := false
		for _, item := range routeExclude.Content {
			if item.Value == cidr {
				found = true
				break
			}
		}
		if !found {
			routeExclude.Content = append(routeExclude.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: cidr})
		}
	}

	var out strings.Builder
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return "", fmt.Errorf("序列化 Agent Mihomo 配置失败: %w", err)
	}
	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("关闭 Agent YAML 编码器失败: %w", err)
	}
	return out.String(), nil
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n") + "\n"
}

// agentHasHealthySmartDNS reports whether the authenticated Agent heartbeat
// confirms that the combined image has a working local SmartDNS resolver.
func (a *App) agentHasHealthySmartDNS(machineCode string) bool {
	if strings.TrimSpace(machineCode) == "" {
		return false
	}
	value, err := a.store.GetSetting("agent_status_" + machineCode)
	if err != nil || strings.TrimSpace(value) == "" {
		return false
	}
	var status map[string]any
	if err := json.Unmarshal([]byte(value), &status); err != nil {
		return false
	}
	// A stale healthy heartbeat must never keep the local SmartDNS endpoint
	// selected after an Agent disconnects or stops reporting health. Use the
	// server-stamped received_at field, not agent_lastseen (config requests also
	// update agent_lastseen and therefore cannot prove a fresh health report).
	receivedAt, ok := status["received_at"].(float64)
	if !ok || receivedAt <= 0 || receivedAt > 9.0e15 {
		return false
	}
	age := time.Since(time.Unix(int64(receivedAt), 0))
	if age > agentWSHeartbeatTTL || age < -30*time.Second {
		return false
	}
	return status["smartdns_available"] == true &&
		status["smartdns_running"] == true &&
		status["smartdns_dns_healthy"] == true
}

// applyAgentRuntimeDNS derives the outgoing Agent config without mutating its persisted source.
func applyAgentRuntimeDNS(yml string, smartDNSHealthy bool) (string, error) {
	if smartDNSHealthy {
		return routeAgentDNSViaSmartDNS(yml)
	}
	// Never leave the generated SmartDNS loopback as the only resolver when
	// SmartDNS is unhealthy. Preserve operator-selected nameservers otherwise.
	return routeAgentDNSFallbackIfSmartDNS(yml)
}

func routeAgentDNSFallbackIfSmartDNS(yml string) (string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(yml), &doc); err != nil {
		return "", fmt.Errorf("解析 Agent DNS 回退配置失败: %w", err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return "", fmt.Errorf("Agent DNS 回退配置必须是 YAML 对象")
	}
	root := doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "dns" || root.Content[i+1].Kind != yaml.MappingNode { continue }
		dns := root.Content[i+1]
		for j := 0; j+1 < len(dns.Content); j += 2 {
			if dns.Content[j].Value != "nameserver" { continue }
			servers := dns.Content[j+1]
			if servers.Kind != yaml.SequenceNode || len(servers.Content) != 1 || servers.Content[0].Value != "127.0.0.1:6053" {
				return yml, nil
			}
			servers.Content = []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "223.5.5.5"},
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "119.29.29.29"},
			}
			out, err := yaml.Marshal(&doc)
			return string(out), err
		}
	}
	return yml, nil
}

// restoreAgentDNSNameserver restores only dns.nameserver from a freshly generated baseline.
// It is intentionally limited to the legacy SmartDNS-only value so operator DNS
// settings are never overwritten during ordinary config delivery.
func restoreAgentDNSNameserver(yml, fallbackYML string) (string, bool, error) {
	var currentDoc, fallbackDoc yaml.Node
	if err := yaml.Unmarshal([]byte(yml), &currentDoc); err != nil {
		return "", false, fmt.Errorf("解析现有 Agent DNS 配置失败: %w", err)
	}
	if err := yaml.Unmarshal([]byte(fallbackYML), &fallbackDoc); err != nil {
		return "", false, fmt.Errorf("解析基准 Agent DNS 配置失败: %w", err)
	}
	findMappingValue := func(root *yaml.Node, key string) *yaml.Node {
		if root == nil || len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode { return nil }
		mapping := root.Content[0]
		for i := 0; i+1 < len(mapping.Content); i += 2 {
			if mapping.Content[i].Value == key { return mapping.Content[i+1] }
		}
		return nil
	}
	currentDNS := findMappingValue(&currentDoc, "dns")
	fallbackDNS := findMappingValue(&fallbackDoc, "dns")
	if currentDNS == nil || currentDNS.Kind != yaml.MappingNode { return yml, false, nil }
	var currentNameserver *yaml.Node
	for i := 0; i+1 < len(currentDNS.Content); i += 2 {
		if currentDNS.Content[i].Value == "nameserver" { currentNameserver = currentDNS.Content[i+1]; break }
	}
	if currentNameserver == nil || currentNameserver.Kind != yaml.SequenceNode || len(currentNameserver.Content) != 1 ||
		currentNameserver.Content[0].Value != "127.0.0.1:6053" {
		return yml, false, nil
	}
	if fallbackDNS == nil || fallbackDNS.Kind != yaml.MappingNode {
		return "", false, fmt.Errorf("基准 Agent 配置缺少 dns 对象，拒绝保留失效的 SmartDNS 地址")
	}
	var fallbackNameserver *yaml.Node
	for i := 0; i+1 < len(fallbackDNS.Content); i += 2 {
		if fallbackDNS.Content[i].Value == "nameserver" { fallbackNameserver = fallbackDNS.Content[i+1]; break }
	}
	if fallbackNameserver == nil || fallbackNameserver.Kind != yaml.SequenceNode || len(fallbackNameserver.Content) == 0 {
		return "", false, fmt.Errorf("基准 Agent 配置缺少有效 dns.nameserver，拒绝保留失效的 SmartDNS 地址")
	}
	// The generated baseline now prefers SmartDNS. Legacy migration while
	// SmartDNS is unhealthy must restore independent bootstrap resolvers instead.
	if len(fallbackNameserver.Content) == 1 && fallbackNameserver.Content[0].Value == "127.0.0.1:6053" {
		fallbackNameserver = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "223.5.5.5"},
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "119.29.29.29"},
		}}
	}
	for i := 0; i+1 < len(currentDNS.Content); i += 2 {
		if currentDNS.Content[i].Value == "nameserver" {
			copyNode := *fallbackNameserver
			copyNode.Content = append([]*yaml.Node(nil), fallbackNameserver.Content...)
			currentDNS.Content[i+1] = &copyNode
			out, err := yaml.Marshal(&currentDoc)
			if err != nil { return "", false, fmt.Errorf("序列化恢复后的 Agent DNS 配置失败: %w", err) }
			return string(out), true, nil
		}
	}
	return yml, false, nil
}

// routeAgentDNSViaSmartDNS changes only the ordinary nameserver list. Bootstrap
// and proxy-server DNS stay on literal IP resolvers to avoid resolver loops.
func routeAgentDNSViaSmartDNS(yml string) (string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(yml), &doc); err != nil {
		return "", fmt.Errorf("解析 Agent DNS 配置失败: %w", err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return "", fmt.Errorf("Agent DNS 配置必须是 YAML 对象")
	}
	root := doc.Content[0]
	var dns *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "dns" {
			dns = root.Content[i+1]
			break
		}
	}
	if dns == nil || dns.Kind != yaml.MappingNode {
		return "", fmt.Errorf("Agent DNS 配置缺少 dns 对象")
	}
	for i := 0; i+1 < len(dns.Content); i += 2 {
		if dns.Content[i].Value == "nameserver" {
			dns.Content[i+1] = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "127.0.0.1:6053"},
			}}
			out, err := yaml.Marshal(&doc)
			return string(out), err
		}
	}
	dns.Content = append(dns.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "nameserver"},
		&yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "127.0.0.1:6053"},
		}},
	)
	out, err := yaml.Marshal(&doc)
	return string(out), err
}

func (a *App) BuildConfigForMachine(machineCode string) (string, error) {
	proxies, err := a.store.ListProxies()
	if err != nil {
		return "", err
	}
	secretKey := "mihomo_secret_controller"
	if machineCode != "" {
		secretKey = "agent_mihomo_secret_" + machineCode
	}
	secret, err := a.getOrCreateMihomoSecret(secretKey)
	if err != nil {
		return "", err
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		return "", fmt.Errorf("读取 Mihomo 设置失败: %w", err)
	}
	mode := routingModeForMachine(proxies, machineCode)
	controllerHost := controllerHostFromSettings(settings)
	yml, err := buildConfigFromProxiesWithMode(proxies, machineCode, secret, mode, controllerHost)
	if err != nil {
		return "", err
	}
	// Controller configs keep their separate listener; Agent configs expose no explicit proxy listener.
	if strings.TrimSpace(machineCode) != "" {
		yml, err = normalizeAgentProxyConfig(yml)
		if err != nil {
			return "", err
		}
	}
	// SmartDNS is applied only to the runtime WebSocket payload. Never persist
	// the Agent-local 127.0.0.1:6053 resolver into the operator's source YAML.
	// The global default is enabled for new installations. Respect an explicit
	// controller setting for generated configs; saved per-node YAML remains authoritative.
	if strings.EqualFold(strings.TrimSpace(settings["tun_enable"]), "false") {
		yml = strings.Replace(yml, "tun:\n    enable: true", "tun:\n    enable: false", 1)
	}
	return yml, nil
}

// getOrCreateMihomoSecret creates a cryptographically random API secret once per controller/Agent.
func (a *App) getOrCreateMihomoSecret(key string) (string, error) {
	settings, err := a.store.GetSettings()
	if err != nil {
		return "", fmt.Errorf("读取 Mihomo 密钥失败: %w", err)
	}
	if secret := strings.TrimSpace(settings[key]); secret != "" {
		return secret, nil
	}
	secret := strings.TrimSpace(a.cfg.MihomoSecret)
	if secret == "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("生成 Mihomo 随机密钥失败: %w", err)
		}
		secret = hex.EncodeToString(buf)
	}
	created, err := a.store.CreateSettingIfAbsent(key, secret)
	if err != nil {
		return "", fmt.Errorf("保存 Mihomo 密钥失败: %w", err)
	}
	if created {
		return secret, nil
	}
	settings, err = a.store.GetSettings()
	if err != nil {
		return "", fmt.Errorf("回读 Mihomo 密钥失败: %w", err)
	}
	if secret = strings.TrimSpace(settings[key]); secret == "" {
		return "", fmt.Errorf("Mihomo 密钥保存后仍不存在")
	}
	return secret, nil
}

// syncAuthorizedNodeConfigs refreshes cached YAML for machines with dedicated tokens.
// It does not publish or reload the controller's own Mihomo configuration.
func (a *App) syncAuthorizedNodeConfigs() error {
	settings, err := a.store.GetSettings()
	if err != nil {
		return fmt.Errorf("读取机器授权失败: %w", err)
	}
	const prefix = "agent_machine_"
	configs := make(map[string]string)
	for key, token := range settings {
		if !strings.HasPrefix(key, prefix) || strings.TrimSpace(token) == "" {
			continue
		}
		machineCode := strings.TrimSpace(strings.TrimPrefix(key, prefix))
		if machineCode == "" {
			continue
		}
		generated, err := a.BuildConfigForMachine(machineCode)
		if err != nil {
			return fmt.Errorf("为机器 %s 生成配置失败: %w", machineCode, err)
		}
		// Existing complete per-node YAML is authoritative for TUN, DNS, ports and other settings.
		// Proxy edits refresh only generated proxies/rules and preserve the node's secret.
		existing, err := a.store.GetNodeConfig(machineCode)
		if err != nil {
			return fmt.Errorf("读取机器 %s 的独立配置失败: %w", machineCode, err)
		}
		if existing != nil && strings.TrimSpace(existing.YAML) != "" {
			var currentDoc, generatedDoc map[string]any
			if err := yaml.Unmarshal([]byte(existing.YAML), &currentDoc); err != nil {
				return fmt.Errorf("机器 %s 的独立 YAML 无效: %w", machineCode, err)
			}
			if len(currentDoc) == 0 {
				return fmt.Errorf("机器 %s 的独立 YAML 必须是非空映射", machineCode)
			}
			if err := yaml.Unmarshal([]byte(generated), &generatedDoc); err != nil {
				return fmt.Errorf("机器 %s 的生成 YAML 无效: %w", machineCode, err)
			}
			// Mihomo must stay in rule mode for managed routing rules to take
			// effect. A stale/custom "mode: global" would bypass MATCH,REJECT and
			// silently defeat the node's selected routing policy.
			if value, ok := generatedDoc["mode"]; ok {
				currentDoc["mode"] = value
			}
			if value, ok := generatedDoc["proxies"]; ok {
				currentDoc["proxies"] = value
			}
			mergedRules, mergeErr := mergeManagedRuleValues(currentDoc["rules"], generatedDoc["rules"])
			if mergeErr != nil {
				return fmt.Errorf("合并机器 %s 的自定义规则失败: %w", machineCode, mergeErr)
			}
			currentDoc["rules"] = mergedRules
			marshaled, marshalErr := yaml.Marshal(currentDoc)
			if marshalErr != nil {
				return fmt.Errorf("序列化机器 %s 的独立配置失败: %w", machineCode, marshalErr)
			}
			generated = string(marshaled)
		}
		generated, err = normalizeAgentProxyConfig(generated)
		if err != nil {
			return fmt.Errorf("机器 %s 的透明代理配置校正失败: %w", machineCode, err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(generated), &doc); err != nil {
			return fmt.Errorf("机器 %s 的 YAML 校验失败: %w", machineCode, err)
		}
		if len(doc) == 0 {
			return fmt.Errorf("机器 %s 的 YAML 内容为空", machineCode)
		}
		configs[machineCode] = generated
	}
	if err := a.store.SaveNodeConfigs(configs); err != nil {
		return fmt.Errorf("批量保存节点配置失败: %w", err)
	}
	return nil
}

func normalizeProxyRoutingMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "global", "split", "rule", "return", "game":
		return strings.ToLower(strings.TrimSpace(raw))
	case "proxy":
		return "return"
	case "china":
		return "split"
	default:
		return "rule"
	}
}

func routingModeForMachine(proxies []Proxy, machineCode string) string {
	// A Mihomo config has one routing mode for the whole machine, not one mode
	// per proxy. ListProxies is persisted in stable ID order, so the first
	// enabled proxy assigned to this machine remains the compatibility anchor.
	// Additional proxies contribute outbound nodes but cannot silently change
	// an existing machine's traffic policy.
	for _, p := range proxies {
		if !p.Enabled || p.Mode == "direct" || p.Mode == "reject" {
			continue
		}
		matches := p.MachineCode == "__GLOBAL__" && machineCode == ""
		if machineCode != "" && strings.TrimSpace(p.MachineCode) == machineCode {
			matches = true
		}
		if !matches {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(p.Mode)) {
		case "global", "split", "rule", "return", "game":
			return normalizeProxyRoutingMode(p.Mode)
		case "proxy":
			return "return"
		case "china":
			return "split"
		}
	}
	return "rule"
}

func controllerHostFromSettings(settings map[string]string) string {
	candidates := []string{settings["central_url"], settings["public_url"], settings["server_url"], settings["agent_central_url"]}
	candidates = append(candidates, os.Getenv("S5M_CENTRAL_URL"), os.Getenv("S5M_PUBLIC_URL"), os.Getenv("PUBLIC_URL"))
	for _, candidate := range candidates {
		raw := strings.TrimSpace(candidate)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		u, err := url.Parse(raw)
		if err == nil && u.Hostname() != "" {
			return strings.Trim(strings.ToLower(u.Hostname()), "[]")
		}
	}
	return ""
}

// marshalProxiesWithSharedAnchor emits a YAML merge anchor only when every
// generated proxy has identical protocol, server and protocol-specific options.
// Name and port are intentionally excluded: aliases override those per node.
// Mixed endpoints/protocols fall back to ordinary YAML serialization.
func marshalProxiesWithSharedAnchor(proxies []proxyOut) ([]byte, error) {
	if len(proxies) < 2 {
		return yaml.Marshal(proxies)
	}
	options := func(p proxyOut) (string, error) {
		b, err := yaml.Marshal(p.Extra)
		return string(b), err
	}
	firstOptions, err := options(proxies[0])
	if err != nil {
		return nil, err
	}
	for _, p := range proxies[1:] {
		currentOptions, err := options(p)
		if err != nil {
			return nil, err
		}
		if p.Type != proxies[0].Type || p.Server != proxies[0].Server || currentOptions != firstOptions {
			return yaml.Marshal(proxies)
		}
	}
	root := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for i, p := range proxies {
		m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		add := func(k string, v *yaml.Node) {
			m.Content = append(m.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k},
				v,
			)
		}
		if i == 0 {
			m.Anchor = "s5m_shared_proxy"
			add("name", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: p.Name})
			add("type", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: p.Type})
			add("server", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: p.Server})
			add("port", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprint(p.Port)})
			keys := make([]string, 0, len(p.Extra))
			for k := range p.Extra {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				var value yaml.Node
				if err := value.Encode(p.Extra[k]); err != nil {
					return nil, err
				}
				add(k, &value)
			}
		} else {
			alias := &yaml.Node{Kind: yaml.AliasNode, Alias: root.Content[0], Value: "s5m_shared_proxy"}
			add("<<", alias)
			m.Content[len(m.Content)-2].Tag = "!!merge"
			add("name", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: p.Name})
			add("port", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprint(p.Port)})
		}
		root.Content = append(root.Content, m)
	}
	return yaml.Marshal(root)
}

func buildConfigFromProxies(proxies []Proxy, machineCode, secret string) (string, error) {
	return buildConfigFromProxiesWithMode(proxies, machineCode, secret, "rule", "")
}

func buildConfigFromProxiesWithMode(proxies []Proxy, machineCode, secret, routingMode, controllerHost string) (string, error) {
	routingMode = normalizeProxyRoutingMode(routingMode)
	// Normalize persisted rows before generating either proxy entries or routing
	// rules. Older/imported rows may predate API validation.
	proxies = append([]Proxy(nil), proxies...)
	for i := range proxies {
		proxies[i].Name = strings.TrimSpace(proxies[i].Name)
		proxies[i].Mode = strings.TrimSpace(proxies[i].Mode)
		proxies[i].Type = strings.ToLower(strings.TrimSpace(proxies[i].Type))
		proxies[i].Server = strings.TrimSpace(proxies[i].Server)
		proxies[i].MachineCode = strings.TrimSpace(proxies[i].MachineCode)
	}
	matchesMachine := func(p Proxy) bool {
		// Global proxies are explicitly marked; an empty machine code stays unbound.
		if p.MachineCode == "__GLOBAL__" {
			return true
		}
		return machineCode != "" && p.MachineCode == machineCode
	}
	eligible := func(p Proxy) bool {
		return p.Enabled && p.Mode != "direct" && p.Mode != "reject" && matchesMachine(p)
	}
	endpointKey := func(p Proxy) string {
		return strings.ToLower(strings.TrimSpace(p.Type)) + "|" +
			strings.Trim(strings.TrimSpace(p.Server), "[]") + "|" +
			fmt.Sprint(p.Port)
	}

	var outs []proxyOut
	emittedNames := map[string]bool{}
	activeByEndpoint := map[string][]Proxy{}

	for _, p := range proxies {
		if !eligible(p) {
			continue
		}
		if p.Name == "" || len(p.Name) > 100 {
			return "", fmt.Errorf("代理名称不能为空且不能超过 100 个字符")
		}
		switch p.Mode {
		case "proxy", "china", "global", "split", "rule", "return", "game":
		default:
			return "", fmt.Errorf("代理 %q 的运行模式无效：%q", p.Name, p.Mode)
		}
		switch p.Type {
		case "socks5", "http", "ss", "vmess", "vless", "trojan":
		default:
			return "", fmt.Errorf("代理 %q 的类型无效：%q", p.Name, p.Type)
		}
		if p.Server == "" || strings.ContainsAny(p.Server, " \t\r\n") {
			return "", fmt.Errorf("代理 %q 的服务器地址为空或包含空白字符", p.Name)
		}
		if p.Port < 1 || p.Port > 65535 {
			return "", fmt.Errorf("代理 %q 的端口必须在 1-65535 之间", p.Name)
		}
		if emittedNames[p.Name] {
			return "", fmt.Errorf("代理名称重复：%q", p.Name)
		}
		emittedNames[p.Name] = true
		key := endpointKey(p)
		activeByEndpoint[key] = append(activeByEndpoint[key], p)

		ex := map[string]any{}
		for k, v := range p.Extra {
			switch k {
			case "name", "type", "server", "port":
				continue
			}
			ex[k] = v
		}
		outs = append(outs, proxyOut{
			Name: p.Name, Type: p.Type, Server: p.Server,
			Port: p.Port, Extra: ex,
		})
	}

	proxiesYAML := " []"
	if len(outs) > 0 {
		b, err := marshalProxiesWithSharedAnchor(outs)
		if err != nil {
			return "", err
		}
		proxiesYAML = "\n" + indent(string(b), "    ")
	}

	rules := []string{"DOMAIN-SUFFIX,v2net.cc,DIRECT"}
	// Keep Agent-to-controller HTTPS/WebSocket traffic direct under TUN strict-route.
	if controllerHost != "" {
		if ip := net.ParseIP(controllerHost); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			rules = append(rules, fmt.Sprintf("IP-CIDR,%s/%d,DIRECT,no-resolve", ip.String(), bits))
		} else {
			rules = append(rules, fmt.Sprintf("DOMAIN,%s,DIRECT", controllerHost))
		}
	}
	// SmartDNS uses literal-IP DoT upstreams, so it does not need DNS bootstrap
	// through Mihomo. Route its encrypted upstream sockets through the selected
	// proxy explicitly; this rule must precede source-CIDR and terminal MATCH rules.
	if len(outs) > 0 {
		rules = append(rules, fmt.Sprintf("PROCESS-NAME,smartdns,%s", outs[0].Name))
	}
	// Mihomo's own DoH bootstrap stays independent from SmartDNS and uses literal-IP DNS.
	if len(outs) > 0 && routingMode != "global" {
		for _, domain := range []string{"dns.alidns.com", "doh.pub", "dns.cloudflare.com", "dns.google"} {
			rules = append(rules, fmt.Sprintf("DOMAIN-SUFFIX,%s,%s", domain, outs[0].Name))
		}
	}
	seenCIDR := map[string]string{}

	for _, p := range proxies {
		if !matchesMachine(p) || p.Mode == "direct" || p.Mode == "reject" {
			continue
		}

		target := ""
		if eligible(p) {
			target = p.Name
		} else if !p.Enabled {
			// 禁用记录只能作为映射元数据，不能成为实际出口。
			candidates := activeByEndpoint[endpointKey(p)]
			if len(candidates) == 1 {
				target = candidates[0].Name
			} else {
				continue
			}
		} else {
			continue
		}

		cidr := strings.TrimSpace(p.SourceCIDR)
		if cidr == "" {
			continue
		}

		_, network, parseErr := net.ParseCIDR(cidr)
		if parseErr != nil {
			return "", fmt.Errorf("代理 %q 的 SourceCIDR 无效 %q: %w", p.Name, cidr, parseErr)
		}
		ones, bits := network.Mask.Size()
		if ones == 0 && (bits == 32 || bits == 128) {
			continue
		}

		canonical := network.String()
		if previous, exists := seenCIDR[canonical]; exists {
			return "", fmt.Errorf("客户端网段 %q 重复映射到 %q 和 %q", canonical, previous, target)
		}
		if !emittedNames[target] {
			return "", fmt.Errorf("客户端网段 %q 的目标代理 %q 未生成", canonical, target)
		}

		seenCIDR[canonical] = target
		rules = append(rules, fmt.Sprintf("SRC-IP-CIDR,%s,%s", canonical, target))
	}

	firstProxy, firstGameProxy := "", ""
	for _, p := range outs {
		if firstProxy == "" {
			firstProxy = p.Name
		}
		for _, original := range proxies {
			if original.Name == p.Name && original.Mode == "game" && firstGameProxy == "" {
				firstGameProxy = p.Name
			}
		}
	}
	switch routingMode {
	case "global":
		if firstProxy != "" {
			rules = append(rules, fmt.Sprintf("MATCH,%s", firstProxy))
		} else {
			rules = append(rules, "MATCH,DIRECT")
		}
	case "split":
		// Legacy split mode keeps its historical proxy fallback for existing records.
		if firstProxy != "" {
			rules = append(rules, fmt.Sprintf("MATCH,%s", firstProxy))
		} else {
			rules = append(rules, "MATCH,DIRECT")
		}
	case "rule":
		// Strict rule mode: only explicit rules may pass traffic; unmatched traffic is rejected.
		rules = append(rules, "MATCH,REJECT")
	case "return":
		// Return-to-China mode: mainland destinations use the proxy; overseas destinations go direct.
		if firstProxy != "" {
			rules = append(rules, fmt.Sprintf("GEOIP,CN,%s", firstProxy))
		} else {
			rules = append(rules, "GEOIP,CN,DIRECT")
		}
		rules = append(rules, "MATCH,DIRECT")
	case "game":
		gameProxy := firstGameProxy
		if gameProxy == "" {
			gameProxy = firstProxy
		}
		if gameProxy != "" {
			for _, domain := range []string{"steampowered.com", "steamcommunity.com", "steamcontent.com", "epicgames.com", "playstation.net", "playstation.com", "xboxlive.com", "xbox.com", "battle.net", "blizzard.com", "riotgames.com", "leagueoflegends.com", "valorant.com", "ea.com"} {
				rules = append(rules, fmt.Sprintf("DOMAIN-SUFFIX,%s,%s", domain, gameProxy))
			}
		}
		rules = append(rules, "MATCH,DIRECT")
	}
	rb, err := yaml.Marshal(rules)
	if err != nil {
		return "", err
	}
	rulesYAML := "\n" + indent(string(rb), "    ")

	if strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("Mihomo API 密钥不能为空")
	}
	out := strings.Replace(baseTemplate, "__S5M_MIHOMO_SECRET__", secret, 1)
	out = strings.Replace(out, "__PROXIES__", proxiesYAML, 1)
	out = strings.Replace(out, "__RULES__", rulesYAML, 1)
	return out, nil
}

// BuildConfig builds the managed default and overlays user-owned global settings.
// The database remains authoritative for proxies and rules, while other YAML keys
// (ports, DNS, TUN options, sniffer settings, etc.) can be customized by admins.
func (a *App) BuildConfig() (string, error) {
	generated, err := a.BuildConfigForMachine("")
	if err != nil {
		return "", err
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		return "", fmt.Errorf("读取全局配置失败: %w", err)
	}
	custom := strings.TrimSpace(settings["config_yaml"])
	if custom == "" {
		return generated, nil
	}
	return mergeManagedProxySections(custom, generated)
}

// mergeManagedProxySections keeps the admin's global YAML settings but refreshes
// proxies/rules from the authoritative proxy database before preview or publish.
// mergeManagedRuleValues keeps operator rules ahead of the generated terminal MATCH.
// System bypasses (v2net.cc/controller) and generated safety rules remain first.
// Operator-provided MATCH rules are ignored so they cannot shadow the final policy.
func mergeManagedRuleValues(customValue, generatedValue any) ([]any, error) {
	generated, ok := generatedValue.([]any)
	if !ok {
		return nil, fmt.Errorf("生成的 rules 必须是数组")
	}
	var custom []any
	if customValue != nil {
		var valid bool
		custom, valid = customValue.([]any)
		if !valid {
			return nil, fmt.Errorf("自定义 rules 必须是数组")
		}
	}
	merged := make([]any, 0, len(generated)+len(custom))
	var terminal any
	terminalCount := 0
	for _, raw := range generated {
		rule, valid := raw.(string)
		if !valid || strings.TrimSpace(rule) == "" {
			return nil, fmt.Errorf("生成的规则必须是非空字符串")
		}
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(rule)), "MATCH,") {
			terminal = strings.TrimSpace(rule)
			terminalCount++
			continue
		}
		merged = append(merged, rule)
	}
	seen := make(map[string]bool, len(merged)+len(custom))
	for _, raw := range merged {
		seen[strings.TrimSpace(raw.(string))] = true
	}
	for _, raw := range custom {
		rule, valid := raw.(string)
		if !valid || strings.TrimSpace(rule) == "" {
			return nil, fmt.Errorf("自定义规则必须是非空字符串")
		}
		rule = strings.TrimSpace(rule)
		if strings.HasPrefix(strings.ToUpper(rule), "MATCH,") || seen[rule] {
			continue
		}
		merged = append(merged, rule)
		seen[rule] = true
	}
	if terminalCount != 1 {
		return nil, fmt.Errorf("生成的 rules 必须且只能包含一条最终 MATCH 规则，实际为 %d 条", terminalCount)
	}
	merged = append(merged, terminal)
	return merged, nil
}

func mergeManagedProxySections(customYAML, generatedYAML string) (string, error) {
	var customDoc map[string]any
	if err := yaml.Unmarshal([]byte(customYAML), &customDoc); err != nil {
		return "", fmt.Errorf("全局 YAML 语法错误: %w", err)
	}
	if len(customDoc) == 0 {
		return "", fmt.Errorf("全局 YAML 必须是非空映射")
	}

	var generatedDoc map[string]any
	if err := yaml.Unmarshal([]byte(generatedYAML), &generatedDoc); err != nil {
		return "", fmt.Errorf("生成的 YAML 无效: %w", err)
	}
	// The top-level Mihomo mode is managed: generated rules (including the
	// terminal MATCH policy) are only authoritative when Mihomo evaluates rules.
	if value, ok := generatedDoc["mode"]; ok {
		customDoc["mode"] = value
	}
	if value, ok := generatedDoc["proxies"]; ok {
		customDoc["proxies"] = value
	}
	mergedRules, err := mergeManagedRuleValues(customDoc["rules"], generatedDoc["rules"])
	if err != nil {
		return "", fmt.Errorf("合并自定义规则失败: %w", err)
	}
	customDoc["rules"] = mergedRules
	merged, err := yaml.Marshal(customDoc)
	if err != nil {
		return "", fmt.Errorf("序列化全局 YAML 失败: %w", err)
	}
	return string(merged), nil
}

func (a *App) Publish() (*ConfigVersion, error) {
	yml, err := a.BuildConfig()
	if err != nil {
		return nil, err
	}

	var chk any
	if err := yaml.Unmarshal([]byte(yml), &chk); err != nil {
		return nil, fmt.Errorf("YAML 语法错误: %w", err)
	}

	configDir := filepath.Dir(a.cfg.ConfigPath)
	if err := os.MkdirAll(a.cfg.BackupDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建备份目录失败: %w", err)
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建配置目录失败: %w", err)
	}

	candidate := a.cfg.ConfigPath + ".candidate"
	if err := os.WriteFile(candidate, []byte(yml), 0o600); err != nil {
		return nil, fmt.Errorf("写入候选配置失败: %w", err)
	}
	defer os.Remove(candidate)

	check := exec.Command("/opt/mihomo/mihomo", "-t", "-d", configDir, "-f", candidate)
	if output, err := check.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("Mihomo 候选配置校验失败: %w; 输出: %s", err, strings.TrimSpace(string(output)))
	}

	v, err := a.store.NextVersion()
	if err != nil {
		return nil, fmt.Errorf("获取配置版本失败: %w", err)
	}

	oldConfig, readErr := os.ReadFile(a.cfg.ConfigPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("读取当前配置失败: %w", readErr)
	}
	hadOld := readErr == nil

	if hadOld {
		backupPath := filepath.Join(a.cfg.BackupDir, time.Now().Format("20060102-150405.000000")+".yaml")
		if err := os.WriteFile(backupPath, oldConfig, 0o600); err != nil {
			return nil, fmt.Errorf("备份当前配置失败，未发布: %w", err)
		}
	}

	sum := sha256.Sum256([]byte(yml))
	sha := hex.EncodeToString(sum[:])

	restoreOld := func() error {
		if !hadOld {
			return os.Remove(a.cfg.ConfigPath)
		}
		tmpRestore := a.cfg.ConfigPath + ".restore"
		if err := os.WriteFile(tmpRestore, oldConfig, 0o600); err != nil {
			return err
		}
		return os.Rename(tmpRestore, a.cfg.ConfigPath)
	}

	if err := os.Rename(candidate, a.cfg.ConfigPath); err != nil {
		return nil, fmt.Errorf("替换配置文件失败: %w", err)
	}

	if err := a.store.InsertVersion(v, sha, yml, "published"); err != nil {
		if restoreErr := restoreOld(); restoreErr != nil {
			return nil, fmt.Errorf("记录版本失败: %v；恢复旧配置也失败: %w", err, restoreErr)
		}
		return nil, fmt.Errorf("记录配置版本失败，已恢复旧配置: %w", err)
	}

	cv := &ConfigVersion{Version: v, SHA256: sha, Status: "published"}
	if err := a.ReloadMihomo(); err != nil {
		if restoreErr := restoreOld(); restoreErr != nil {
			cv.Status = "published_reload_failed_restore_failed"
			_ = a.store.UpdateVersionStatus(v, cv.Status)
			return cv, fmt.Errorf("新配置重载失败: %v；恢复旧配置失败: %w", err, restoreErr)
		}
		if hadOld {
			if reloadOldErr := a.ReloadMihomo(); reloadOldErr != nil {
				cv.Status = "published_reload_failed_old_reload_failed"
				_ = a.store.UpdateVersionStatus(v, cv.Status)
				return cv, fmt.Errorf("新配置重载失败: %v；旧配置已恢复文件，但重载旧配置也失败: %w", err, reloadOldErr)
			}
		}
		cv.Status = "published_reload_failed_rolled_back"
		_ = a.store.UpdateVersionStatus(v, cv.Status)
		return cv, fmt.Errorf("新配置重载失败，已恢复旧配置: %w", err)
	}

	return cv, nil
}

func (a *App) Rollback(version int) (*ConfigVersion, error) {
	yml, err := a.store.VersionYAML(version)
	if err != nil {
		return nil, fmt.Errorf("版本不存在: %w", err)
	}

	var chk any
	if err := yaml.Unmarshal([]byte(yml), &chk); err != nil {
		return nil, fmt.Errorf("历史 YAML 损坏: %w", err)
	}

	// Proxy rows and routing rules are managed by the database. Roll back the
	// historical global settings, but regenerate those managed sections from the
	// current database so the live config cannot diverge from the proxy inventory.
	managedYAML, err := a.BuildConfigForMachine("")
	if err != nil {
		return nil, fmt.Errorf("生成当前代理和规则失败，未回滚: %w", err)
	}
	yml, err = mergeManagedProxySections(yml, managedYAML)
	if err != nil {
		return nil, fmt.Errorf("合并当前代理和规则失败，未回滚: %w", err)
	}

	configDir := filepath.Dir(a.cfg.ConfigPath)
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建配置目录失败: %w", err)
	}
	if err := os.MkdirAll(a.cfg.BackupDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建备份目录失败，未回滚: %w", err)
	}

	candidate := a.cfg.ConfigPath + ".rollback-candidate"
	defer os.Remove(candidate)
	if err := os.WriteFile(candidate, []byte(yml), 0o600); err != nil {
		return nil, fmt.Errorf("写入候选配置失败，未回滚: %w", err)
	}

	check := exec.Command("/opt/mihomo/mihomo", "-t", "-d", configDir, "-f", candidate)
	if output, err := check.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("历史配置未通过 Mihomo 校验，未回滚: %w; 输出: %s",
			err, strings.TrimSpace(string(output)))
	}

	oldConfig, readErr := os.ReadFile(a.cfg.ConfigPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("读取当前配置失败，未回滚: %w", readErr)
	}
	hadOld := readErr == nil

	if hadOld {
		backupPath := filepath.Join(a.cfg.BackupDir,
			"before-rollback-"+time.Now().Format("20060102-150405.000000")+".yaml")
		if err := os.WriteFile(backupPath, oldConfig, 0o600); err != nil {
			return nil, fmt.Errorf("备份当前配置失败，未回滚: %w", err)
		}
	}

	sum := sha256.Sum256([]byte(yml))
	cv := &ConfigVersion{
		Version: version,
		SHA256:  hex.EncodeToString(sum[:]),
		Status:  "rollback_failed",
	}

	tmp := a.cfg.ConfigPath + ".rollback-tmp"
	if err := os.WriteFile(tmp, []byte(yml), 0o600); err != nil {
		return cv, fmt.Errorf("写入回滚临时文件失败: %w", err)
	}
	defer os.Remove(tmp)

	if err := os.Rename(tmp, a.cfg.ConfigPath); err != nil {
		return cv, fmt.Errorf("替换配置失败: %w", err)
	}

	if err := a.ReloadMihomo(); err != nil {
		if !hadOld {
			_ = os.Remove(a.cfg.ConfigPath)
			cv.Status = "rollback_failed_no_previous_config"
			_ = a.store.UpdateVersionStatus(version, cv.Status)
			return cv, fmt.Errorf("历史配置重载失败，原先不存在配置文件，已移除回滚文件: %w", err)
		}

		restore := a.cfg.ConfigPath + ".rollback-restore"
		if writeErr := os.WriteFile(restore, oldConfig, 0o600); writeErr != nil {
			cv.Status = "rollback_failed_restore_failed"
			_ = a.store.UpdateVersionStatus(version, cv.Status)
			return cv, fmt.Errorf("历史配置重载失败: %v；写入恢复文件失败: %w", err, writeErr)
		}
		if renameErr := os.Rename(restore, a.cfg.ConfigPath); renameErr != nil {
			_ = os.Remove(restore)
			cv.Status = "rollback_failed_restore_failed"
			_ = a.store.UpdateVersionStatus(version, cv.Status)
			return cv, fmt.Errorf("历史配置重载失败: %v；恢复原配置失败: %w", err, renameErr)
		}

		if reloadErr := a.ReloadMihomo(); reloadErr != nil {
			cv.Status = "rollback_failed_old_reload_failed"
			_ = a.store.UpdateVersionStatus(version, cv.Status)
			return cv, fmt.Errorf("历史配置重载失败: %v；原配置文件已恢复，但重新加载也失败: %w", err, reloadErr)
		}

		cv.Status = "rollback_failed_restored"
		_ = a.store.UpdateVersionStatus(version, cv.Status)
		return cv, fmt.Errorf("回滚失败，已恢复原配置并重新加载: %w", err)
	}

	// Keep the editable global-config draft aligned with the configuration that
	// was actually rolled back. Otherwise preview/publish would rebuild from the
	// stale config_yaml setting and could silently undo the rollback.
	if err := a.store.UpdateSettings(map[string]string{"config_yaml": yml}); err != nil {
		cv.Status = "rolled_back_draft_sync_failed"
		_ = a.store.UpdateVersionStatus(version, cv.Status)
		return cv, fmt.Errorf("回滚已完成，但全局配置草稿同步失败；请重新保存当前回滚配置后再发布: %w", err)
	}

	cv.Status = "rolled_back"
	if err := a.store.UpdateVersionStatus(version, cv.Status); err != nil {
		return cv, fmt.Errorf("回滚已完成，但记录版本状态失败: %w", err)
	}
	return cv, nil
}
