package app

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// applySmartDNSSharedFallback wires the validated shared routing plan into a
// generated Mihomo document. Legacy documents are returned byte-for-byte when
// the mode is not shared; per-client mode is deliberately not synthesized here.
func applySmartDNSSharedFallback(document string, plan SmartDNSRoutingPlan) (string, error) {
	if plan.Mode != SmartDNSProxyModeShared {
		return document, nil
	}
	if plan.Strategy != SmartDNSDefaultStrategy || len(plan.ProxyNames) == 0 {
		return "", fmt.Errorf("SmartDNS shared fallback 缺少有效代理或策略")
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(document), &root); err != nil {
		return "", fmt.Errorf("解析 Mihomo YAML 失败: %w", err)
	}
	if len(root) == 0 {
		return "", fmt.Errorf("Mihomo YAML 必须是非空对象")
	}
	groups, _ := root["proxy-groups"].([]any)
	// Refuse to silently replace an operator-owned group with the reserved name.
	for _, raw := range groups {
		group, ok := raw.(map[string]any)
		if ok && group["name"] == SmartDNSGroupName {
			return "", fmt.Errorf("代理组名称 %q 已被占用", SmartDNSGroupName)
		}
	}
	proxies := make([]any, 0, len(plan.ProxyNames))
	for _, name := range plan.ProxyNames {
		if strings.TrimSpace(name) == "" {
			return "", fmt.Errorf("SmartDNS Fallback 代理名称不能为空")
		}
		proxies = append(proxies, name)
	}
	groups = append(groups, map[string]any{
		"name": SmartDNSGroupName,
		"type": "fallback",
		"proxies": proxies,
		"url": "https://www.gstatic.com/generate_204",
		"interval": 60,
	})
	root["proxy-groups"] = groups

	rules, ok := root["rules"].([]any)
	if !ok {
		return "", fmt.Errorf("Mihomo rules 必须是数组")
	}
	replaced := false
	for i, raw := range rules {
		rule, ok := raw.(string)
		if !ok {
			return "", fmt.Errorf("Mihomo rules 第 %d 项不是字符串", i)
		}
		parts := strings.Split(rule, ",")
		if len(parts) >= 3 && strings.EqualFold(strings.TrimSpace(parts[0]), "PROCESS-NAME") &&
			strings.EqualFold(strings.TrimSpace(parts[1]), "smartdns") {
			rules[i] = "PROCESS-NAME,smartdns," + SmartDNSGroupName
			replaced = true
		}
	}
	if !replaced {
		// Return-to-China mode historically omitted the SmartDNS process rule
			// because DNS was expected to follow destination geography. Shared
		// SmartDNS mode explicitly selects one DNS egress group, so add its rule
		// after the controller/domain bypasses and before client/terminal rules.
		// Only the generated controller bypasses may precede this process rule.
		// Never skip arbitrary operator DOMAIN/IP-CIDR rules: doing so could let
		// a broad custom rule shadow the explicit SmartDNS egress policy.
		insertAt := 0
		// Only treat a directly following DOMAIN rule as the controller bypass
		// when the generated v2net.cc suffix bypass is present. An arbitrary
		// operator DOMAIN rule at the beginning must not be mistaken for it.
		controllerBypassPrefix := false
		if insertAt < len(rules) {
			if rule, ok := rules[insertAt].(string); ok &&
				strings.HasPrefix(strings.ToUpper(strings.TrimSpace(rule)), "DOMAIN-SUFFIX,V2NET.CC,DIRECT") {
				insertAt++
				controllerBypassPrefix = true
			}
		}
		if controllerBypassPrefix && insertAt < len(rules) {
			if rule, ok := rules[insertAt].(string); ok {
				upper := strings.ToUpper(strings.TrimSpace(rule))
				if strings.HasPrefix(upper, "DOMAIN,") && strings.HasSuffix(upper, ",DIRECT") {
					insertAt++
				}
			}
		}
		rules = append(rules, nil)
		copy(rules[insertAt+1:], rules[insertAt:])
		rules[insertAt] = "PROCESS-NAME,smartdns," + SmartDNSGroupName
	}
	root["rules"] = rules
	out, err := yaml.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("序列化 SmartDNS Fallback 配置失败: %w", err)
	}
	return string(out), nil
}


// applySmartDNSPerClientListeners creates one loopback-only SOCKS listener per
// client mapping. Each listener is pinned directly to the selected Mihomo
// outbound; it never traverses the global rules or a shared proxy group.
func applySmartDNSPerClientListeners(document string, plan SmartDNSRoutingPlan) (string, error) {
	if plan.Mode != SmartDNSProxyModePerClient {
		return document, nil
	}
	if len(plan.Clients) == 0 || len(plan.ProxyNames) == 0 {
		return "", fmt.Errorf("SmartDNS per-client 缺少客户端映射或可用代理")
	}
	allowed := make(map[string]bool, len(plan.ProxyNames))
	for _, name := range plan.ProxyNames {
		if strings.TrimSpace(name) == "" {
			return "", fmt.Errorf("SmartDNS per-client 代理名称不能为空")
		}
		allowed[name] = true
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(document), &root); err != nil {
		return "", fmt.Errorf("解析 Mihomo YAML 失败: %w", err)
	}
	if len(root) == 0 {
		return "", fmt.Errorf("Mihomo YAML 必须是非空对象")
	}
	proxies, ok := root["proxies"].([]any)
	if !ok {
		return "", fmt.Errorf("Mihomo proxies 必须是数组")
	}
	existingProxies := make(map[string]bool, len(proxies))
	for _, raw := range proxies {
		p, ok := raw.(map[string]any)
		if !ok { return "", fmt.Errorf("Mihomo proxies 包含无效项目") }
		if name, ok := p["name"].(string); ok { existingProxies[name] = true }
	}
	var listeners []any
	if rawListeners, exists := root["listeners"]; exists {
		var ok bool
		listeners, ok = rawListeners.([]any)
		if !ok {
			return "", fmt.Errorf("Mihomo listeners 必须是数组，拒绝覆盖现有配置")
		}
	}
	usedPorts := make(map[int]bool, len(listeners))
	usedNames := make(map[string]bool, len(listeners))
	for index, raw := range listeners {
		item, ok := raw.(map[string]any)
		if !ok {
			return "", fmt.Errorf("Mihomo listeners 第 %d 项不是对象", index)
		}
		if name, exists := item["name"]; exists {
			value, ok := name.(string)
			if !ok || strings.TrimSpace(value) == "" {
				return "", fmt.Errorf("Mihomo listeners 第 %d 项名称无效", index)
			}
			usedNames[value] = true
		}
		if rawPort, exists := item["port"]; exists {
			var port int
			switch value := rawPort.(type) {
			case int:
				port = value
			case int64:
				port = int(value)
			case uint64:
				if value > 65535 { return "", fmt.Errorf("Mihomo listeners 第 %d 项端口越界", index) }
				port = int(value)
			case float64:
				if value != float64(int(value)) { return "", fmt.Errorf("Mihomo listeners 第 %d 项端口不是整数", index) }
				port = int(value)
			default:
				return "", fmt.Errorf("Mihomo listeners 第 %d 项端口类型无效", index)
			}
			if port < 1 || port > 65535 {
				return "", fmt.Errorf("Mihomo listeners 第 %d 项端口越界", index)
			}
			usedPorts[port] = true
		}
	}
	for _, client := range plan.Clients {
		if !allowed[client.ProxyName] || !existingProxies[client.ProxyName] {
			return "", fmt.Errorf("客户端 %s 指向的代理 %q 未出现在当前 Mihomo 配置中", client.ClientCIDR, client.ProxyName)
		}
		port := client.ListenPort
		if port == 0 {
			// Auto-assigned ports must skip operator-owned listeners instead of
			// failing on the first deterministic slot. Keep allocation stable.
			port = 16000
			for port <= 65535 && usedPorts[port] { port++ }
		}
		if port < 1024 || port > 65535 || usedPorts[port] {
			return "", fmt.Errorf("客户端 %s 的 Mihomo SOCKS 监听端口 %d 无效或已占用", client.ClientCIDR, port)
		}
		name := fmt.Sprintf("s5m-smartdns-%d", port)
		if usedNames[name] { return "", fmt.Errorf("Mihomo Listener 名称 %q 已被占用", name) }
		listeners = append(listeners, map[string]any{
			"name": name, "type": "socks", "listen": "127.0.0.1",
			"port": port, "udp": true, "proxy": client.ProxyName,
		})
		usedPorts[port], usedNames[name] = true, true
	}
	root["listeners"] = listeners
	out, err := yaml.Marshal(root)
	if err != nil { return "", fmt.Errorf("序列化 Mihomo per-client Listener 失败: %w", err) }
	return string(out), nil
}
