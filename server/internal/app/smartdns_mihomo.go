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
		return "", fmt.Errorf("未找到 SmartDNS PROCESS-NAME 路由规则，拒绝生成未生效的 Fallback 配置")
	}
	root["rules"] = rules
	out, err := yaml.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("序列化 SmartDNS Fallback 配置失败: %w", err)
	}
	return string(out), nil
}
