package app

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

const (
	SmartDNSProxyModeShared  = "shared"
	SmartDNSProxyModePerClient = "per_client"
	SmartDNSDefaultStrategy = "fallback"
	SmartDNSGroupName = "SMARTDNS-PROXY"
)

// SmartDNSClientRoute binds one client subnet to a real Mihomo proxy name.
// A route is not active until the runtime has provisioned an isolated resolver
// instance for it; generating PROCESS-NAME rules for one shared process is invalid.
type SmartDNSClientRoute struct {
	ClientCIDR string `json:"client_cidr"`
	ProxyName  string `json:"proxy_name"`
	ListenPort int    `json:"listen_port,omitempty"`
}

type SmartDNSRoutingConfig struct {
	Mode     string                `json:"mode"`
	Strategy string                `json:"strategy"`
	Clients  []SmartDNSClientRoute `json:"clients,omitempty"`
}

type SmartDNSProxyRef struct {
	Name    string
	Enabled bool
}

// SmartDNSRoutingPlan is a validated, deterministic intermediate plan. Runtime
// code must consume this plan and provision the listeners/isolation before
// switching DNS traffic; it must not treat the plan itself as proof of routing.
type SmartDNSRoutingPlan struct {
	Mode       string
	Strategy   string
	GroupName  string
	ProxyNames []string
	Clients    []SmartDNSClientRoute
}

func BuildSmartDNSRoutingPlan(cfg SmartDNSRoutingConfig, proxies []SmartDNSProxyRef) (SmartDNSRoutingPlan, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		// Empty config is the legacy state: do not silently alter existing nodes.
		return SmartDNSRoutingPlan{Mode: "legacy"}, nil
	}
	if mode != SmartDNSProxyModeShared && mode != SmartDNSProxyModePerClient {
		return SmartDNSRoutingPlan{}, fmt.Errorf("SmartDNS 代理模式无效: %q", cfg.Mode)
	}
	strategy := strings.ToLower(strings.TrimSpace(cfg.Strategy))
	if strategy == "" {
		strategy = SmartDNSDefaultStrategy
	}
	if strategy != SmartDNSDefaultStrategy {
		return SmartDNSRoutingPlan{}, fmt.Errorf("当前仅支持 fallback 策略，收到: %q", cfg.Strategy)
	}

	available := make(map[string]bool, len(proxies))
	for _, p := range proxies {
		name := strings.TrimSpace(p.Name)
		if name == "" || len(name) > 100 {
			if p.Enabled {
				return SmartDNSRoutingPlan{}, fmt.Errorf("启用的代理名称不能为空且不能超过 100 个字符")
			}
			continue
		}
		if p.Enabled {
			available[name] = true
		}
	}
	names := make([]string, 0, len(available))
	for name := range available { names = append(names, name) }
	sort.Strings(names)
	if len(names) == 0 {
		return SmartDNSRoutingPlan{}, fmt.Errorf("SmartDNS 代理模式已启用，但没有可用代理节点")
	}

	plan := SmartDNSRoutingPlan{Mode: mode, Strategy: strategy, ProxyNames: names}
	if mode == SmartDNSProxyModeShared {
		plan.GroupName = SmartDNSGroupName
		if len(cfg.Clients) != 0 {
			return SmartDNSRoutingPlan{}, fmt.Errorf("统一动态代理模式不接受客户端独立出口映射")
		}
		return plan, nil
	}

	seen := make(map[string]bool, len(cfg.Clients))
	networks := make([]*net.IPNet, 0, len(cfg.Clients))
	ports := make(map[int]bool, len(cfg.Clients))
	for i, route := range cfg.Clients {
		route.ClientCIDR = strings.TrimSpace(route.ClientCIDR)
		route.ProxyName = strings.TrimSpace(route.ProxyName)
		if route.ClientCIDR == "" || route.ProxyName == "" {
			return SmartDNSRoutingPlan{}, fmt.Errorf("第 %d 条客户端 DNS 映射缺少 CIDR 或代理节点", i+1)
		}
		_, network, err := net.ParseCIDR(route.ClientCIDR)
		if err != nil { return SmartDNSRoutingPlan{}, fmt.Errorf("第 %d 条客户端 CIDR 无效: %w", i+1, err) }
		route.ClientCIDR = network.String()
		if seen[route.ClientCIDR] { return SmartDNSRoutingPlan{}, fmt.Errorf("客户端网段重复映射: %s", route.ClientCIDR) }
		for _, existing := range networks {
			if network.Contains(existing.IP) || existing.Contains(network.IP) {
				return SmartDNSRoutingPlan{}, fmt.Errorf("客户端网段存在重叠映射: %s 与 %s", route.ClientCIDR, existing.String())
			}
		}
		networks = append(networks, network)
		seen[route.ClientCIDR] = true
		if !available[route.ProxyName] { return SmartDNSRoutingPlan{}, fmt.Errorf("客户端网段 %s 引用了不存在或已禁用的代理 %q", route.ClientCIDR, route.ProxyName) }
		if route.ListenPort < 0 || route.ListenPort > 65535 { return SmartDNSRoutingPlan{}, fmt.Errorf("客户端网段 %s 的 DNS 监听端口无效", route.ClientCIDR) }
		if route.ListenPort != 0 {
			if ports[route.ListenPort] { return SmartDNSRoutingPlan{}, fmt.Errorf("SmartDNS 监听端口重复: %d", route.ListenPort) }
			ports[route.ListenPort] = true
		}
		plan.Clients = append(plan.Clients, route)
	}
	if len(plan.Clients) == 0 { return SmartDNSRoutingPlan{}, fmt.Errorf("按客户端 IP 独立代理模式至少需要一条映射") }
	sort.Slice(plan.Clients, func(i, j int) bool { return plan.Clients[i].ClientCIDR < plan.Clients[j].ClientCIDR })
	return plan, nil
}
