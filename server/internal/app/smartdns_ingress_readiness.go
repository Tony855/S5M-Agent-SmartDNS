package app

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const smartDNSIngressReadinessContractVersion = 1

var smartDNSIngressInterfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

// validateSmartDNSIngressReadiness is the Master-side fail-closed gate for
// per-client config publication. A heartbeat capability bit alone is not
// sufficient: it must attest to the exact routed ingress, firewall, transport,
// address-family and CIDR state that the generated config depends on.
func validateSmartDNSIngressReadiness(settings map[string]string, machineCode string, routing SmartDNSRoutingConfig, now time.Time) error {
	machineCode = strings.TrimSpace(machineCode)
	if machineCode == "" {
		return fmt.Errorf("Agent 机器码为空，无法验证 DNS ingress 就绪状态")
	}
	lastSeen, err := strconv.ParseInt(strings.TrimSpace(settings["agent_lastseen_"+machineCode]), 10, 64)
	if err != nil || lastSeen <= 0 {
		return fmt.Errorf("Agent 尚未上报 DNS ingress 心跳")
	}
	age := now.Sub(time.Unix(lastSeen, 0))
	if age > 90*time.Second || age < -30*time.Second {
		return fmt.Errorf("Agent DNS ingress 就绪状态已过期")
	}

	var status map[string]any
	if err := json.Unmarshal([]byte(settings["agent_status_"+machineCode]), &status); err != nil || status == nil {
		return fmt.Errorf("Agent DNS ingress 状态缺失或格式无效")
	}
	if version, ok := status["dns_ingress_contract_version"].(float64); !ok || version != smartDNSIngressReadinessContractVersion {
		return fmt.Errorf("Agent DNS ingress 就绪协议版本不匹配")
	}
	for _, key := range []string{
		"dns_ingress_ready",
		"dns_ingress_source_ip_preserved",
		"dns_ingress_firewall_ready",
		"dns_ingress_firewall_persistent",
		"dns_ingress_udp_ready",
		"dns_ingress_tcp_ready",
		"dns_ingress_smartdns_listener_ready",
	} {
		if status[key] != true {
			return fmt.Errorf("Agent DNS ingress 未满足就绪条件: %s", key)
		}
	}
	if iface, ok := status["dns_ingress_interface"].(string); !ok || !smartDNSIngressInterfacePattern.MatchString(iface) {
		return fmt.Errorf("Agent DNS ingress 网卡信息缺失或无效")
	}

	hasIPv4, hasIPv6 := false, false
	requiredCIDRs := make(map[string]struct{}, len(routing.Clients))
	for _, route := range routing.Clients {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(route.ClientCIDR))
		if err != nil {
			return fmt.Errorf("DNS ingress 映射 CIDR 无效: %q", route.ClientCIDR)
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 || prefix.Addr().IsUnspecified() || prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() || prefix.Addr().IsMulticast() || prefix.Addr().Is4In6() {
			return fmt.Errorf("DNS ingress 客户端 CIDR 过宽或使用保留地址族: %s", prefix.String())
		}
		requiredCIDRs[prefix.String()] = struct{}{}
		if prefix.Addr().Is4() {
			hasIPv4 = true
		} else {
			hasIPv6 = true
		}
	}
	if len(requiredCIDRs) == 0 {
		return fmt.Errorf("DNS ingress 没有可验收的客户端 CIDR")
	}

	reported, ok := status["dns_ingress_client_cidrs"].([]any)
	if !ok {
		return fmt.Errorf("Agent 未上报 DNS ingress 允许的客户端 CIDR")
	}
	allowed := make(map[string]struct{}, len(reported))
	for _, item := range reported {
		value, ok := item.(string)
		if !ok {
			return fmt.Errorf("Agent DNS ingress CIDR 状态包含无效项目")
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("Agent DNS ingress CIDR 状态包含无效网段")
		}
		normalized := prefix.Masked().String()
		if _, duplicate := allowed[normalized]; duplicate {
			return fmt.Errorf("Agent DNS ingress CIDR 状态包含重复网段: %s", normalized)
		}
		allowed[normalized] = struct{}{}
	}
	// The firewall allowlist must be the exact configured CIDR set. A
	// superset is not acceptable: it would silently authorize client networks
	// that have no per-client proxy mapping, even though SmartDNS itself
	// remains fail-closed for those clients.
	for cidr := range requiredCIDRs {
		if _, ok := allowed[cidr]; !ok {
			return fmt.Errorf("Agent DNS ingress 未授权当前映射网段: %s", cidr)
		}
	}
	for cidr := range allowed {
		if _, ok := requiredCIDRs[cidr]; !ok {
			return fmt.Errorf("Agent DNS ingress 防火墙包含未配置的额外网段: %s", cidr)
		}
	}
	if len(allowed) != len(requiredCIDRs) {
		return fmt.Errorf("Agent DNS ingress 防火墙 CIDR 集合与当前映射不完全一致")
	}

	validateAddress := func(key string, wantIPv4 bool) error {
		value, ok := status[key].(string)
		if !ok {
			return fmt.Errorf("Agent DNS ingress 地址缺失: %s", key)
		}
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || (wantIPv4 && ip.To4() == nil) || (!wantIPv4 && ip.To4() != nil) {
			return fmt.Errorf("Agent DNS ingress 地址无效: %s", key)
		}
		return nil
	}
	if hasIPv4 {
		if status["dns_ingress_ipv4_ready"] != true {
			return fmt.Errorf("Agent DNS ingress IPv4 尚未就绪")
		}
		if err := validateAddress("dns_ingress_ipv4_address", true); err != nil {
			return err
		}
		if status["dns_ingress_smartdns_ipv4_bound"] != true || status["dns_ingress_smartdns_ipv4_bind_address"] != status["dns_ingress_ipv4_address"] {
			return fmt.Errorf("SmartDNS 未在已验收的 IPv4 ingress 地址上同时监听")
		}
	}
	if hasIPv6 {
		if status["dns_ingress_ipv6_ready"] != true {
			return fmt.Errorf("Agent DNS ingress IPv6 尚未就绪")
		}
		if err := validateAddress("dns_ingress_ipv6_address", false); err != nil {
			return err
		}
		if status["dns_ingress_smartdns_ipv6_bound"] != true || status["dns_ingress_smartdns_ipv6_bind_address"] != status["dns_ingress_ipv6_address"] {
			return fmt.Errorf("SmartDNS 未在已验收的 IPv6 ingress 地址上同时监听")
		}
	}
	return nil
}


// requireSmartDNSIngressReady centralizes the production fail-closed gate so
// both periodic config publication and direct SmartDNS apply commands enforce
// the same per-client ingress contract.
func (a *App) requireSmartDNSIngressReady(machineCode string) error {
	raw, err := a.store.GetSetting("smartdns_routing_config")
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("读取 SmartDNS 路由模式失败: %w", err)
	}
	if err == sql.ErrNoRows || strings.TrimSpace(raw) == "" {
		return nil
	}
	var routing SmartDNSRoutingConfig
	if err := json.Unmarshal([]byte(raw), &routing); err != nil {
		return fmt.Errorf("SmartDNS 路由设置 JSON 无效: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(routing.Mode), SmartDNSProxyModePerClient) {
		return nil
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		return fmt.Errorf("读取 Agent DNS ingress 就绪状态失败: %w", err)
	}
	if err := validateSmartDNSIngressReadiness(settings, machineCode, routing, time.Now()); err != nil {
		return fmt.Errorf("Agent DNS ingress 尚未通过生产就绪校验，拒绝发布 per-client 配置: %w", err)
	}
	return nil
}
