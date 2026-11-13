package app

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

func readySmartDNSIngressSettings(now time.Time, cidrs ...string) map[string]string {
	status := map[string]any{
		"dns_ingress_contract_version": float64(smartDNSIngressReadinessContractVersion),
		"dns_ingress_ready": true,
		"dns_ingress_source_ip_preserved": true,
		"dns_ingress_firewall_ready": true,
		"dns_ingress_firewall_persistent": true,
		"dns_ingress_udp_ready": true,
		"dns_ingress_tcp_ready": true,
		"dns_ingress_smartdns_listener_ready": true,
		"dns_ingress_smartdns_ipv4_bound": true,
		"dns_ingress_smartdns_ipv4_bind_address": "192.0.2.1",
		"dns_ingress_smartdns_ipv6_bound": true,
		"dns_ingress_smartdns_ipv6_bind_address": "2001:db8::1",
		"dns_ingress_interface": "eth0",
		"dns_ingress_client_cidrs": cidrs,
		"dns_ingress_ipv4_ready": true,
		"dns_ingress_ipv4_address": "192.0.2.1",
		"dns_ingress_ipv6_ready": true,
		"dns_ingress_ipv6_address": "2001:db8::1",
	}
	raw, _ := json.Marshal(status)
	return map[string]string{
		"agent_lastseen_node-a": strconv.FormatInt(now.Unix(), 10),
		"agent_status_node-a": string(raw),
	}
}

func TestValidateSmartDNSIngressReadinessRequiresCompleteFreshAttestation(t *testing.T) {
	now := time.Unix(1794560000, 0)
	routing := SmartDNSRoutingConfig{Mode: SmartDNSProxyModePerClient, Clients: []SmartDNSClientRoute{
		{ClientCIDR: "192.168.50.0/24", ProxyName: "proxy-a"},
		{ClientCIDR: "2001:db8:50::/64", ProxyName: "proxy-b"},
	}}
	valid := readySmartDNSIngressSettings(now, "192.168.50.0/24", "2001:db8:50::/64")
	if err := validateSmartDNSIngressReadiness(valid, "node-a", routing, now); err != nil {
		t.Fatalf("valid ingress attestation rejected: %v", err)
	}

	tests := []struct {
		name string
		mutate func(map[string]string)
		want string
	}{
		{"missing status", func(s map[string]string) { delete(s, "agent_status_node-a") }, "状态缺失"},
		{"stale heartbeat", func(s map[string]string) { s["agent_lastseen_node-a"] = "1" }, "已过期"},
		{"no source preservation", func(s map[string]string) { s["agent_status_node-a"] = strings.Replace(s["agent_status_node-a"], `"dns_ingress_source_ip_preserved":true`, `"dns_ingress_source_ip_preserved":false`, 1) }, "source_ip_preserved"},
		{"firewall not persistent", func(s map[string]string) { s["agent_status_node-a"] = strings.Replace(s["agent_status_node-a"], `"dns_ingress_firewall_persistent":true`, `"dns_ingress_firewall_persistent":false`, 1) }, "firewall_persistent"},
		{"missing TCP", func(s map[string]string) { s["agent_status_node-a"] = strings.Replace(s["agent_status_node-a"], `"dns_ingress_tcp_ready":true`, `"dns_ingress_tcp_ready":false`, 1) }, "tcp_ready"},
		{"SmartDNS not bound to ingress", func(s map[string]string) { s["agent_status_node-a"] = strings.Replace(s["agent_status_node-a"], `"dns_ingress_smartdns_ipv4_bound":true`, `"dns_ingress_smartdns_ipv4_bound":false`, 1) }, "SmartDNS 未在已验收的 IPv4 ingress 地址上"},
		{"CIDR not provisioned", func(s map[string]string) { s["agent_status_node-a"] = strings.Replace(s["agent_status_node-a"], "192.168.50.0/24", "192.168.60.0/24", 1) }, "未授权"},
		{"IPv6 not ready", func(s map[string]string) { s["agent_status_node-a"] = strings.Replace(s["agent_status_node-a"], `"dns_ingress_ipv6_ready":true`, `"dns_ingress_ipv6_ready":false`, 1) }, "IPv6"},
		{"invalid interface", func(s map[string]string) { s["agent_status_node-a"] = strings.Replace(s["agent_status_node-a"], `"dns_ingress_interface":"eth0"`, `"dns_ingress_interface":"eth0;bad"`, 1) }, "网卡信息"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := readySmartDNSIngressSettings(now, "192.168.50.0/24", "2001:db8:50::/64")
			tt.mutate(got)
			err := validateSmartDNSIngressReadiness(got, "node-a", routing, now)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestValidateSmartDNSIngressReadinessChecksOnlyMappedAddressFamilies(t *testing.T) {
	now := time.Unix(1794560000, 0)
	routing := SmartDNSRoutingConfig{Mode: SmartDNSProxyModePerClient, Clients: []SmartDNSClientRoute{
		{ClientCIDR: "192.168.50.0/24", ProxyName: "proxy-a"},
	}}
	settings := readySmartDNSIngressSettings(now, "192.168.50.0/24")
	raw := strings.Replace(settings["agent_status_node-a"], `,"dns_ingress_ipv6_ready":true,"dns_ingress_ipv6_address":"2001:db8::1","dns_ingress_smartdns_ipv6_bound":true,"dns_ingress_smartdns_ipv6_bind_address":"2001:db8::1"`, "", 1)
	settings["agent_status_node-a"] = raw
	if err := validateSmartDNSIngressReadiness(settings, "node-a", routing, now); err != nil {
		t.Fatalf("IPv4-only route should not require an IPv6 ingress address: %v", err)
	}
}
