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


func TestValidateSmartDNSIngressReadinessRequiresExactFirewallCIDRSet(t *testing.T) {
	now := time.Unix(1794560000, 0)
	routing := SmartDNSRoutingConfig{Mode: SmartDNSProxyModePerClient, Clients: []SmartDNSClientRoute{
		{ClientCIDR: "192.168.50.0/24", ProxyName: "proxy-a"},
	}}
	for _, tc := range []struct {
		name string
		mutate func([]any) []any
	}{
		{
			name: "extra unconfigured CIDR",
			mutate: func(values []any) []any { return append(values, "192.168.60.0/24") },
		},
		{
			name: "duplicate CIDR",
			mutate: func(values []any) []any { return append(values, "192.168.50.0/24") },
		},
		{
			name: "duplicate after normalization",
			mutate: func(values []any) []any { return append(values, "192.168.50.9/24") },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := readySmartDNSIngressSettings(now, "192.168.50.0/24")
			var status map[string]any
			if err := json.Unmarshal([]byte(settings["agent_status_node-a"]), &status); err != nil {
				t.Fatal(err)
			}
			values, ok := status["dns_ingress_client_cidrs"].([]any)
			if !ok { t.Fatal("CIDR fixture has unexpected type") }
			status["dns_ingress_client_cidrs"] = tc.mutate(values)
			raw, err := json.Marshal(status)
			if err != nil { t.Fatal(err) }
			settings["agent_status_node-a"] = string(raw)
			if err := validateSmartDNSIngressReadiness(settings, "node-a", routing, now); err == nil {
				t.Fatal("ingress readiness accepted a non-exact firewall CIDR set")
			}
		})
	}
}


func TestValidateSmartDNSIngressReadinessRejectsDefaultAndMappedCIDRs(t *testing.T) {
	now := time.Unix(1794560000, 0)
	for _, cidr := range []string{"0.0.0.0/0", "::/0", "::ffff:192.0.2.0/120"} {
		t.Run(cidr, func(t *testing.T) {
			routing := SmartDNSRoutingConfig{Mode: SmartDNSProxyModePerClient, Clients: []SmartDNSClientRoute{
				{ClientCIDR: cidr, ProxyName: "proxy-a"},
			}}
			settings := readySmartDNSIngressSettings(now, cidr)
			if err := validateSmartDNSIngressReadiness(settings, "node-a", routing, now); err == nil {
				t.Fatalf("unsafe CIDR %s accepted by production readiness gate", cidr)
			}
		})
	}
}


func TestValidateSmartDNSIngressReadinessRejectsLinkLocalAddresses(t *testing.T) {
	now := time.Unix(1794560000, 0)
	routing := SmartDNSRoutingConfig{Mode: SmartDNSProxyModePerClient, Clients: []SmartDNSClientRoute{
		{ClientCIDR: "192.168.50.0/24", ProxyName: "proxy-a"},
	}}
	settings := readySmartDNSIngressSettings(now, "192.168.50.0/24")
	var status map[string]any
	if err := json.Unmarshal([]byte(settings["agent_status_node-a"]), &status); err != nil { t.Fatal(err) }
	status["dns_ingress_ipv4_address"] = "169.254.10.1"
	status["dns_ingress_smartdns_ipv4_bind_address"] = "169.254.10.1"
	raw, err := json.Marshal(status)
	if err != nil { t.Fatal(err) }
	settings["agent_status_node-a"] = string(raw)
	if err := validateSmartDNSIngressReadiness(settings, "node-a", routing, now); err == nil {
		t.Fatal("link-local ingress address accepted")
	}
}


func TestValidateSmartDNSIngressReadinessRejectsNonRoutableClientCIDRs(t *testing.T) {
	now := time.Unix(1794560000, 0)
	for _, cidr := range []string{"127.0.0.0/8", "169.254.0.0/16", "fe80::/64", "::1/128"} {
		t.Run(cidr, func(t *testing.T) {
			routing := SmartDNSRoutingConfig{Mode: SmartDNSProxyModePerClient, Clients: []SmartDNSClientRoute{
				{ClientCIDR: cidr, ProxyName: "proxy-a"},
			}}
			settings := readySmartDNSIngressSettings(now, cidr)
			if err := validateSmartDNSIngressReadiness(settings, "node-a", routing, now); err == nil {
				t.Fatalf("non-routable client CIDR %s accepted", cidr)
			}
		})
	}
}


func TestBuildSmartDNSAgentIngressContractFromFreshReadiness(t *testing.T) {
	now := time.Unix(1794560000, 0)
	routing := SmartDNSRoutingConfig{Mode: SmartDNSProxyModePerClient, Clients: []SmartDNSClientRoute{
		{ClientCIDR: "192.168.50.0/24", ProxyName: "proxy-v4"},
		{ClientCIDR: "2001:db8:50::/64", ProxyName: "proxy-v6"},
	}}
	settings := readySmartDNSIngressSettings(now, "192.168.50.0/24", "2001:db8:50::/64")
	contract, err := buildSmartDNSAgentIngressContract(settings, "node-a", routing, now)
	if err != nil { t.Fatalf("build ingress contract: %v", err) }
	if contract.Version != 1 || !contract.Ready || contract.IPv4Address != "192.0.2.1" || contract.IPv6Address != "2001:db8::1" {
		t.Fatalf("unexpected ingress contract: %#v", contract)
	}
	if len(contract.ClientCIDRs) != 2 || contract.ClientCIDRs[0] != "192.168.50.0/24" || contract.ClientCIDRs[1] != "2001:db8:50::/64" {
		t.Fatalf("unexpected contract CIDR set: %#v", contract.ClientCIDRs)
	}
}

func TestBuildSmartDNSAgentIngressContractRejectsStaleOrIncompleteStatus(t *testing.T) {
	now := time.Unix(1794560000, 0)
	routing := SmartDNSRoutingConfig{Mode: SmartDNSProxyModePerClient, Clients: []SmartDNSClientRoute{
		{ClientCIDR: "192.168.50.0/24", ProxyName: "proxy-v4"},
	}}
	settings := readySmartDNSIngressSettings(now, "192.168.50.0/24")
	delete(settings, "agent_status_node-a")
	if _, err := buildSmartDNSAgentIngressContract(settings, "node-a", routing, now); err == nil {
		t.Fatal("contract builder accepted missing Agent readiness status")
	}
}


func TestValidateSmartDNSIngressReadinessRejectsIPv4MappedIPv6Addresses(t *testing.T) {
	now := time.Unix(1794560000, 0)
	routing := SmartDNSRoutingConfig{Mode: SmartDNSProxyModePerClient, Clients: []SmartDNSClientRoute{
		{ClientCIDR: "192.168.50.0/24", ProxyName: "proxy-a"},
	}}
	settings := readySmartDNSIngressSettings(now, "192.168.50.0/24")
	var status map[string]any
	if err := json.Unmarshal([]byte(settings["agent_status_node-a"]), &status); err != nil { t.Fatal(err) }
	status["dns_ingress_ipv4_address"] = "::ffff:192.0.2.1"
	status["dns_ingress_smartdns_ipv4_bind_address"] = "::ffff:192.0.2.1"
	raw, err := json.Marshal(status)
	if err != nil { t.Fatal(err) }
	settings["agent_status_node-a"] = string(raw)
	if err := validateSmartDNSIngressReadiness(settings, "node-a", routing, now); err == nil {
		t.Fatal("IPv4-mapped IPv6 ingress address accepted as IPv4")
	}
}


func TestSmartDNSIngressProvisioningAllowsFirstBindButPublicationRequiresRuntimeReady(t *testing.T) {
	now := time.Unix(1794560000, 0)
	routing := SmartDNSRoutingConfig{Mode: SmartDNSProxyModePerClient, Clients: []SmartDNSClientRoute{
		{ClientCIDR: "192.168.50.0/24", ProxyName: "proxy-a"},
	}}
	settings := readySmartDNSIngressSettings(now, "192.168.50.0/24")
	var status map[string]any
	if err := json.Unmarshal([]byte(settings["agent_status_node-a"]), &status); err != nil { t.Fatal(err) }
	status["dns_ingress_ready"] = false
	status["dns_ingress_smartdns_listener_ready"] = false
	status["dns_ingress_smartdns_ipv4_bound"] = false
	status["dns_ingress_smartdns_ipv4_bind_address"] = ""
	raw, err := json.Marshal(status)
	if err != nil { t.Fatal(err) }
	settings["agent_status_node-a"] = string(raw)
	if err := validateSmartDNSIngressProvisioning(settings, "node-a", routing, now); err != nil {
		t.Fatalf("valid host-side provisioning state rejected before first SmartDNS bind: %v", err)
	}
	if err := validateSmartDNSIngressReadiness(settings, "node-a", routing, now); err == nil {
		t.Fatal("runtime publication gate accepted an Agent before SmartDNS ingress bind")
	}
	contract, err := buildSmartDNSAgentIngressProvisioningContract(settings, "node-a", routing, now)
	if err != nil || !contract.Ready || contract.IPv4Address != "192.0.2.1" {
		t.Fatalf("provisioning contract = %#v, err=%v", contract, err)
	}
}
