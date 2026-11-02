package app

import (
	"strings"
	"testing"
)

func TestBuildSmartDNSPerClientConfigUsesExactLoopbackListenerMappings(t *testing.T) {
	mappings := []SmartDNSClientRuntimeMapping{
		{ClientCIDR: "192.168.20.0/24", ProxyName: "node-b", ListenerName: "s5m-smartdns-16001", ListenerAddress: "127.0.0.1", ListenerPort: 16001},
		{ClientCIDR: "192.168.10.0/24", ProxyName: "node-a", ListenerName: "s5m-smartdns-16000", ListenerAddress: "127.0.0.1", ListenerPort: 16000},
	}
	got, err := buildSmartDNSPerClientConfig(mappings)
	if err != nil {
		t.Fatalf("build SmartDNS config: %v", err)
	}
	for _, want := range []string{
		"bind 127.0.0.1:6053",
		"bind-tcp 127.0.0.1:6053",
		"proxy-server socks5://127.0.0.1:16000 -name s5m-smartdns-16000",
		"server-tls 1.1.1.1:853 -host-name cloudflare-dns.com -group s5m-smartdns-group-16000 -proxy s5m-smartdns-16000",
		"server-tls 8.8.8.8:853 -host-name dns.google -group s5m-smartdns-group-16000 -proxy s5m-smartdns-16000",
		"group-match -client-ip 192.168.10.0/24 -g s5m-smartdns-group-16000",
		"proxy-server socks5://127.0.0.1:16001 -name s5m-smartdns-16001",
		"group-match -client-ip 192.168.20.0/24 -g s5m-smartdns-group-16001",
		"No default upstream",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("generated config missing %q:\n%s", want, got)
		}
	}
	if strings.Index(got, "192.168.10.0/24") > strings.Index(got, "192.168.20.0/24") {
		t.Fatalf("generated config is not deterministic by CIDR order:\n%s", got)
	}
}

func TestBuildSmartDNSPerClientConfigRejectsUnsafeMappings(t *testing.T) {
	base := SmartDNSClientRuntimeMapping{
		ClientCIDR: "192.168.10.0/24", ProxyName: "node-a",
		ListenerName: "s5m-smartdns-16000", ListenerAddress: "127.0.0.1", ListenerPort: 16000,
	}
	cases := []struct {
		name string
		edit func(*SmartDNSClientRuntimeMapping)
	}{
		{name: "non-loopback listener", edit: func(m *SmartDNSClientRuntimeMapping) { m.ListenerAddress = "0.0.0.0" }},
		{name: "privileged port", edit: func(m *SmartDNSClientRuntimeMapping) { m.ListenerPort = 53 }},
		{name: "invalid CIDR", edit: func(m *SmartDNSClientRuntimeMapping) { m.ClientCIDR = "not-a-cidr" }},
		{name: "missing proxy", edit: func(m *SmartDNSClientRuntimeMapping) { m.ProxyName = "" }},
		{name: "missing listener name", edit: func(m *SmartDNSClientRuntimeMapping) { m.ListenerName = "" }},
		{name: "listener name and port mismatch", edit: func(m *SmartDNSClientRuntimeMapping) { m.ListenerName = "s5m-smartdns-16001" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := base
			tc.edit(&m)
			if _, err := buildSmartDNSPerClientConfig([]SmartDNSClientRuntimeMapping{m}); err == nil {
				t.Fatal("unsafe mapping accepted")
			}
		})
	}
	if _, err := buildSmartDNSPerClientConfig(nil); err == nil {
		t.Fatal("empty mapping list accepted")
	}
}

func TestBuildSmartDNSPerClientConfigRejectsDuplicateCIDRsAndPorts(t *testing.T) {
	first := SmartDNSClientRuntimeMapping{
		ClientCIDR: "192.168.10.0/24", ProxyName: "node-a",
		ListenerName: "s5m-smartdns-16000", ListenerAddress: "127.0.0.1", ListenerPort: 16000,
	}
	second := SmartDNSClientRuntimeMapping{
		ClientCIDR: "192.168.10.1/24", ProxyName: "node-b",
		ListenerName: "s5m-smartdns-16000", ListenerAddress: "127.0.0.1", ListenerPort: 16000,
	}
	if _, err := buildSmartDNSPerClientConfig([]SmartDNSClientRuntimeMapping{first, second}); err == nil {
		t.Fatal("canonical duplicate CIDR accepted")
	}
	second.ClientCIDR = "192.168.20.0/24"
	if _, err := buildSmartDNSPerClientConfig([]SmartDNSClientRuntimeMapping{first, second}); err == nil {
		t.Fatal("duplicate listener port accepted")
	}
}
