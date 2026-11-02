package app

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestApplySmartDNSSharedFallbackCreatesDynamicFallbackGroup(t *testing.T) {
	input := `mode: rule
proxies:
  - name: node-a
    type: socks5
    server: 192.0.2.1
    port: 1080
  - name: node-b
    type: socks5
    server: 192.0.2.2
    port: 1080
rules:
  - DOMAIN-SUFFIX,v2net.cc,DIRECT
  - PROCESS-NAME,smartdns,node-a
  - SRC-IP-CIDR,192.168.18.23/32,node-b
  - MATCH,REJECT
`
	plan := SmartDNSRoutingPlan{
		Mode: SmartDNSProxyModeShared, Strategy: SmartDNSDefaultStrategy,
		GroupName: SmartDNSGroupName, ProxyNames: []string{"node-a", "node-b"},
	}
	got, err := applySmartDNSSharedFallback(input, plan)
	if err != nil { t.Fatal(err) }
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil { t.Fatalf("invalid output YAML: %v", err) }
	groups, ok := doc["proxy-groups"].([]any)
	if !ok || len(groups) != 1 { t.Fatalf("unexpected proxy-groups: %#v", doc["proxy-groups"]) }
	group := groups[0].(map[string]any)
	if group["type"] != "fallback" || group["url"] != "https://www.gstatic.com/generate_204" {
		t.Fatalf("unexpected fallback group: %#v", group)
	}
	names := group["proxies"].([]any)
	if len(names) != 2 || names[0] != "node-a" || names[1] != "node-b" { t.Fatalf("proxy order lost: %#v", names) }
	rules := doc["rules"].([]any)
	if rules[1] != "PROCESS-NAME,smartdns,SMARTDNS-PROXY" { t.Fatalf("SmartDNS rule not redirected: %#v", rules[1]) }
	if rules[2] != "SRC-IP-CIDR,192.168.18.23/32,node-b" { t.Fatalf("ordinary client route changed: %#v", rules[2]) }
}

func TestApplySmartDNSSharedFallbackRejectsReservedNameCollision(t *testing.T) {
	plan := SmartDNSRoutingPlan{Mode: SmartDNSProxyModeShared, Strategy: SmartDNSDefaultStrategy, ProxyNames: []string{"node-a"}}
	for _, input := range []string{
		"proxy-groups:\n  - name: SMARTDNS-PROXY\n    type: select\n    proxies: [node-a]\nrules:\n  - PROCESS-NAME,smartdns,node-a\n",
	} {
		if _, err := applySmartDNSSharedFallback(input, plan); err == nil { t.Fatalf("expected error for %s", input) }
	}
}

func TestApplySmartDNSSharedFallbackLeavesLegacyDocumentUntouched(t *testing.T) {
	input := "rules:\n  - MATCH,DIRECT\n"
	got, err := applySmartDNSSharedFallback(input, SmartDNSRoutingPlan{Mode: "legacy"})
	if err != nil { t.Fatal(err) }
	if got != input { t.Fatalf("legacy document changed: %q", got) }
	if strings.TrimSpace(got) == "" { t.Fatal("empty legacy document") }
}


func TestApplySmartDNSSharedFallbackInsertsBeforeCustomDomainAndIPRules(t *testing.T) {
	input := `rules:
  - DOMAIN-SUFFIX,v2net.cc,DIRECT
  - DOMAIN,controller.example.com,DIRECT
  - DOMAIN,private.example.com,DIRECT
  - IP-CIDR,192.0.2.0/24,DIRECT,no-resolve
  - MATCH,DIRECT
proxies:
  - name: node-a
    type: socks5
    server: 192.0.2.1
    port: 1080
`
	plan := SmartDNSRoutingPlan{Mode: SmartDNSProxyModeShared, Strategy: SmartDNSDefaultStrategy, ProxyNames: []string{"node-a"}}
	got, err := applySmartDNSSharedFallback(input, plan)
	if err != nil { t.Fatal(err) }
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil { t.Fatal(err) }
	rules := doc["rules"].([]any)
	want := []string{
		"DOMAIN-SUFFIX,v2net.cc,DIRECT",
		"DOMAIN,controller.example.com,DIRECT",
		"PROCESS-NAME,smartdns,SMARTDNS-PROXY",
		"DOMAIN,private.example.com,DIRECT",
		"IP-CIDR,192.0.2.0/24,DIRECT,no-resolve",
		"MATCH,DIRECT",
	}
	if len(rules) != len(want) { t.Fatalf("rules length = %d, want %d: %#v", len(rules), len(want), rules) }
	for i := range want {
		if rules[i] != want[i] { t.Errorf("rules[%d] = %#v, want %#v", i, rules[i], want[i]) }
	}
}

func TestApplySmartDNSSharedFallbackDoesNotSkipArbitraryDomainRule(t *testing.T) {
	input := `rules:
  - DOMAIN,custom.example.com,DIRECT
  - MATCH,DIRECT
proxies:
  - name: node-a
    type: socks5
    server: 192.0.2.1
    port: 1080
`
	plan := SmartDNSRoutingPlan{Mode: SmartDNSProxyModeShared, Strategy: SmartDNSDefaultStrategy, ProxyNames: []string{"node-a"}}
	got, err := applySmartDNSSharedFallback(input, plan)
	if err != nil { t.Fatal(err) }
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil { t.Fatal(err) }
	rules := doc["rules"].([]any)
	if rules[0] != "PROCESS-NAME,smartdns,SMARTDNS-PROXY" || rules[1] != "DOMAIN,custom.example.com,DIRECT" {
		t.Fatalf("custom domain rule incorrectly precedes SmartDNS routing: %#v", rules)
	}
}


func TestApplySmartDNSPerClientListenersPinsLoopbackSOCKSToExactOutbound(t *testing.T) {
	input := `proxies:
  - name: Mihomo-IPv6-24580
    type: socks5
    server: 192.0.2.10
    port: 1080
  - name: Mihomo-IPv6-24581
    type: socks5
    server: 192.0.2.11
    port: 1080
listeners: []
rules:
  - DOMAIN-SUFFIX,v2net.cc,DIRECT
  - MATCH,DIRECT
`
	plan := SmartDNSRoutingPlan{
		Mode: SmartDNSProxyModePerClient,
		ProxyNames: []string{"Mihomo-IPv6-24580", "Mihomo-IPv6-24581"},
		Clients: []SmartDNSClientRoute{
			{ClientCIDR: "192.168.18.23/32", ProxyName: "Mihomo-IPv6-24580", ListenPort: 16080},
			{ClientCIDR: "192.168.18.33/32", ProxyName: "Mihomo-IPv6-24581", ListenPort: 16081},
		},
	}
	got, err := applySmartDNSPerClientListeners(input, plan)
	if err != nil { t.Fatal(err) }
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil { t.Fatal(err) }
	listeners := doc["listeners"].([]any)
	if len(listeners) != 2 { t.Fatalf("got %d listeners, want 2", len(listeners)) }
	for i, want := range []struct{ port int; proxy string }{
		{16080, "Mihomo-IPv6-24580"}, {16081, "Mihomo-IPv6-24581"},
	} {
		item := listeners[i].(map[string]any)
		if item["type"] != "socks" || item["listen"] != "127.0.0.1" ||
			item["udp"] != true || item["proxy"] != want.proxy ||
			item["port"] != want.port {
			t.Fatalf("listener %d is not isolated as expected: %#v", i, item)
		}
	}
	rules := doc["rules"].([]any)
	if rules[0] != "DOMAIN-SUFFIX,v2net.cc,DIRECT" || rules[1] != "MATCH,DIRECT" {
		t.Fatalf("existing routing rules were modified: %#v", rules)
	}
}

func TestApplySmartDNSPerClientListenersRejectsUnknownProxyAndPortCollision(t *testing.T) {
	input := `proxies:
  - name: node-a
    type: socks5
    server: 192.0.2.1
    port: 1080
listeners:
  - name: existing
    type: socks
    listen: 127.0.0.1
    port: 16080
    proxy: node-a
rules: [MATCH,DIRECT]
`
	cases := []struct{name string; plan SmartDNSRoutingPlan}{
		{"unknown outbound", SmartDNSRoutingPlan{Mode:SmartDNSProxyModePerClient, ProxyNames:[]string{"missing"}, Clients:[]SmartDNSClientRoute{{ClientCIDR:"192.168.1.2/32",ProxyName:"missing",ListenPort:16081}}}},
		{"port collision", SmartDNSRoutingPlan{Mode:SmartDNSProxyModePerClient, ProxyNames:[]string{"node-a"}, Clients:[]SmartDNSClientRoute{{ClientCIDR:"192.168.1.2/32",ProxyName:"node-a",ListenPort:16080}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name,func(t *testing.T){
			if _,err:=applySmartDNSPerClientListeners(input,tc.plan);err==nil { t.Fatal("expected validation failure") }
		})
	}
}

func TestApplySmartDNSPerClientListenersLeavesLegacyUntouched(t *testing.T) {
	input := "rules:\n  - MATCH,DIRECT\n"
	got, err := applySmartDNSPerClientListeners(input, SmartDNSRoutingPlan{Mode:"legacy"})
	if err != nil { t.Fatal(err) }
	if got != input { t.Fatalf("legacy document changed: %q", got) }
}
