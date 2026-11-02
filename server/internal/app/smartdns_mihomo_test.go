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

func TestApplySmartDNSSharedFallbackRejectsMissingRuleAndNameCollision(t *testing.T) {
	plan := SmartDNSRoutingPlan{Mode: SmartDNSProxyModeShared, Strategy: SmartDNSDefaultStrategy, ProxyNames: []string{"node-a"}}
	for _, input := range []string{
		"rules:\n  - MATCH,DIRECT\n",
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
