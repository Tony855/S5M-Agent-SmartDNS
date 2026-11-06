package main

import (
	"os"
	"strings"
	"testing"
)

func TestSmartDNSImageDefaultConfigUsesDirectFallback(t *testing.T) {
	data, err := os.ReadFile("smartdns/default-config-smartdns.yaml")
	if err != nil {
		t.Fatalf("read SmartDNS image default config: %v", err)
	}
	config := string(data)
	if !strings.Contains(config, "  - DOMAIN-SUFFIX,v2net.cc,DIRECT") {
		t.Fatal("controller domain direct rule is missing")
	}
	if !strings.Contains(config, "  - MATCH,DIRECT") {
		t.Fatal("unmatched traffic must use the requested direct fallback")
	}
	if strings.Contains(config, "MATCH,REJECT") {
		t.Fatal("image default config must not retain a terminal REJECT rule")
	}
}

func TestCombinedSmartDNSDefaultConfigEnablesAndValidatesIPv6(t *testing.T) {
	data, err := os.ReadFile("smartdns/smartdns.conf")
	if err != nil {
		t.Fatalf("read combined SmartDNS config: %v", err)
	}
	if err := validateSmartDNSConfig(data); err != nil {
		t.Fatalf("combined SmartDNS default config rejected: %v", err)
	}
	for _, directive := range []string{
		"dualstack-ip-selection no",
		"dualstack-ip-selection-threshold 10",
		"dualstack-ip-allow-force-AAAA yes",
	} {
		if !strings.Contains(string(data), directive) {
			t.Errorf("combined SmartDNS config missing %q", directive)
		}
	}
}
