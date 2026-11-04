package main

import (
	"os"
	"strings"
	"testing"
)

func TestSmartDNSImageDefaultConfigFailsClosed(t *testing.T) {
	data, err := os.ReadFile("smartdns/default-config-smartdns.yaml")
	if err != nil {
		t.Fatalf("read SmartDNS image default config: %v", err)
	}
	config := string(data)
	if !strings.Contains(config, "  - DOMAIN-SUFFIX,v2net.cc,DIRECT") {
		t.Fatal("controller domain direct rule is missing")
	}
	if !strings.Contains(config, "  - MATCH,REJECT") {
		t.Fatal("unmatched traffic must be rejected by the default rule")
	}
	if strings.Contains(config, "MATCH,DIRECT") {
		t.Fatal("default config must not send unmatched traffic direct")
	}
}

