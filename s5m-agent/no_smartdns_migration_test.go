package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMigrateNoSmartDNSConfigPreservesUserConfiguration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := []byte(`secret: keep-this-secret
external-controller: 127.0.0.1:8088
proxies:
  - name: node-one
    type: socks5
    server: 192.0.2.10
    port: 1080
dns:
  enable: true
  ipv6: true
  listen: 127.0.0.1:5353
  default-nameserver: [tls://223.5.5.5]
  nameserver:
    - 127.0.0.1:6053
  nameserver-policy:
    "geosite:cn": 127.0.0.1:6054
    "+.internal.example": 192.0.2.53
    "+.mixed.example": [127.0.0.1:6054, 192.0.2.54]
  fallback:
    - https://dns.cloudflare.com/dns-query
rules:
  - DOMAIN-SUFFIX,v2net.cc,DIRECT
  - MATCH,DIRECT
`)
	if err := os.WriteFile(path, original, 0600); err != nil { t.Fatal(err) }
	if err := migrateNoSmartDNSConfig(path); err != nil { t.Fatal(err) }
	got, err := os.ReadFile(path); if err != nil { t.Fatal(err) }
	text := string(got)
	for _, want := range []string{"keep-this-secret", "node-one", "192.0.2.10", "v2net.cc,DIRECT", "MATCH,DIRECT", "+.internal.example", "192.0.2.53", "192.0.2.54", "223.5.5.5"} {
		if !strings.Contains(text, want) { t.Fatalf("migration lost %q: %s", want, text) }
	}
	for _, stale := range []string{"127.0.0.1:6053", "127.0.0.1:6054"} {
		if strings.Contains(text, stale) { t.Fatalf("stale SmartDNS reference remains: %s", stale) }
	}
	backup, err := os.ReadFile(path+".pre-no-smartdns"); if err != nil { t.Fatal(err) }
	if string(backup) != string(original) { t.Fatal("one-time backup does not match original config") }
	var parsed map[string]any
	if err := yaml.Unmarshal(got, &parsed); err != nil { t.Fatalf("migrated YAML invalid: %v", err) }
	if parsed["secret"] != "keep-this-secret" { t.Fatal("API secret changed") }
	if err := migrateNoSmartDNSConfig(path); err != nil { t.Fatal(err) }
	backup2, err := os.ReadFile(path+".pre-no-smartdns"); if err != nil { t.Fatal(err) }
	if string(backup2) != string(original) { t.Fatal("second migration overwrote original backup") }
}

func TestMigrateNoSmartDNSConfigRemovesTransportQualifiedListeners(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := []byte(`dns:
  enable: true
  nameserver:
    - udp://127.0.0.1:6053
    - tcp://[::1]:6054
    - https://localhost:6053/dns-query
    - 9.9.9.9
`)
	if err := os.WriteFile(path, original, 0600); err != nil { t.Fatal(err) }
	if err := migrateNoSmartDNSConfig(path); err != nil { t.Fatal(err) }
	got, err := os.ReadFile(path); if err != nil { t.Fatal(err) }
	text := string(got)
	for _, stale := range []string{"6053", "6054", "localhost"} {
		if strings.Contains(text, stale) { t.Fatalf("transport-qualified stale resolver remains (%s): %s", stale, text) }
	}
	if !strings.Contains(text, "9.9.9.9") { t.Fatalf("migration removed valid resolver: %s", text) }
}

func TestMigrateNoSmartDNSConfigRejectsMalformedConfigWithoutMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := []byte("dns: [broken\n")
	if err := os.WriteFile(path, original, 0600); err != nil { t.Fatal(err) }
	if err := migrateNoSmartDNSConfig(path); err == nil { t.Fatal("expected malformed YAML error") }
	got, err := os.ReadFile(path); if err != nil { t.Fatal(err) }
	if string(got) != string(original) { t.Fatal("malformed config was modified") }
}

func TestNormalizeNoSmartDNSYAMLForControllerPush(t *testing.T) {
	previous := agentSupportsSmartDNS
	agentSupportsSmartDNS = "false"
	defer func() { agentSupportsSmartDNS = previous }()
	input := []byte(`dns:
  enable: true
  listen: 127.0.0.1:5353
  nameserver: [127.0.0.1:6053, 9.9.9.9]
  nameserver-policy:
    "geosite:cn": [127.0.0.1:6054, 223.5.5.5]
    "+.corp.example": 192.0.2.80
rules:
  - DOMAIN-SUFFIX,v2net.cc,DIRECT
  - MATCH,DIRECT
`)
	got, err := normalizeNoSmartDNSYAML(input)
	if err != nil { t.Fatal(err) }
	for _, stale := range []string{"127.0.0.1:6053", "127.0.0.1:6054"} {
		if strings.Contains(string(got), stale) { t.Fatalf("controller config still contains %s: %s", stale, got) }
	}
	for _, keep := range []string{"9.9.9.9", "223.5.5.5", "192.0.2.80", "v2net.cc,DIRECT", "MATCH,DIRECT"} {
		if !strings.Contains(string(got), keep) { t.Fatalf("controller config lost %s: %s", keep, got) }
	}
}

func TestNoSmartDNSBuildReportsControlUnsupported(t *testing.T) {
	previous := agentSupportsSmartDNS
	agentSupportsSmartDNS = "false"
	defer func() { agentSupportsSmartDNS = previous }()
	status := map[string]any{}
	collectSmartDNSStatus(status)
	if status["smartdns_available"] != false { t.Fatalf("SmartDNS should be unavailable: %#v", status) }
	if status["smartdns_control_supported"] != false { t.Fatalf("SmartDNS controls should be unsupported: %#v", status) }
	if status["smartdns_enabled"] != false { t.Fatalf("SmartDNS should report disabled: %#v", status) }
}


func TestNoSmartDNSImageDefaultConfigFailsClosedForTransparentProxy(t *testing.T) {
	data, err := os.ReadFile("default-config-no-smartdns.yaml")
	if err != nil { t.Fatalf("read no-SmartDNS default config: %v", err) }
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil { t.Fatalf("parse default config: %v", err) }
	rules, ok := root["rules"].([]any)
	if !ok || len(rules) == 0 { t.Fatalf("default rules missing: %#v", root["rules"]) }
	if root["allow-lan"] != false { t.Fatalf("default config must not expose unauthenticated LAN proxy, allow-lan=%#v", root["allow-lan"]) }
	if rules[len(rules)-1] != "MATCH,REJECT" {
		t.Fatalf("unmatched traffic must fail closed until a valid proxy policy is received, got %#v", rules)
	}
	for _, raw := range rules {
		if raw == "MATCH,DIRECT" { t.Fatal("default transparent-proxy policy must not leak unmatched traffic direct") }
	}
	tun, ok := root["tun"].(map[string]any)
	if !ok || tun["enable"] != true { t.Fatalf("TUN must remain enabled by default: %#v", root["tun"]) }
}
