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
	for _, want := range []string{"keep-this-secret", "node-one", "192.0.2.10", "v2net.cc,DIRECT", "MATCH,DIRECT", "+.internal.example", "192.0.2.53", "223.5.5.5"} {
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

func TestMigrateNoSmartDNSConfigRejectsMalformedConfigWithoutMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := []byte("dns: [broken\n")
	if err := os.WriteFile(path, original, 0600); err != nil { t.Fatal(err) }
	if err := migrateNoSmartDNSConfig(path); err == nil { t.Fatal("expected malformed YAML error") }
	got, err := os.ReadFile(path); if err != nil { t.Fatal(err) }
	if string(got) != string(original) { t.Fatal("malformed config was modified") }
}
