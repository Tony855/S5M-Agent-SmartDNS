package main

import (
	"strings"
	"testing"
)

func TestValidateSmartDNSConfigRejectsUnimplementedPerClientDirectives(t *testing.T) {
	base := "bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nserver-tls 1.1.1.1:853 -host-name cloudflare-dns.com -tls-host-verify cloudflare-dns.com\n"
	tests := []struct {
		name string
		line string
	}{
		{name: "proxy-server", line: "proxy-server socks5://127.0.0.1:19081 -name client-a"},
		{name: "group-match", line: "group-match -client-ip 192.168.10.0/24 client-a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSmartDNSConfig([]byte(base + tt.line + "\n"))
			if err == nil {
				t.Fatalf("validator accepted unsupported per-client directive %q", tt.line)
			}
			if !strings.Contains(err.Error(), "不允许配置指令") {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestValidateSmartDNSConfigAcceptsExistingEncryptedSharedMode(t *testing.T) {
	config := "bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nserver-tls 1.1.1.1:853 -host-name cloudflare-dns.com -tls-host-verify cloudflare-dns.com\n"
	if err := validateSmartDNSConfig([]byte(config)); err != nil {
		t.Fatalf("existing encrypted shared-mode config rejected: %v", err)
	}
}

func TestValidateSmartDNSConfigRejectsProxyServerInjectionVariants(t *testing.T) {
	base := "bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nserver-tls 1.1.1.1:853 -host-name cloudflare-dns.com -tls-host-verify cloudflare-dns.com\n"
	for _, directive := range []string{
		"proxy-server http://127.0.0.1:19081",
		"proxy-server socks5://0.0.0.0:19081",
		"group-match -client-ip 0.0.0.0/0 default",
		"include /tmp/attacker.conf",
	} {
		t.Run(strings.ReplaceAll(directive, " ", "_"), func(t *testing.T) {
			if err := validateSmartDNSConfig([]byte(base + directive + "\n")); err == nil {
				t.Fatalf("validator accepted unsafe or unsupported directive %q", directive)
			}
		})
	}
}

func TestValidateSmartDNSConfigAcceptsIPv6LoopbackPerClientConfig(t *testing.T) {
	config := strings.Join([]string{
		"bind 127.0.0.1:6053",
		"bind-tcp 127.0.0.1:6053",
		"bind [::1]:6053",
		"bind-tcp [::1]:6053",
		"server-tls 1.1.1.1:853 -host-name cloudflare-dns.com -tls-host-verify cloudflare-dns.com -group s5m-smartdns-group-16000 -proxy s5m-smartdns-16000",
		"dualstack-ip-selection yes",
		"dualstack-ip-selection-threshold 10",
		"dualstack-ip-allow-force-AAAA yes",
		"",
	}, "\n")
	if err := validateSmartDNSConfig([]byte(config)); err != nil {
		t.Fatalf("valid IPv6 per-client SmartDNS config rejected: %v", err)
	}
}

func TestValidateSmartDNSConfigRejectsIncompleteOrExposedIPv6Listeners(t *testing.T) {
	base := "bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nserver-tls 1.1.1.1:853 -host-name cloudflare-dns.com -tls-host-verify cloudflare-dns.com\n"
	tests := []struct {
		name string
		config string
	}{
		{name: "missing IPv6 TCP listener", config: base + "bind [::1]:6053\n"},
		{name: "public IPv6 listener", config: base + "bind [::]:6053\nbind-tcp [::]:6053\n"},
		{name: "public IPv4 listener", config: base + "bind 0.0.0.0:6053\nbind-tcp 0.0.0.0:6053\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateSmartDNSConfig([]byte(tt.config)); err == nil {
				t.Fatalf("validator accepted unsafe/incomplete listener config")
			}
		})
	}
}

func TestValidateSmartDNSConfigRestrictsDualStackDirectives(t *testing.T) {
	base := "bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nserver-tls 1.1.1.1:853 -host-name cloudflare-dns.com -tls-host-verify cloudflare-dns.com\n"
	for _, line := range []string{
		"dualstack-ip-selection no",
		"dualstack-ip-selection-threshold 999",
		"dualstack-ip-allow-force-AAAA no",
	} {
		if err := validateSmartDNSConfig([]byte(base + line + "\n")); err == nil {
			t.Errorf("validator accepted unsupported dual-stack setting %q", line)
		}
	}
}
