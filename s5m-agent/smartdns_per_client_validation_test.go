package main

import (
	"strings"
	"reflect"
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

func TestSmartDNSConfigHasDomesticListenerRequiresUDPAndTCP(t *testing.T) {
	tests := []struct {
		name string
		config string
		want bool
	}{
		{name: "both listeners", config: "bind 127.0.0.1:6054 -group china-dot\nbind-tcp 127.0.0.1:6054 -group china-dot\n", want: true},
		{name: "UDP only", config: "bind 127.0.0.1:6054 -group china-dot\n", want: false},
		{name: "TCP only", config: "bind-tcp 127.0.0.1:6054 -group china-dot\n", want: false},
		{name: "no domestic listener", config: "bind 127.0.0.1:6053\n", want: false},
		{name: "comment only", config: "# bind 127.0.0.1:6054 -group china-dot\n", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := smartDNSConfigHasDomesticListener([]byte(tt.config)); got != tt.want {
				t.Fatalf("smartDNSConfigHasDomesticListener() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProbeSmartDNSDNSWithConfigIncludesDomesticDataplane(t *testing.T) {
	base := []byte("bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\n")
	domestic := []byte("bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nbind 127.0.0.1:6054 -group china-dot\nbind-tcp 127.0.0.1:6054 -group china-dot\n")
	tests := []struct {
		name string
		config []byte
		want []string
	}{
		{name: "primary only", config: base, want: []string{"127.0.0.1:6053"}},
		{name: "primary and domestic", config: domestic, want: []string{"127.0.0.1:6053", "127.0.0.1:6054"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var udpCalls, tcpCalls []string
			ok := probeSmartDNSDNSWithConfigAndProbes(tt.config,
				func(address string) bool { udpCalls = append(udpCalls, address); return true },
				func(address string) bool { tcpCalls = append(tcpCalls, address); return true },
			)
			if !ok { t.Fatal("healthy configured listeners were reported unhealthy") }
			if !reflect.DeepEqual(udpCalls, tt.want) || !reflect.DeepEqual(tcpCalls, tt.want) {
				t.Fatalf("probe calls UDP=%v TCP=%v, want %v", udpCalls, tcpCalls, tt.want)
			}
		})
	}
}

func TestProbeSmartDNSDNSWithConfigFailsWhenDomesticDataplaneFails(t *testing.T) {
	config := []byte("bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nbind 127.0.0.1:6054 -group china-dot\nbind-tcp 127.0.0.1:6054 -group china-dot\n")
	if probeSmartDNSDNSWithConfigAndProbes(config,
		func(address string) bool { return address != "127.0.0.1:6054" },
		func(string) bool { return true },
	) {
		t.Fatal("domestic UDP failure was ignored")
	}
	if probeSmartDNSDNSWithConfigAndProbes(config,
		func(string) bool { return true },
		func(address string) bool { return address != "127.0.0.1:6054" },
	) {
		t.Fatal("domestic TCP failure was ignored")
	}
}
