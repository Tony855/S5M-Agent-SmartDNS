package main

import (
	"strings"
	"testing"
)

func validPerClientIngressFixture() ([]byte, smartDNSPerClientIngressContract) {
	config := strings.Join([]string{
		"bind 127.0.0.1:6053",
		"bind-tcp 127.0.0.1:6053",
		"bind 172.31.0.10:6055",
		"bind-tcp 172.31.0.10:6055",
		"proxy-server socks5://127.0.0.1:16000 -name s5m-smartdns-16000",
		"server-tls 1.1.1.1:853 -host-name cloudflare-dns.com -tls-host-verify cloudflare-dns.com -group s5m-smartdns-group-16000 -proxy s5m-smartdns-16000 -exclude-default-group",
		"group-begin s5m-smartdns-group-16000",
		"group-match -client-ip 192.168.50.10/32",
		"group-end",
		"cache-size 0",
		"",
	}, "\n")
	contract := smartDNSPerClientIngressContract{
		Version: smartDNSPerClientIngressContractVersion,
		Ready: true,
		IPv4Address: "172.31.0.10",
		ClientCIDRs: []string{"192.168.50.10/32"},
	}
	return []byte(config), contract
}

func TestValidateSmartDNSConfigWithIngressAcceptsExactAttestedPlan(t *testing.T) {
	config, contract := validPerClientIngressFixture()
	if err := validateSmartDNSConfigWithIngress(config, contract); err != nil {
		t.Fatalf("valid contract-bound config rejected: %v", err)
	}
}

func TestValidateSmartDNSConfigWithIngressRequiresReadyVersionedContract(t *testing.T) {
	config, contract := validPerClientIngressFixture()
	contract.Ready = false
	if err := validateSmartDNSConfigWithIngress(config, contract); err == nil {
		t.Fatal("unready ingress contract accepted")
	}
	contract.Ready = true
	contract.Version++
	if err := validateSmartDNSConfigWithIngress(config, contract); err == nil {
		t.Fatal("unsupported ingress contract version accepted")
	}
}

func TestValidateSmartDNSConfigWithIngressRejectsPublicOrUnattestedBinds(t *testing.T) {
	config, contract := validPerClientIngressFixture()
	for _, bind := range []string{"bind 0.0.0.0:6055", "bind [::]:6055", "bind 172.31.0.11:6055"} {
		t.Run(strings.ReplaceAll(bind, ":", "_"), func(t *testing.T) {
			changed := strings.Replace(string(config), "bind 172.31.0.10:6055", bind, 1)
			if err := validateSmartDNSConfigWithIngress([]byte(changed), contract); err == nil {
				t.Fatalf("unsafe bind accepted: %s", bind)
			}
		})
	}
}

func TestValidateSmartDNSConfigWithIngressRejectsCIDRAndProxyMismatches(t *testing.T) {
	config, contract := validPerClientIngressFixture()
	tests := []struct {
		name string
		config string
		contract smartDNSPerClientIngressContract
	}{
		{name: "unmapped CIDR", config: strings.Replace(string(config), "192.168.50.10/32", "192.168.50.11/32", 1), contract: contract},
		{name: "extra firewall CIDR", config: string(config), contract: smartDNSPerClientIngressContract{Version: 1, Ready: true, IPv4Address: "172.31.0.10", ClientCIDRs: []string{"192.168.50.10/32", "192.168.50.11/32"}}},
		{name: "wrong proxy endpoint", config: strings.Replace(string(config), "socks5://127.0.0.1:16000", "socks5://0.0.0.0:16000", 1), contract: contract},
		{name: "wrong proxy mapping", config: strings.Replace(string(config), "-proxy s5m-smartdns-16000", "-proxy s5m-smartdns-16001", 1), contract: contract},
		{name: "missing default-group exclusion", config: strings.Replace(string(config), " -exclude-default-group", "", 1), contract: contract},
		{name: "unmapped upstream", config: strings.Replace(string(config), "-group s5m-smartdns-group-16000", "-group default", 1), contract: contract},
		{name: "missing TCP ingress", config: strings.Replace(string(config), "bind-tcp 172.31.0.10:6055\n", "", 1), contract: contract},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateSmartDNSConfigWithIngress([]byte(tt.config), tt.contract); err == nil {
				t.Fatal("invalid per-client configuration accepted")
			}
		})
	}
}

func TestValidateSmartDNSConfigWithIngressRequiresExactNonOverlappingCIDRs(t *testing.T) {
	config, contract := validPerClientIngressFixture()
	contract.ClientCIDRs = []string{"192.168.50.0/24"}
	if err := validateSmartDNSConfigWithIngress(config, contract); err == nil {
		t.Fatal("CIDR set that does not exactly match group mapping accepted")
	}
	contract.ClientCIDRs = []string{"192.168.50.10/32", "192.168.50.0/24"}
	if err := validateSmartDNSConfigWithIngress(config, contract); err == nil {
		t.Fatal("overlapping CIDRs in readiness contract accepted")
	}
}

func TestValidateSmartDNSConfigWithIngressRejectsDuplicateListenersAndReservedCIDRs(t *testing.T) {
	config, contract := validPerClientIngressFixture()
	duplicate := strings.Replace(string(config), "bind 172.31.0.10:6055\n", "bind 172.31.0.10:6055\nbind 172.31.0.10:6055\n", 1)
	if err := validateSmartDNSConfigWithIngress([]byte(duplicate), contract); err == nil {
		t.Fatal("duplicate UDP ingress listener accepted")
	}
	for _, cidr := range []string{"0.0.0.0/0", "::/0", "::ffff:192.0.2.0/120"} {
		contract.ClientCIDRs = []string{cidr}
		contract.IPv4Address = "172.31.0.10"
		contract.IPv6Address = ""
		if err := validateSmartDNSConfigWithIngress(config, contract); err == nil {
			t.Errorf("reserved/default/mapped CIDR accepted: %s", cidr)
		}
	}
}
