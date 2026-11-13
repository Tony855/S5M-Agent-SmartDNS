package main

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestCollectSmartDNSStatusFailsClosedWithoutHostAttestation(t *testing.T) {
	status := map[string]any{}
	collectSmartDNSStatusWithDependencies(status, smartDNSStatusDependencies{
		binaryInfo: func() (os.FileInfo, error) { return nil, errors.New("not installed") },
	})

	if status["dns_ingress_contract_version"] != 0 {
		t.Fatalf("contract version = %#v, want unsupported version 0", status["dns_ingress_contract_version"])
	}
	if status["dns_ingress_ready"] != false {
		t.Fatalf("ingress must remain fail-closed: %#v", status["dns_ingress_ready"])
	}
	if status["dns_ingress_reason"] != "host_ingress_attestation_reader_unavailable" {
		t.Fatalf("unexpected ingress reason: %#v", status["dns_ingress_reason"])
	}
	for _, key := range []string{
		"dns_ingress_source_ip_preserved",
		"dns_ingress_firewall_ready",
		"dns_ingress_firewall_persistent",
		"dns_ingress_udp_ready",
		"dns_ingress_tcp_ready",
		"dns_ingress_smartdns_listener_ready",
		"dns_ingress_ipv4_ready",
		"dns_ingress_ipv6_ready",
		"dns_ingress_smartdns_ipv4_bound",
		"dns_ingress_smartdns_ipv6_bound",
	} {
		if status[key] != false {
			t.Errorf("%s = %#v, want false", key, status[key])
		}
	}
	if got, ok := status["dns_ingress_client_cidrs"].([]string); !ok || len(got) != 0 {
		t.Fatalf("client CIDRs = %#v, want an empty []string", status["dns_ingress_client_cidrs"])
	}
	for _, key := range []string{
		"dns_ingress_interface",
		"dns_ingress_ipv4_address",
		"dns_ingress_ipv6_address",
		"dns_ingress_smartdns_ipv4_bind_address",
		"dns_ingress_smartdns_ipv6_bind_address",
	} {
		if status[key] != "" {
			t.Errorf("%s = %#v, want empty", key, status[key])
		}
	}
}


func TestCollectSmartDNSStatusCombinesHostAttestationAndExactListenerObservation(t *testing.T) {
	status := map[string]any{}
	now := time.Now().Unix()
	attestation := smartDNSHostIngressAttestation{
		Version: 1, UpdatedAt: now, Interface: "eno1", IPv4Address: "172.31.0.10",
		ClientCIDRs: []string{"192.168.50.0/24"}, SourceIPPreserved: true,
		FirewallReady: true, FirewallPersistent: true, UDPReady: true, TCPReady: true,
	}
	collectSmartDNSStatusWithDependencies(status, smartDNSStatusDependencies{
		binaryInfo: func() (os.FileInfo, error) { return nil, errors.New("not installed") },
		ingressAttestation: func() (smartDNSHostIngressAttestation, error) { return attestation, nil },
		ingressObservation: func() (smartDNSIngressObservation, error) {
			return smartDNSIngressObservation{Interfaces: []string{"eth1"}, IPv4: []string{"172.31.0.10"}, AddressInterfaces: map[string]string{"172.31.0.10": "eth1"}}, nil
		},
		ingressSocketBound: func(address string) (bool, error) { return address == "172.31.0.10", nil },
	})
	if status["dns_ingress_contract_version"] != 1 || status["dns_ingress_ready"] != true {
		t.Fatalf("valid host attestation and listener observation should be ready: %#v", status)
	}
	if status["dns_ingress_interface"] != "eno1" || status["dns_ingress_ipv4_address"] != "172.31.0.10" {
		t.Fatalf("host ingress identity not reported: %#v", status)
	}
	if status["dns_ingress_smartdns_ipv4_bound"] != true || status["dns_ingress_smartdns_listener_ready"] != true {
		t.Fatalf("exact SmartDNS listener bind not reported: %#v", status)
	}
}

func TestCollectSmartDNSStatusUsesPerClientHealthWithoutDefaultResolverProbe(t *testing.T) {
	status := map[string]any{}
	config, _ := validPerClientIngressFixture()
	configText := string(config)
	attestation := smartDNSHostIngressAttestation{
		Version: 1, UpdatedAt: time.Now().Unix(), Interface: "eno1", IPv4Address: "172.31.0.10",
		ClientCIDRs: []string{"192.168.50.10/32"}, SourceIPPreserved: true,
		FirewallReady: true, FirewallPersistent: true, UDPReady: true, TCPReady: true,
	}
	info, err := os.Stat(os.Args[0])
	if err != nil { t.Fatal(err) }
	contract := smartDNSPerClientIngressContract{Version: 1, Ready: true, IPv4Address: "172.31.0.10", ClientCIDRs: []string{"192.168.50.10/32"}}
	if !smartDNSFeatureSupported() { t.Fatal("SmartDNS feature should be present in this test build") }
	if !hasPerClientSmartDNSDirectives([]byte(configText)) { t.Fatalf("per-client directives not detected: %s", configText) }
	if err := validateSmartDNSConfigWithIngress([]byte(configText), contract); err != nil { t.Fatalf("per-client test fixture invalid: %v", err) }
	sharedProbeCalled, perClientProbeCalled := false, false
	collectSmartDNSStatusWithDependencies(status, smartDNSStatusDependencies{
		enabled: func() bool { return true },
		binaryInfo: func() (os.FileInfo, error) { return info, nil },
		readConfig: func(string) ([]byte, error) { return []byte(configText), nil },
		version: func() ([]byte, error) { return []byte("SmartDNS test"), nil },
		process: func() ([]byte, error) { return []byte("1234"), nil },
		probe: func() bool { sharedProbeCalled = true; return false },
		restart: func() error { return errors.New("unexpected restart") },
		waitHealthy: func(time.Duration) bool { return false },
		ingressAttestation: func() (smartDNSHostIngressAttestation, error) { return attestation, nil },
		ingressObservation: func() (smartDNSIngressObservation, error) {
			return smartDNSIngressObservation{
				Interfaces: []string{"eth1"}, IPv4: []string{"172.31.0.10"},
				AddressInterfaces: map[string]string{"172.31.0.10": "eth1"},
			}, nil
		},
		ingressSocketBound: func(string) (bool, error) { return true, nil },
		perClientProbe: func([]byte, smartDNSHostIngressAttestation) bool { perClientProbeCalled = true; return true },
	})
	if !perClientProbeCalled || sharedProbeCalled {
		t.Fatalf("per-client health probe selection incorrect: perClient=%v shared=%v", perClientProbeCalled, sharedProbeCalled)
	}
	if status["smartdns_dns_healthy"] != true || status["dns_ingress_ready"] != true {
		t.Fatalf("per-client config should report its dedicated health and ingress readiness: %#v", status)
	}
}
