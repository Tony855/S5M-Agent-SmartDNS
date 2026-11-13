package main

import (
	"errors"
	"os"
	"testing"\n\t"time"
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
		Version: 1, UpdatedAt: now, Interface: "eth1", IPv4Address: "172.31.0.10",
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
	if status["dns_ingress_interface"] != "eth1" || status["dns_ingress_ipv4_address"] != "172.31.0.10" {
		t.Fatalf("host ingress identity not reported: %#v", status)
	}
	if status["dns_ingress_smartdns_ipv4_bound"] != true || status["dns_ingress_smartdns_listener_ready"] != true {
		t.Fatalf("exact SmartDNS listener bind not reported: %#v", status)
	}
}
