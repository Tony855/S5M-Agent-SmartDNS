package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func validHostIngressAttestationFixture() smartDNSHostIngressAttestation {
	return smartDNSHostIngressAttestation{
		Version: 1, UpdatedAt: time.Now().Unix(), Interface: "eth1",
		IPv4Address: "172.31.0.10", ClientCIDRs: []string{"192.168.50.0/24"},
		SourceIPPreserved: true, FirewallReady: true, FirewallPersistent: true,
		UDPReady: true, TCPReady: true,
	}
}

func writeHostIngressAttestationFixture(t *testing.T, path string, attestation smartDNSHostIngressAttestation, mode os.FileMode) {
	t.Helper()
	data, err := json.Marshal(attestation)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, data, mode); err != nil { t.Fatal(err) }
}

func TestReadSmartDNSHostIngressAttestationAcceptsFreshRootOwnedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ingress.json")
	want := validHostIngressAttestationFixture()
	writeHostIngressAttestationFixture(t, path, want, 0600)
	got, err := readSmartDNSHostIngressAttestationFromPath(path)
	if err != nil { t.Fatalf("read valid attestation: %v", err) }
	if got.Version != want.Version || got.Interface != want.Interface || got.IPv4Address != want.IPv4Address || len(got.ClientCIDRs) != 1 {
		t.Fatalf("attestation mismatch: %#v", got)
	}
}

func TestReadSmartDNSHostIngressAttestationRejectsSymlinkAndWritableFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	writeHostIngressAttestationFixture(t, target, validHostIngressAttestationFixture(), 0600)
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil { t.Fatal(err) }
	if _, err := readSmartDNSHostIngressAttestationFromPath(link); err == nil {
		t.Fatal("symlinked host attestation accepted")
	}
	writable := filepath.Join(dir, "writable.json")
	writeHostIngressAttestationFixture(t, writable, validHostIngressAttestationFixture(), 0666)
	if _, err := readSmartDNSHostIngressAttestationFromPath(writable); err == nil {
		t.Fatal("group/world writable host attestation accepted")
	}
}

func TestValidateSmartDNSHostIngressAttestationRejectsStaleAndOverlappingCIDRs(t *testing.T) {
	stale := validHostIngressAttestationFixture()
	stale.UpdatedAt = time.Now().Add(-2 * time.Minute).Unix()
	if err := validateSmartDNSHostIngressAttestation(stale); err == nil {
		t.Fatal("stale host attestation accepted")
	}
	overlap := validHostIngressAttestationFixture()
	overlap.ClientCIDRs = []string{"192.168.50.0/24", "192.168.50.10/32"}
	if err := validateSmartDNSHostIngressAttestation(overlap); err == nil {
		t.Fatal("overlapping client CIDRs accepted")
	}
}
