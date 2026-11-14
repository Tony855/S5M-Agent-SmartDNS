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
	if err := os.Chmod(path, mode); err != nil { t.Fatal(err) }
}

func TestReadSmartDNSHostIngressAttestationAcceptsFreshRootOwnedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ingress.json")
	want := validHostIngressAttestationFixture()
	writeHostIngressAttestationFixture(t, path, want, 0600)
	got, err := readSmartDNSHostIngressAttestationFromPathWithOwner(path, false)
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
	if _, err := readSmartDNSHostIngressAttestationFromPathWithOwner(link, false); err == nil {
		t.Fatal("symlinked host attestation accepted")
	}
	writable := filepath.Join(dir, "writable.json")
	writeHostIngressAttestationFixture(t, writable, validHostIngressAttestationFixture(), 0666)
	if _, err := readSmartDNSHostIngressAttestationFromPathWithOwner(writable, false); err == nil {
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


func TestReadSmartDNSHostIngressAttestationEnforcesRootOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ingress.json")
	writeHostIngressAttestationFixture(t, path, validHostIngressAttestationFixture(), 0600)
	_, err := readSmartDNSHostIngressAttestationFromPath(path)
	if os.Geteuid() == 0 && err != nil { t.Fatalf("root-owned test file should be accepted: %v", err) }
	if os.Geteuid() != 0 && err == nil { t.Fatal("non-root-owned host attestation accepted") }
}

func TestValidateSmartDNSHostIngressAttestationRejectsNonCanonicalCIDR(t *testing.T) {
	att := validHostIngressAttestationFixture()
	att.ClientCIDRs = []string{"192.168.50.1/24"}
	if err := validateSmartDNSHostIngressAttestation(att); err == nil {
		t.Fatal("non-canonical client CIDR accepted")
	}
}

func TestValidateSmartDNSHostIngressAttestationRequiresMatchingAddressFamily(t *testing.T) {
	att := validHostIngressAttestationFixture()
	att.IPv4Address = ""
	att.IPv6Address = "2001:db8:31::10"
	if err := validateSmartDNSHostIngressAttestation(att); err == nil {
		t.Fatal("IPv4 client CIDR accepted without an IPv4 ingress address")
	}
}
