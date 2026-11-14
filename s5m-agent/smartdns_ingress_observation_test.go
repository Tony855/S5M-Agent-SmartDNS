package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestDecodeProcSocketAddress(t *testing.T) {
	cases := []struct {
		name string
		raw string
		ipv6 bool
		want string
	}{
		{name: "ipv4", raw: "0A0200C0", want: "192.0.2.10"},
		{name: "ipv6", raw: "b80d0120000000000000000001000000", ipv6: true, want: "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeProcSocketAddress(tc.raw, tc.ipv6)
			if err != nil { t.Fatal(err) }
			if got.String() != tc.want { t.Fatalf("address = %s, want %s", got, tc.want) }
		})
	}
}

func TestProcSocketTableObservesOnlyIngressPortAndCorrectTCPState(t *testing.T) {
	addresses := map[string]bool{"192.0.2.10": true}
	udp := []byte("sl local_address rem_address st tx_queue\n 0: 0A0200C0:17A7 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 12345\n")
	if !procSocketTableHasListener(udp, false, 6055, addresses, false) {
		t.Fatal("UDP socket bound to an observed interface address should be detected")
	}
	if procSocketTableHasListener(udp, false, 6053, addresses, false) {
		t.Fatal("shared loopback port must not be mistaken for the dedicated ingress port")
	}

	tcpListen := []byte("sl local_address rem_address st tx_queue\n 0: 0A0200C0:17A7 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12346\n")
	if !procSocketTableHasListener(tcpListen, false, 6055, addresses, true) {
		t.Fatal("TCP LISTEN socket bound to an observed interface address should be detected")
	}
	tcpEstablished := []byte("sl local_address rem_address st tx_queue\n 0: 0A0200C0:17A7 00000000:0000 01 00000000:00000000 00:00000000 00000000 1000 0 12347\n")
	if procSocketTableHasListener(tcpEstablished, false, 6055, addresses, true) {
		t.Fatal("an established TCP socket must not be reported as a listener")
	}
}

func TestProcSocketTableAcceptsWildcardBindButNotUnrelatedAddress(t *testing.T) {
	wildcard := []byte("sl local_address rem_address st tx_queue\n 0: 00000000:17A7 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 12345\n")
	if !procSocketTableHasListener(wildcard, false, 6055, map[string]bool{"192.0.2.10": true}, false) {
		t.Fatal("wildcard UDP bind should be visible on the interface")
	}
	other := []byte("sl local_address rem_address st tx_queue\n 0: 0B0200C0:17A7 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 12345\n")
	if procSocketTableHasListener(other, false, 6055, map[string]bool{"192.0.2.10": true}, false) {
		t.Fatal("socket bound to an address not assigned to the Agent must not be attributed to ingress")
	}
}

func TestCollectSmartDNSIngressObservationFailsWhenNoNonLoopbackInterfaceExists(t *testing.T) {
	deps := smartDNSIngressObservationDependencies{
		interfaces: func() ([]net.Interface, error) { return []net.Interface{{Name: "lo", Flags: net.FlagUp | net.FlagLoopback}}, nil },
		readFile: func(string) ([]byte, error) { return nil, nil },
	}
	if _, err := collectSmartDNSIngressObservation(deps); err == nil {
		t.Fatal("observation without a non-loopback interface must fail")
	}
}


func TestProcSocketTableExactListenerRejectsWildcard(t *testing.T) {
	wildcard := []byte("sl local_address rem_address st tx_queue\n 0: 00000000:17A7 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 12345\n")
	if procSocketTableHasExactListener(wildcard, false, 6055, "192.0.2.10", false) {
		t.Fatal("wildcard UDP bind must not satisfy an exact ingress address contract")
	}
	exact := []byte("sl local_address rem_address st tx_queue\n 0: 0A0200C0:17A7 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 12345\n")
	if !procSocketTableHasExactListener(exact, false, 6055, "192.0.2.10", false) {
		t.Fatal("exact UDP ingress bind should satisfy the address contract")
	}
}

func TestProcSocketTableExactListenerRejectsNonListeningUDPState(t *testing.T) {
	connectedUDP := []byte("sl local_address rem_address st tx_queue\n 0: 0A0200C0:17A7 0100007F:0035 01 00000000:00000000 00:00000000 00000000 1000 0 12345\n")
	if procSocketTableHasExactListener(connectedUDP, false, 6055, "192.0.2.10", false) {
		t.Fatal("connected UDP socket must not satisfy the exact UDP listener readiness contract")
	}
	listeningUDP := []byte("sl local_address rem_address st tx_queue\n 0: 0A0200C0:17A7 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 12346\n")
	if !procSocketTableHasExactListener(listeningUDP, false, 6055, "192.0.2.10", false) {
		t.Fatal("UDP socket in listening state on the exact address should satisfy readiness")
	}
}


func TestProcSocketTableExactListenerInodesAndSmartDNSProcessOwnership(t *testing.T) {
	udp := []byte("sl local_address rem_address st tx_queue\n 0: 0A0200C0:17A7 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 12345\n")
	tcp := []byte("sl local_address rem_address st tx_queue\n 0: 0A0200C0:17A7 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12346\n")
	udpInodes := procSocketTableExactListenerInodes(udp, false, 6055, "192.0.2.10", false)
	tcpInodes := procSocketTableExactListenerInodes(tcp, false, 6055, "192.0.2.10", true)
	if !udpInodes["12345"] || !tcpInodes["12346"] {
		t.Fatalf("exact ingress socket inodes not extracted: UDP=%v TCP=%v", udpInodes, tcpInodes)
	}

	procRoot := t.TempDir()
	fdDir := filepath.Join(procRoot, "1234", "fd")
	if err := os.MkdirAll(fdDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[12345]", filepath.Join(fdDir, "3")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[12346]", filepath.Join(fdDir, "4")); err != nil {
		t.Fatal(err)
	}
	owned, err := procProcessOwnsSocketInodes(procRoot, 1234, udpInodes, tcpInodes)
	if err != nil || !owned {
		t.Fatalf("SmartDNS process owning both exact sockets should be accepted: owned=%v err=%v", owned, err)
	}

	if err := os.Remove(filepath.Join(fdDir, "4")); err != nil {
		t.Fatal(err)
	}
	owned, err = procProcessOwnsSocketInodes(procRoot, 1234, udpInodes, tcpInodes)
	if err != nil || owned {
		t.Fatalf("process owning only UDP must not satisfy ingress readiness: owned=%v err=%v", owned, err)
	}

	otherFDDir := filepath.Join(procRoot, "5678", "fd")
	if err := os.MkdirAll(otherFDDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[12346]", filepath.Join(otherFDDir, "4")); err != nil {
		t.Fatal(err)
	}
	owned, err = procProcessOwnsSocketInodes(procRoot, 5678, udpInodes, tcpInodes)
	if err != nil || owned {
		t.Fatalf("a different process owning only TCP must not satisfy SmartDNS readiness: owned=%v err=%v", owned, err)
	}
}
