package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const smartDNSHostIngressAttestationPath = "/run/s5m-agent-ingress/ingress.json"
const smartDNSHostIngressAttestationVersion = 1

var smartDNSHostIngressInterfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

// smartDNSHostIngressAttestation is written atomically by the restricted
// host-side ingress controller and mounted read-only into the Agent container.
// It contains only host provisioning facts; Agent socket inspection is still
// required before runtime readiness can become true.
type smartDNSHostIngressAttestation struct {
	Version int `json:"version"`
	UpdatedAt int64 `json:"updated_at"`
	Interface string `json:"interface"`
	IPv4Address string `json:"ipv4_address,omitempty"`
	IPv6Address string `json:"ipv6_address,omitempty"`
	ClientCIDRs []string `json:"client_cidrs"`
	SourceIPPreserved bool `json:"source_ip_preserved"`
	FirewallReady bool `json:"firewall_ready"`
	FirewallPersistent bool `json:"firewall_persistent"`
	UDPReady bool `json:"udp_ready"`
	TCPReady bool `json:"tcp_ready"`
}

func readSmartDNSHostIngressAttestation() (smartDNSHostIngressAttestation, error) {
	return readSmartDNSHostIngressAttestationFromPath(smartDNSHostIngressAttestationPath)
}

func readSmartDNSHostIngressAttestationFromPath(path string) (smartDNSHostIngressAttestation, error) {
	var attestation smartDNSHostIngressAttestation
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil { return attestation, fmt.Errorf("open host ingress attestation: %w", err) }
	file := os.NewFile(uintptr(fd), path)
	if file == nil { _ = syscall.Close(fd); return attestation, fmt.Errorf("invalid host ingress attestation file descriptor") }
	defer file.Close()
	info, err := file.Stat()
	if err != nil { return attestation, fmt.Errorf("stat host ingress attestation: %w", err) }
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 8<<10 {
		return attestation, fmt.Errorf("host ingress attestation must be a non-empty regular file no larger than 8 KiB")
	}
	if info.Mode().Perm()&0022 != 0 {
		return attestation, fmt.Errorf("host ingress attestation must not be group/world writable")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 {
		return attestation, fmt.Errorf("host ingress attestation must be owned by root")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 8<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&attestation); err != nil {
		return smartDNSHostIngressAttestation{}, fmt.Errorf("decode host ingress attestation: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return smartDNSHostIngressAttestation{}, fmt.Errorf("host ingress attestation contains trailing JSON")
	}
	if err := validateSmartDNSHostIngressAttestation(attestation); err != nil {
		return smartDNSHostIngressAttestation{}, err
	}
	return attestation, nil
}

func validateSmartDNSHostIngressAttestation(attestation smartDNSHostIngressAttestation) error {
	if attestation.Version != smartDNSHostIngressAttestationVersion {
		return fmt.Errorf("unsupported host ingress attestation version")
	}
	if attestation.UpdatedAt <= 0 || time.Since(time.Unix(attestation.UpdatedAt, 0)) > 90*time.Second || time.Since(time.Unix(attestation.UpdatedAt, 0)) < -30*time.Second {
		return fmt.Errorf("host ingress attestation is stale")
	}
	if !smartDNSHostIngressInterfacePattern.MatchString(strings.TrimSpace(attestation.Interface)) {
		return fmt.Errorf("host ingress attestation interface is invalid")
	}
	if strings.TrimSpace(attestation.IPv4Address) == "" && strings.TrimSpace(attestation.IPv6Address) == "" {
		return fmt.Errorf("host ingress attestation has no ingress address")
	}
	if strings.TrimSpace(attestation.IPv4Address) != "" {
		ip, err := netip.ParseAddr(strings.TrimSpace(attestation.IPv4Address))
		if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return fmt.Errorf("host ingress attestation IPv4 address is invalid")
		}
	}
	if strings.TrimSpace(attestation.IPv6Address) != "" {
		ip, err := netip.ParseAddr(strings.TrimSpace(attestation.IPv6Address))
		if err != nil || !ip.Is6() || ip.Is4In6() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return fmt.Errorf("host ingress attestation IPv6 address is invalid")
		}
	}
	if len(attestation.ClientCIDRs) == 0 || len(attestation.ClientCIDRs) > 128 {
		return fmt.Errorf("host ingress attestation client CIDR set is empty or too large")
	}
	seen := make(map[string]bool, len(attestation.ClientCIDRs))
	prefixes := make([]netip.Prefix, 0, len(attestation.ClientCIDRs))
	for _, raw := range attestation.ClientCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil { return fmt.Errorf("host ingress attestation contains invalid client CIDR") }
		prefix = prefix.Masked()
		addr := prefix.Addr()
		if prefix.Bits() == 0 || addr.IsUnspecified() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.Is4In6() {
			return fmt.Errorf("host ingress attestation contains reserved client CIDR")
		}
		if seen[prefix.String()] { return fmt.Errorf("host ingress attestation contains duplicate client CIDR") }
		seen[prefix.String()] = true
		for _, previous := range prefixes {
			if addr.Is4() == previous.Addr().Is4() && (prefix.Contains(previous.Addr()) || previous.Contains(addr)) {
				return fmt.Errorf("host ingress attestation contains overlapping client CIDRs")
			}
		}
		prefixes = append(prefixes, prefix)
	}
	return nil
}
