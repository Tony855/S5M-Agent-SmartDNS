package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const smartDNSHostIngressAttestationPath = "/run/s5m-agent-ingress/ingress.json"
const smartDNSHostIngressAttestationVersion = 1

var smartDNSHostIngressInterfacePattern = regexp.MustCompile("^[A-Za-z0-9_.:-]{1,15}$")

const smartDNSLinuxUserHz = 100

// A root-owned 0600 file is not trustworthy when the Agent itself runs as
// root and the Docker bind mount is writable. Inspect the opened descriptor's
// mount flags so a deployment that omits :ro cannot turn host JSON booleans
// into self-asserted readiness.
func smartDNSAttestationFileSystemReadOnly(fd int) (bool, error) {
	var filesystem syscall.Statfs_t
	if err := syscall.Fstatfs(fd, &filesystem); err != nil {
		return false, fmt.Errorf("inspect host ingress attestation mount: %w", err)
	}
	return filesystem.Flags&syscall.MS_RDONLY != 0, nil
}

var smartDNSAttestationMountReadOnly = smartDNSAttestationFileSystemReadOnly

// parseSmartDNSContainerInitStartTime derives PID 1's start time from the
// Linux procfs ABI. Docker restarts retain a container ID and may retain its
// network ID/IP, so an attestation written before this PID namespace existed
// must never be reused by the restarted Agent.
func parseSmartDNSContainerInitStartTime(processStat, systemStat []byte) (time.Time, error) {
	closeParen := strings.LastIndex(string(processStat), ")")
	if closeParen < 0 {
		return time.Time{}, fmt.Errorf("container PID 1 proc stat is malformed")
	}
	fields := strings.Fields(string(processStat[closeParen+1:]))
	// Fields begin at proc stat field 3 (state); starttime is field 22.
	if len(fields) <= 19 {
		return time.Time{}, fmt.Errorf("container PID 1 proc stat is truncated")
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("container PID 1 start ticks are invalid: %w", err)
	}
	for _, line := range strings.Split(string(systemStat), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "btime" {
			continue
		}
		bootSeconds, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || bootSeconds <= 0 {
			return time.Time{}, fmt.Errorf("system boot time is invalid")
		}
		seconds := int64(startTicks / smartDNSLinuxUserHz)
		remainder := int64(startTicks % smartDNSLinuxUserHz)
		return time.Unix(bootSeconds+seconds, remainder*int64(time.Second)/smartDNSLinuxUserHz), nil
	}
	return time.Time{}, fmt.Errorf("system boot time is missing from proc stat")
}

func currentSmartDNSContainerInitStartTime() (time.Time, error) {
	processStat, err := os.ReadFile("/proc/1/stat")
	if err != nil {
		return time.Time{}, fmt.Errorf("read container PID 1 start time: %w", err)
	}
	systemStat, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, fmt.Errorf("read system boot time: %w", err)
	}
	return parseSmartDNSContainerInitStartTime(processStat, systemStat)
}

func validateSmartDNSHostIngressFileFreshForContainer(attestationModTime, containerStartTime time.Time) error {
	if attestationModTime.IsZero() || containerStartTime.IsZero() || attestationModTime.Before(containerStartTime) {
		return fmt.Errorf("host ingress attestation predates the current Agent container start; waiting for a fresh host reconcile")
	}
	return nil
}

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
	return readSmartDNSHostIngressAttestationFromPathWithOwner(path, true)
}

func readSmartDNSHostIngressAttestationFromPathWithOwner(path string, requireRootOwner bool) (smartDNSHostIngressAttestation, error) {
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
	readOnly, mountErr := smartDNSAttestationMountReadOnly(fd)
	if mountErr != nil {
		return attestation, fmt.Errorf("verify host ingress attestation mount: %w", mountErr)
	}
	if !readOnly {
		return attestation, fmt.Errorf("host ingress attestation must be mounted read-only from the Docker host")
	}
	if info.Mode().Perm()&0022 != 0 {
		return attestation, fmt.Errorf("host ingress attestation must not be group/world writable")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || (requireRootOwner && stat.Uid != 0) {
		return attestation, fmt.Errorf("host ingress attestation must be owned by root")
	}
	containerStartTime, err := currentSmartDNSContainerInitStartTime()
	if err != nil {
		return attestation, fmt.Errorf("cannot verify current Agent container start time: %w", err)
	}
	if err := validateSmartDNSHostIngressFileFreshForContainer(info.ModTime(), containerStartTime); err != nil {
		return attestation, err
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
	if attestation.Interface != strings.TrimSpace(attestation.Interface) || !smartDNSHostIngressInterfacePattern.MatchString(attestation.Interface) {
		return fmt.Errorf("host ingress attestation interface is invalid")
	}
	if strings.TrimSpace(attestation.IPv4Address) == "" && strings.TrimSpace(attestation.IPv6Address) == "" {
		return fmt.Errorf("host ingress attestation has no ingress address")
	}
	if strings.TrimSpace(attestation.IPv4Address) != "" {
		ip, err := netip.ParseAddr(strings.TrimSpace(attestation.IPv4Address))
		if err != nil || !ip.Is4() || ip.String() != attestation.IPv4Address || !ip.IsGlobalUnicast() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return fmt.Errorf("host ingress attestation IPv4 address is invalid")
		}
	}
	if strings.TrimSpace(attestation.IPv6Address) != "" {
		ip, err := netip.ParseAddr(strings.TrimSpace(attestation.IPv6Address))
		if err != nil || !ip.Is6() || ip.String() != attestation.IPv6Address || !ip.IsGlobalUnicast() || ip.Zone() != "" || ip.Is4In6() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return fmt.Errorf("host ingress attestation IPv6 address is invalid")
		}
	}
	if len(attestation.ClientCIDRs) == 0 || len(attestation.ClientCIDRs) > 128 {
		return fmt.Errorf("host ingress attestation client CIDR set is empty or too large")
	}
	seen := make(map[string]bool, len(attestation.ClientCIDRs))
	hasIPv4CIDR, hasIPv6CIDR := false, false
	prefixes := make([]netip.Prefix, 0, len(attestation.ClientCIDRs))
	for _, raw := range attestation.ClientCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil { return fmt.Errorf("host ingress attestation contains invalid client CIDR") }
		if prefix.String() != raw || prefix != prefix.Masked() { return fmt.Errorf("host ingress attestation client CIDR is not canonical") }
		prefix = prefix.Masked()
		addr := prefix.Addr()
		if addr.Is4() { hasIPv4CIDR = true } else { hasIPv6CIDR = true }
		if prefix.Bits() == 0 || !addr.IsGlobalUnicast() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.Is4In6() {
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
	if hasIPv4CIDR && strings.TrimSpace(attestation.IPv4Address) == "" { return fmt.Errorf("host ingress attestation is missing an IPv4 ingress address") }
	if hasIPv6CIDR && strings.TrimSpace(attestation.IPv6Address) == "" { return fmt.Errorf("host ingress attestation is missing an IPv6 ingress address") }
	return nil
}
