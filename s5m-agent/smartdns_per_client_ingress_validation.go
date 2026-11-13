package main

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const smartDNSPerClientIngressContractVersion = 1

// smartDNSPerClientIngressContract is supplied only after the host-side
// ingress controller has provisioned and attested the routed dataplane.
// This validator is intentionally separate from validateSmartDNSConfig:
// shared-mode policy remains unchanged and never accepts non-loopback binds.
type smartDNSPerClientIngressContract struct {
	Version      int
	Ready        bool
	IPv4Address  string
	IPv6Address  string
	ClientCIDRs  []string
}

type smartDNSPerClientGroup struct {
	cidr       string
}

func validateSmartDNSConfigWithIngress(data []byte, contract smartDNSPerClientIngressContract) error {
	if contract.Version != smartDNSPerClientIngressContractVersion || !contract.Ready {
		return fmt.Errorf("per-client DNS ingress contract is missing, unsupported, or not ready")
	}
	if len(data) == 0 || len(data) > 8<<10 {
		return fmt.Errorf("SmartDNS per-client config must be non-empty and at most 8 KiB")
	}
	if smartDNSControlChars.Match(data) {
		return fmt.Errorf("SmartDNS per-client config contains control characters")
	}

	cidrs := make(map[string]bool, len(contract.ClientCIDRs))
	hasIPv4CIDR, hasIPv6CIDR := false, false
	for _, raw := range contract.ClientCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("invalid client CIDR in ingress contract")
		}
		prefix = prefix.Masked()
		cidr := prefix.String()
		if cidrs[cidr] {
			return fmt.Errorf("duplicate client CIDR in ingress contract: %s", cidr)
		}
		for existing := range cidrs {
			other, _ := netip.ParsePrefix(existing)
			if prefix.Addr().Is4() == other.Addr().Is4() &&
				(prefix.Contains(other.Addr()) || other.Contains(prefix.Addr())) {
				return fmt.Errorf("overlapping client CIDRs in ingress contract")
			}
		}
		cidrs[cidr] = true
		if prefix.Addr().Is4() {
			hasIPv4CIDR = true
		} else {
			hasIPv6CIDR = true
		}
	}
	if len(cidrs) == 0 {
		return fmt.Errorf("per-client ingress contract has no client CIDRs")
	}

	ingressAddresses := make(map[string]bool, 2)
	if hasIPv4CIDR {
		if err := addValidatedIngressAddress(ingressAddresses, contract.IPv4Address, true); err != nil {
			return fmt.Errorf("invalid IPv4 ingress address: %w", err)
		}
	} else if strings.TrimSpace(contract.IPv4Address) != "" {
		return fmt.Errorf("IPv4 ingress address supplied without IPv4 client CIDRs")
	}
	if hasIPv6CIDR {
		if err := addValidatedIngressAddress(ingressAddresses, contract.IPv6Address, false); err != nil {
			return fmt.Errorf("invalid IPv6 ingress address: %w", err)
		}
	} else if strings.TrimSpace(contract.IPv6Address) != "" {
		return fmt.Errorf("IPv6 ingress address supplied without IPv6 client CIDRs")
	}

	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	var sharedConfig strings.Builder
	ingressUDP, ingressTCP := map[string]int{}, map[string]int{}
	proxies := make(map[string]int)
	groups := make(map[string]*smartDNSPerClientGroup)
	var activeGroup string
	serverGroups := make(map[string]bool)
	upstreamCounts := make(map[string]int)

	for lineNo, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return fmt.Errorf("line %d has invalid directive syntax", lineNo+1)
		}

		switch fields[0] {
		case "bind", "bind-tcp":
			if strings.HasSuffix(fields[1], ":6055") {
				if len(fields) != 2 {
					return fmt.Errorf("line %d: ingress bind does not accept extra options", lineNo+1)
				}
				host, port, err := net.SplitHostPort(fields[1])
				if err != nil || port != "6055" {
					return fmt.Errorf("line %d: invalid ingress bind", lineNo+1)
				}
				ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
				if err != nil || !ingressAddresses[ip.String()] {
					return fmt.Errorf("line %d: ingress bind is not an attested address", lineNo+1)
				}
				if fields[0] == "bind" {
					ingressUDP[ip.String()]++
				} else {
					ingressTCP[ip.String()]++
				}
				continue
			}
			sharedConfig.WriteString(line + "\n")
		case "proxy-server":
			if len(fields) != 4 || fields[2] != "-name" {
				return fmt.Errorf("line %d: invalid per-client proxy-server syntax", lineNo+1)
			}
			u, err := url.Parse(fields[1])
			if err != nil || u.Scheme != "socks5" || u.User != nil ||
				u.Hostname() != "127.0.0.1" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
				return fmt.Errorf("line %d: per-client SOCKS endpoint must be loopback-only", lineNo+1)
			}
			port, err := strconv.Atoi(u.Port())
			if err != nil || port < 1024 || port > 65535 {
				return fmt.Errorf("line %d: invalid per-client SOCKS port", lineNo+1)
			}
			name := fields[3]
			expectedName := fmt.Sprintf("s5m-smartdns-%d", port)
			if name != expectedName || proxies[name] != 0 {
				return fmt.Errorf("line %d: proxy name/port mismatch or duplicate", lineNo+1)
			}
			proxies[name] = port
		case "group-begin":
			if len(fields) != 2 || activeGroup != "" {
				return fmt.Errorf("line %d: invalid or nested group-begin", lineNo+1)
			}
			group := fields[1]
			if !strings.HasPrefix(group, "s5m-smartdns-group-") {
				return fmt.Errorf("line %d: unmanaged group name", lineNo+1)
			}
			if groups[group] != nil {
				return fmt.Errorf("line %d: duplicate group", lineNo+1)
			}
			groups[group] = &smartDNSPerClientGroup{}
			activeGroup = group
		case "group-match":
			if len(fields) != 3 || fields[1] != "-client-ip" || activeGroup == "" || groups[activeGroup].cidr != "" {
				return fmt.Errorf("line %d: invalid group-match scope or syntax", lineNo+1)
			}
			prefix, err := netip.ParsePrefix(fields[2])
			if err != nil {
				return fmt.Errorf("line %d: invalid group-match CIDR", lineNo+1)
			}
			cidr := prefix.Masked().String()
			if !cidrs[cidr] {
				return fmt.Errorf("line %d: group-match CIDR is not in the attested allowlist", lineNo+1)
			}
			groups[activeGroup].cidr = cidr
		case "group-end":
			if len(fields) != 1 || activeGroup == "" || groups[activeGroup].cidr == "" {
				return fmt.Errorf("line %d: invalid group-end", lineNo+1)
			}
			activeGroup = ""
		case "server-tls":
			if activeGroup != "" {
				return fmt.Errorf("line %d: server upstream cannot be nested inside a client match block", lineNo+1)
			}
			group, proxy, excluded := "", "", false
			groupCount, proxyCount, excludedCount := 0, 0, 0
			for i := 2; i < len(fields); i++ {
				switch fields[i] {
				case "-group":
					groupCount++
					if i+1 >= len(fields) { return fmt.Errorf("line %d: missing upstream group", lineNo+1) }
					group = fields[i+1]
					i++
				case "-proxy":
					proxyCount++
					if i+1 >= len(fields) { return fmt.Errorf("line %d: missing upstream proxy", lineNo+1) }
					proxy = fields[i+1]
					i++
				case "-exclude-default-group":
					excludedCount++
					excluded = true
				}
			}
			if groupCount != 1 || proxyCount != 1 || excludedCount != 1 || !excluded {
				return fmt.Errorf("line %d: every per-client DoT upstream must be pinned to one group/proxy and exclude the default group", lineNo+1)
			}
			expectedProxy := strings.Replace(group, "s5m-smartdns-group-", "s5m-smartdns-", 1)
			if expectedProxy == group || proxy != expectedProxy {
				return fmt.Errorf("line %d: upstream group/proxy mapping mismatch", lineNo+1)
			}
			if _, ok := proxies[proxy]; !ok {
				return fmt.Errorf("line %d: upstream references an undeclared proxy", lineNo+1)
			}
			if endpointErr := validateSmartDNSUpstreamEndpoint("server-tls", fields[1], fields[2:]); endpointErr != nil {
				return fmt.Errorf("line %d: invalid encrypted upstream: %w", lineNo+1, endpointErr)
			}
			serverGroups[group] = true
			upstreamCounts[group]++
			sharedConfig.WriteString(line + "\n")
		default:
			sharedConfig.WriteString(line + "\n")
		}
	}
	if activeGroup != "" {
		return fmt.Errorf("unterminated per-client group")
	}
	for address := range ingressAddresses {
		if ingressUDP[address] != 1 || ingressTCP[address] != 1 {
			return fmt.Errorf("ingress address %s must have both UDP and TCP listeners", address)
		}
	}
	if len(ingressUDP) != len(ingressAddresses) || len(ingressTCP) != len(ingressAddresses) {
		return fmt.Errorf("unexpected or duplicate ingress listener address")
	}
	if len(groups) != len(cidrs) || len(proxies) != len(cidrs) {
		return fmt.Errorf("per-client group/proxy count does not match the attested CIDR set")
	}
	seenCIDRs := make(map[string]bool, len(groups))
	for group, entry := range groups {
		if entry.cidr == "" || upstreamCounts[group] == 0 || !serverGroups[group] {
			return fmt.Errorf("group %s has no matching CIDR or encrypted upstream", group)
		}
		if seenCIDRs[entry.cidr] {
			return fmt.Errorf("multiple groups map to the same client CIDR")
		}
		seenCIDRs[entry.cidr] = true
		expectedProxy := strings.Replace(group, "s5m-smartdns-group-", "s5m-smartdns-", 1)
		if _, ok := proxies[expectedProxy]; !ok {
			return fmt.Errorf("group %s has no dedicated proxy listener", group)
		}
	}
	for cidr := range cidrs {
		if !seenCIDRs[cidr] {
			return fmt.Errorf("attested client CIDR %s has no SmartDNS group", cidr)
		}
	}
	for proxy := range proxies {
		used := false
		for group := range serverGroups {
			if strings.Replace(group, "s5m-smartdns-group-", "s5m-smartdns-", 1) == proxy {
				used = true
				break
			}
		}
		if !used {
			return fmt.Errorf("declared per-client proxy is not used by an upstream")
		}
	}
	if err := validateSmartDNSConfig([]byte(sharedConfig.String())); err != nil {
		return fmt.Errorf("shared resolver policy validation failed: %w", err)
	}
	return nil
}

func addValidatedIngressAddress(addresses map[string]bool, raw string, wantIPv4 bool) error {
	ip, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.Is4() != wantIPv4 {
		return fmt.Errorf("address is not a usable unicast address for the configured family")
	}
	if addresses[ip.String()] {
		return fmt.Errorf("duplicate ingress address")
	}
	addresses[ip.String()] = true
	return nil
}
