package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

const smartDNSPerClientIngressPort = 6055

type smartDNSIngressObservation struct {
	Interfaces []string
	IPv4       []string
	IPv6       []string
	AddressInterfaces map[string]string
	UDP        bool
	TCP        bool
}

type smartDNSIngressObservationDependencies struct {
	interfaces func() ([]net.Interface, error)
	readFile   func(string) ([]byte, error)
}

func defaultSmartDNSIngressObservationDependencies() smartDNSIngressObservationDependencies {
	return smartDNSIngressObservationDependencies{
		interfaces: net.Interfaces,
		readFile:   os.ReadFile,
	}
}

// collectSmartDNSIngressObservation reports only facts visible inside the
// Agent network namespace. It intentionally does not attest host firewall
// persistence, source-IP preservation, routed reachability, or proxy egress.
func collectSmartDNSIngressObservation(deps smartDNSIngressObservationDependencies) (smartDNSIngressObservation, error) {
	observed := smartDNSIngressObservation{AddressInterfaces: make(map[string]string)}
	if deps.interfaces == nil || deps.readFile == nil {
		return observed, fmt.Errorf("ingress observation dependencies are unavailable")
	}
	interfaces, err := deps.interfaces()
	if err != nil {
		return observed, fmt.Errorf("enumerate Agent network interfaces: %w", err)
	}
	addressSet := make(map[string]bool)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return observed, fmt.Errorf("read addresses for interface %s: %w", iface.Name, err)
		}
		var ifaceAddresses []string
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil || ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			value := ip.String()
			addressSet[value] = true
			observed.AddressInterfaces[value] = iface.Name
			ifaceAddresses = append(ifaceAddresses, value)
			if ip.To4() != nil {
				observed.IPv4 = append(observed.IPv4, value)
			} else {
				observed.IPv6 = append(observed.IPv6, value)
			}
		}
		if len(ifaceAddresses) > 0 {
			observed.Interfaces = append(observed.Interfaces, iface.Name)
		}
	}
	if len(addressSet) == 0 {
		return observed, fmt.Errorf("no active non-loopback Agent interface addresses were observed")
	}

	udp4, err := deps.readFile("/proc/net/udp")
	if err != nil { return observed, fmt.Errorf("read IPv4 UDP socket table: %w", err) }
	udp6, err := deps.readFile("/proc/net/udp6")
	if err != nil { return observed, fmt.Errorf("read IPv6 UDP socket table: %w", err) }
	tcp4, err := deps.readFile("/proc/net/tcp")
	if err != nil { return observed, fmt.Errorf("read IPv4 TCP socket table: %w", err) }
	tcp6, err := deps.readFile("/proc/net/tcp6")
	if err != nil { return observed, fmt.Errorf("read IPv6 TCP socket table: %w", err) }
	observed.UDP = procSocketTableHasListener(udp4, false, smartDNSPerClientIngressPort, addressSet, false) ||
		procSocketTableHasListener(udp6, true, smartDNSPerClientIngressPort, addressSet, false)
	observed.TCP = procSocketTableHasListener(tcp4, false, smartDNSPerClientIngressPort, addressSet, true) ||
		procSocketTableHasListener(tcp6, true, smartDNSPerClientIngressPort, addressSet, true)
	return observed, nil
}

func procSocketTableHasListener(data []byte, ipv6 bool, port int, interfaceAddresses map[string]bool, requireTCPListen bool) bool {
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 { continue }
		if requireTCPListen && fields[3] != "0A" { continue }
		if !requireTCPListen && fields[3] != "07" { continue }
		local := strings.Split(fields[1], ":")
		if len(local) != 2 { continue }
		parsedPort, err := strconv.ParseInt(local[1], 16, 32)
		if err != nil || int(parsedPort) != port { continue }
		address, err := decodeProcSocketAddress(local[0], ipv6)
		if err != nil { continue }
		if address.IsUnspecified() || interfaceAddresses[address.String()] {
			return true
		}
	}
	return false
}

func decodeProcSocketAddress(raw string, ipv6 bool) (net.IP, error) {
	decoded, err := hex.DecodeString(raw)
	if err != nil { return nil, err }
	if ipv6 {
		if len(decoded) != net.IPv6len { return nil, fmt.Errorf("invalid IPv6 proc address length") }
		for i := 0; i < len(decoded); i += 4 {
			decoded[i], decoded[i+3] = decoded[i+3], decoded[i]
			decoded[i+1], decoded[i+2] = decoded[i+2], decoded[i+1]
		}
		return net.IP(decoded), nil
	}
	if len(decoded) != net.IPv4len { return nil, fmt.Errorf("invalid IPv4 proc address length") }
	for i, j := 0, len(decoded)-1; i < j; i, j = i+1, j-1 {
		decoded[i], decoded[j] = decoded[j], decoded[i]
	}
	return net.IP(decoded), nil
}


// procSocketTableHasExactListener is stricter than the diagnostic observer:
// wildcard binds are never accepted as proof for a contract-specific address.
func procSocketTableHasExactListener(data []byte, ipv6 bool, port int, expectedAddress string, requireTCPListen bool) bool {
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 { continue }
		if requireTCPListen && fields[3] != "0A" { continue }
		local := strings.Split(fields[1], ":")
		if len(local) != 2 { continue }
		parsedPort, err := strconv.ParseInt(local[1], 16, 32)
		if err != nil || int(parsedPort) != port { continue }
		address, err := decodeProcSocketAddress(local[0], ipv6)
		if err != nil || address.IsUnspecified() { continue }
		if address.String() == expectedAddress { return true }
	}
	return false
}
