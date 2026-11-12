package main

import (
	"errors"
	"strings"
	"testing"
)

func TestProbeMihomoDNSFallbackChecksUDPAndTCPForBothFamilies(t *testing.T) {
	tests := []struct {
		name       string
		config     string
		wantCalls  int
	}{
		{
			name:      "IPv4-only listener configuration",
			config:    "dns:\n  listen: 127.0.0.1:5353\n  ipv6: false\n",
			wantCalls: 4,
		},
		{
			name:      "dual-stack DNS configuration",
			config:    "dns:\n  listen: 0.0.0.0:5353\n  ipv6: true\n",
			wantCalls: 6,
		},
		{
			name:      "IPv6 loopback listener",
			config:    "dns:\n  listen: '[::1]:5353'\n  ipv6: true\n",
			wantCalls: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls [][]string
			ok := probeMihomoDNSFallbackWithDig([]byte(tt.config), func(args ...string) ([]byte, error) {
				calls = append(calls, append([]string(nil), args...))
				qtype := args[len(args)-1]
				if qtype == "AAAA" {
					return []byte("2001:db8::1\n"), nil
				}
				return []byte("192.0.2.10\n"), nil
			})
			if !ok {
				t.Fatal("valid fallback DNS answers should pass")
			}
			if len(calls) != tt.wantCalls {
				t.Fatalf("dig calls = %d, want %d", len(calls), tt.wantCalls)
			}
			seen := map[string]map[bool]bool{}
			for _, args := range calls {
				qtype := args[len(args)-1]
				if seen[qtype] == nil {
					seen[qtype] = map[bool]bool{}
				}
				tcp := false
				for _, arg := range args {
					if arg == "+tcp" {
						tcp = true
					}
				}
				seen[qtype][tcp] = true
				if !strings.Contains(strings.Join(args, " "), "@127.0.0.1") &&
					!strings.Contains(strings.Join(args, " "), "@::1") {
					t.Errorf("probe must use a loopback resolver: %v", args)
				}
			}
			for _, qtype := range []string{"A"} {
				if !seen[qtype][false] || !seen[qtype][true] {
					t.Errorf("%s must be checked over UDP and TCP; got %#v", qtype, seen[qtype])
				}
			}
			if strings.Contains(tt.config, "ipv6: true") && (!seen["AAAA"][false] || !seen["AAAA"][true]) {
				t.Errorf("AAAA must be checked over UDP and TCP; got %#v", seen["AAAA"])
			}
		})
	}
}

func TestProbeMihomoDNSFallbackFailsClosedOnBadAnswersAndCommandErrors(t *testing.T) {
	tests := []struct {
		name   string
		output []byte
		err    error
	}{
		{name: "empty answer"},
		{name: "wrong address family", output: []byte("2001:db8::1\n")},
		{name: "dig command failure", output: []byte("192.0.2.1\n"), err: errors.New("dig failed")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			ok := probeMihomoDNSFallbackWithDig([]byte("dns:\n  listen: 127.0.0.1:5353\n  ipv6: false\n"), func(args ...string) ([]byte, error) {
				calls++
				if tt.name == "wrong address family" {
					return tt.output, nil
				}
				if calls == 1 {
					return tt.output, tt.err
				}
				return []byte("192.0.2.1\n"), nil
			})
			if ok {
				t.Fatal("invalid fallback result must fail closed")
			}
		})
	}
}

func TestProbeMihomoDNSFallbackRejectsNonLoopbackAndMalformedListeners(t *testing.T) {
	for _, listen := range []string{"0.0.0.0", "192.0.2.53:5353", "example.com:5353", "[::]:5353"} {
		t.Run(listen, func(t *testing.T) {
			called := false
			config := []byte("dns:\n  listen: " + listen + "\n  ipv6: false\n")
			if probeMihomoDNSFallbackWithDig(config, func(...string) ([]byte, error) {
				called = true
				return []byte("192.0.2.1"), nil
			}) {
				t.Fatal("unsafe or malformed listener must be rejected")
			}
			if called {
				t.Fatal("dig must not run for an invalid listener")
			}
		})
	}
}

func TestProbeMihomoDNSFallbackRejectsNilRunnerAndInvalidYAML(t *testing.T) {
	if probeMihomoDNSFallbackWithDig([]byte("dns: ["), func(...string) ([]byte, error) {
		t.Fatal("runner must not run for invalid YAML")
		return nil, nil
	}) {
		t.Fatal("invalid YAML must fail")
	}
	if probeMihomoDNSFallbackWithDig([]byte("dns:\n  listen: 127.0.0.1:5353\n"), nil) {
		t.Fatal("nil dig runner must fail")
	}
}



func TestSmartDNSCombinedHealthRequiresEveryDomesticDNSTransport(t *testing.T) {
	config := []byte("bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nbind 127.0.0.1:6054 -group china-dot\nbind-tcp 127.0.0.1:6054 -group china-dot\n")
	tests := []struct {
		name string
		fail string
		want bool
	}{
		{name: "all listeners healthy", want: true},
		{name: "primary UDP failed", fail: "udp:127.0.0.1:6053"},
		{name: "primary TCP failed", fail: "tcp:127.0.0.1:6053"},
		{name: "domestic UDP failed", fail: "udp:127.0.0.1:6054"},
		{name: "domestic TCP failed", fail: "tcp:127.0.0.1:6054"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []string
			probe := func(transport string) func(string) bool {
				return func(address string) bool {
					key := transport + ":" + address
					calls = append(calls, key)
					return key != tt.fail
				}
			}
			got := probeSmartDNSDNSWithConfigAndProbes(config, probe("udp"), probe("tcp"))
			if got != tt.want {
				t.Fatalf("combined SmartDNS health = %v, want %v (calls=%v)", got, tt.want, calls)
			}
			if tt.fail != "" {
				if len(calls) >= 8 {
					t.Fatalf("health probe did not short-circuit after a failed dataplane: %v", calls)
				}
			} else if len(calls) != 4 {
				t.Fatalf("healthy domestic setup should probe primary and domestic UDP/TCP exactly once: %v", calls)
			}
		})
	}
}

func TestSmartDNSCombinedHealthRejectsMissingProbeFunctions(t *testing.T) {
	config := []byte("bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\n")
	if probeSmartDNSDNSWithConfigAndProbes(config, nil, func(string) bool { return true }) {
		t.Fatal("missing UDP probe must fail closed")
	}
	if probeSmartDNSDNSWithConfigAndProbes(config, func(string) bool { return true }, nil) {
		t.Fatal("missing TCP probe must fail closed")
	}
}
