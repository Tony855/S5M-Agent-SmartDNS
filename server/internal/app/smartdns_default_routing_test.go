package app

import (
	"path/filepath"
	"strings"
	"testing"
)

func newSmartDNSRoutingTestApp(t *testing.T, settings map[string]string) *App {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "smartdns-routing.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.db.Close() })
	if len(settings) > 0 {
		if err := store.UpdateSettings(settings); err != nil {
			t.Fatalf("UpdateSettings: %v", err)
		}
	}
	return &App{store: store}
}

func TestBuildConfigForMachineEnabledSmartDNSDefaultsToSharedProxyRoute(t *testing.T) {
	app := newSmartDNSRoutingTestApp(t, map[string]string{
		"smartdns_enabled_node-a": "true",
	})
	if err := app.store.CreateProxy(&Proxy{
		Name: "node-a-out", Mode: "rule", Type: "socks5",
		Server: "192.0.2.10", Port: 1080, MachineCode: "node-a",
		SourceCIDR: "0.0.0.0/0", Enabled: true,
	}); err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}

	got, err := app.BuildConfigForMachine("node-a")
	if err != nil {
		t.Fatalf("BuildConfigForMachine: %v", err)
	}
	for _, want := range []string{
		"name: SMARTDNS-PROXY",
		"node-a-out",
		"PROCESS-NAME,smartdns,SMARTDNS-PROXY",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("enabled SmartDNS config missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "PROCESS-NAME,smartdns,DIRECT") {
		t.Fatalf("SmartDNS must never be routed directly:\n%s", got)
	}
}

func TestBuildConfigForMachineEnabledSmartDNSWithoutProxyFailsClosed(t *testing.T) {
	app := newSmartDNSRoutingTestApp(t, map[string]string{
		"smartdns_enabled_node-a": "true",
	})

	got, err := app.BuildConfigForMachine("node-a")
	if err != nil {
		t.Fatalf("BuildConfigForMachine should generate a fail-closed config: %v", err)
	}
	if !strings.Contains(got, "PROCESS-NAME,smartdns,REJECT") {
		t.Fatalf("SmartDNS without an eligible proxy must be explicitly rejected:\n%s", got)
	}
	if strings.Contains(got, "PROCESS-NAME,smartdns,DIRECT") {
		t.Fatalf("SmartDNS without an eligible proxy must not fall back to DIRECT:\n%s", got)
	}
}

func TestBuildConfigForMachineExplicitEmptySmartDNSRoutingPreservesLegacy(t *testing.T) {
	app := newSmartDNSRoutingTestApp(t, map[string]string{
		"smartdns_enabled_node-a": "true",
		"smartdns_routing_config": "",
	})
	got, err := app.BuildConfigForMachine("node-a")
	if err != nil {
		t.Fatalf("BuildConfigForMachine: %v", err)
	}
	if strings.Contains(got, "PROCESS-NAME,smartdns,") {
		t.Fatalf("explicit empty routing setting must preserve legacy routing:\n%s", got)
	}
}
