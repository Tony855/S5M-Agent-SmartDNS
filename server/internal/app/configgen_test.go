package app

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestNormalizeAgentProxyConfigRemovesExplicitProxyListeners(t *testing.T) {
	input := `mixed-port: 7890
port: 8080
socks-port: 8081
redir-port: 8082
tproxy-port: 8083
listeners:
  - name: unsafe-socks
    type: socks
    listen: 0.0.0.0
    port: 7891
allow-lan: true
external-controller: 0.0.0.0:8088
dns:
  fake-ip-filter:
    - '*.lan'
tun:
  enable: true
  route-exclude-address:
    - 10.1.2.0/24
proxies:
  - name: upstream
    type: socks5
    server: 203.0.113.10
    port: 1080
`
	got, err := normalizeAgentProxyConfig(input)
	if err != nil {
		t.Fatalf("normalizeAgentProxyConfig: %v", err)
	}
	var config map[string]any
	if err := yaml.Unmarshal([]byte(got), &config); err != nil {
		t.Fatalf("decode normalized YAML: %v", err)
	}
	for _, key := range []string{"mixed-port", "port", "socks-port", "redir-port", "tproxy-port", "listeners"} {
		if _, exists := config[key]; exists {
			t.Errorf("explicit proxy listener %q must be removed: %s", key, got)
		}
	}
	if config["allow-lan"] != false {
		t.Fatalf("allow-lan = %#v, want false", config["allow-lan"])
	}
	if config["external-controller"] != "127.0.0.1:8088" {
		t.Fatalf("external-controller = %#v", config["external-controller"])
	}
	if config["find-process-mode"] != "strict" {
		t.Fatalf("find-process-mode = %#v, want strict", config["find-process-mode"])
	}
	dns, ok := config["dns"].(map[string]any)
	if !ok {
		t.Fatalf("dns is not a mapping: %#v", config["dns"])
	}
	filters, ok := dns["fake-ip-filter"].([]any)
	if !ok {
		t.Fatalf("fake-ip-filter is not a sequence: %#v", dns["fake-ip-filter"])
	}
	for _, want := range []string{"*.lan", "*.local", "geosite:private", "+.v2net.cc"} {
		found := false
		for _, item := range filters {
			if item == want { found = true; break }
		}
		if !found { t.Errorf("fake-ip-filter missing %q: %#v", want, filters) }
	}
	if dns["ipv6"] != false {
		t.Errorf("dns.ipv6 = %#v, want false", dns["ipv6"])
	}
	tun, ok := config["tun"].(map[string]any)
	if !ok { t.Fatalf("tun is not a mapping: %#v", config["tun"]) }
	if tun["enable"] != true {
		t.Errorf("TUN enable was not preserved: %#v", tun["enable"])
	}
	dnsHijack, ok := tun["dns-hijack"].([]any)
	if !ok { t.Fatalf("tun dns-hijack is not a sequence: %#v", tun["dns-hijack"]) }
	foundDNSHijack := false
	for _, item := range dnsHijack { if item == "any:53" { foundDNSHijack = true; break } }
	if !foundDNSHijack { t.Errorf("tun dns-hijack missing any:53: %#v", dnsHijack) }
	foundTCPDNSHijack := false
	for _, item := range dnsHijack { if item == "tcp://any:53" { foundTCPDNSHijack = true; break } }
	if !foundTCPDNSHijack { t.Errorf("tun dns-hijack missing tcp://any:53: %#v", dnsHijack) }
	addresses, ok := tun["route-exclude-address"].([]any)
	if !ok { t.Fatalf("route-exclude-address is not a sequence: %#v", tun["route-exclude-address"]) }
	for _, want := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "203.0.113.10/32", "10.1.2.0/24"} {
		found := false
		for _, item := range addresses { if item == want { found = true; break } }
		if !found { t.Errorf("route-exclude-address missing %q: %#v", want, addresses) }
	}
	for _, item := range addresses {
		if item == "198.18.0.0/16" { t.Fatalf("fake-IP range must remain routed through TUN: %#v", addresses) }
	}
}

func TestNormalizeAgentProxyConfigKeepsBootstrapIndependentFromSmartDNSAndTUN(t *testing.T) {
	input := `dns:
  default-nameserver:
    - 127.0.0.1:6053
    - bootstrap.example.com
    - 9.9.9.9
  proxy-server-nameserver:
    - 127.0.0.1:6053
    - resolver.example.com
    - 8.8.4.4
tun:
  enable: true
`
	got, err := normalizeAgentProxyConfig(input)
	if err != nil { t.Fatalf("normalize config: %v", err) }
	var config map[string]any
	if err := yaml.Unmarshal([]byte(got), &config); err != nil { t.Fatalf("decode config: %v", err) }
	dns := config["dns"].(map[string]any)
	for _, key := range []string{"default-nameserver", "proxy-server-nameserver"} {
		servers, ok := dns[key].([]any)
		if !ok { t.Fatalf("%s is not a sequence: %#v", key, dns[key]) }
		seen := map[string]bool{}
		for _, raw := range servers {
			server, ok := raw.(string)
			if !ok || net.ParseIP(server) == nil { t.Errorf("%s contains non-literal bootstrap %v", key, raw); continue }
			if server == "127.0.0.1" || server == "127.0.0.1:6053" { t.Errorf("%s must not point to SmartDNS: %q", key, server) }
			seen[server] = true
		}
		for _, required := range []string{"223.5.5.5", "119.29.29.29"} {
			if !seen[required] { t.Errorf("%s missing independent bootstrap %s: %#v", key, required, servers) }
		}
	}
	tun := config["tun"].(map[string]any)
	excluded := tun["route-exclude-address"].([]any)
	for _, required := range []string{"223.5.5.5/32", "119.29.29.29/32", "::1/128", "fc00::/7", "fe80::/10"} {
		found := false
		for _, raw := range excluded { if raw == required { found = true; break } }
		if !found { t.Errorf("TUN route exclusions missing %s: %#v", required, excluded) }
	}
}

func TestNormalizeAgentProxyConfigIsIdempotent(t *testing.T) {
	input := `allow-lan: true
mixed-port: 7890
secret: test-secret
tun:
  enable: true
dns:
  enable: true
`
	first, err := normalizeAgentProxyConfig(input)
	if err != nil {
		t.Fatalf("first normalization: %v", err)
	}
	second, err := normalizeAgentProxyConfig(first)
	if err != nil {
		t.Fatalf("second normalization: %v", err)
	}
	if first != second {
		t.Fatalf("normalization must be idempotent; first and second output differ:\nFIRST:\n%s\nSECOND:\n%s", first, second)
	}
}

func TestBuildConfigForMachineDoesNotExposeExplicitProxyListener(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "config-ports.db"))
	if err != nil { t.Fatalf("OpenStore: %v", err) }
	defer store.db.Close()

	app := &App{store: store}
	controllerYAML, err := app.BuildConfigForMachine("")
	if err != nil { t.Fatalf("BuildConfigForMachine(controller): %v", err) }
	if !strings.Contains(controllerYAML, "mixed-port: 8080") {
		t.Fatalf("controller config should retain its separate local listener:\n%s", controllerYAML)
	}

	agentYAML, err := app.BuildConfigForMachine("node-a")
	if err != nil { t.Fatalf("BuildConfigForMachine(agent): %v", err) }
	for _, forbidden := range []string{"mixed-port:", "port:", "socks-port:", "redir-port:", "tproxy-port:", "listeners:", "allow-lan: true"} {
		if strings.Contains(agentYAML, forbidden) {
			t.Errorf("Agent config must not expose explicit proxy listener %q:\\n%s", forbidden, agentYAML)
		}
	}
	for _, want := range []string{"allow-lan: false", "external-controller: 127.0.0.1:8088", "listen: 127.0.0.1:5353", "DOMAIN-SUFFIX,v2net.cc,DIRECT", "enable: false"} {
		if !strings.Contains(agentYAML, want) {
			t.Errorf("Agent initial config missing %q:\\n%s", want, agentYAML)
		}
	}
}

func TestSyncAuthorizedNodeConfigsRejectsNullExistingYAMLWithoutPanicOrWrites(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-null-yaml.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.UpdateSettings(map[string]string{
		"agent_machine_node-a":       "token-a",
		"agent_machine_node-b":       "token-b",
		"agent_mihomo_secret_node-a": "secret-a",
		"agent_mihomo_secret_node-b": "secret-b",
		"tun_enable":                 "true",
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	const nullYAML = "null\n"
	const existingNodeB = "mixed-port: 7888\nsecret: node-b-secret\n"
	if err := store.SaveNodeConfig("node-a", nullYAML); err != nil {
		t.Fatalf("seed null node-a config: %v", err)
	}
	if err := store.SaveNodeConfig("node-b", existingNodeB); err != nil {
		t.Fatalf("seed node-b config: %v", err)
	}

	app := &App{store: store}
	if err := app.syncAuthorizedNodeConfigs(); err == nil {
		t.Fatal("sync should reject null existing YAML with an error")
	}

	for code, want := range map[string]string{
		"node-a": nullYAML,
		"node-b": existingNodeB,
	} {
		got, err := store.GetNodeConfig(code)
		if err != nil {
			t.Fatalf("GetNodeConfig(%s): %v", code, err)
		}
		if got == nil || got.YAML != want {
			t.Errorf("failed sync changed %s config: got=%+v, want YAML %q", code, got, want)
		}
	}
}

func TestSyncAuthorizedNodeConfigsDoesNotWriteBatchWhenAnyExistingYAMLIsInvalid(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-invalid-yaml.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.UpdateSettings(map[string]string{
		"agent_machine_node-a":       "token-a",
		"agent_machine_node-b":       "token-b",
		"agent_mihomo_secret_node-a": "secret-a",
		"agent_mihomo_secret_node-b": "secret-b",
		"tun_enable":                 "true",
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	const invalidYAML = "proxies: [\n"
	const existingNodeB = "mixed-port: 7888\nsecret: node-b-secret\n"
	if err := store.SaveNodeConfig("node-a", invalidYAML); err != nil {
		t.Fatalf("seed invalid node-a config: %v", err)
	}
	if err := store.SaveNodeConfig("node-b", existingNodeB); err != nil {
		t.Fatalf("seed node-b config: %v", err)
	}
	app := &App{store: store}
	if err := app.syncAuthorizedNodeConfigs(); err == nil {
		t.Fatal("sync should fail when an authorized node has invalid existing YAML")
	}

	for code, want := range map[string]string{
		"node-a": invalidYAML,
		"node-b": existingNodeB,
	} {
		got, err := store.GetNodeConfig(code)
		if err != nil {
			t.Fatalf("GetNodeConfig(%s): %v", code, err)
		}
		if got == nil || got.YAML != want {
			t.Errorf("failed sync changed %s config: got=%+v, want YAML %q", code, got, want)
		}
	}
}

func TestSyncAuthorizedNodeConfigsPreservesNodeSettingsAndCanRetry(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-sync.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.UpdateSettings(map[string]string{
		"agent_machine_node-a":       "agent-token",
		"agent_mihomo_secret_node-a": "node-secret",
		"tun_enable":                 "true",
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	customYAML := `mixed-port: 7899
secret: keep-this-secret
tun:
  enable: false
dns:
  enable: true
  listen: 127.0.0.1:5353
proxies:
  - name: stale-proxy
    type: socks5
rules:
  - DOMAIN-SUFFIX,custom-node.example,DIRECT
  - MATCH,DIRECT
`
	if err := store.SaveNodeConfig("node-a", customYAML); err != nil {
		t.Fatalf("SaveNodeConfig: %v", err)
	}
	proxy := &Proxy{
		Name: "managed-proxy", Mode: "rule", Type: "socks5",
		Server: "192.0.2.50", Port: 1080, MachineCode: "node-a",
		SourceCIDR: "0.0.0.0/0", Enabled: true,
	}
	if err := store.CreateProxy(proxy); err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}

	app := &App{store: store}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := app.syncAuthorizedNodeConfigs(); err != nil {
			t.Fatalf("sync attempt %d: %v", attempt, err)
		}
		got, err := store.GetNodeConfig("node-a")
		if err != nil {
			t.Fatalf("GetNodeConfig attempt %d: %v", attempt, err)
		}
		if got == nil {
			t.Fatalf("node config missing after attempt %d", attempt)
		}
		for _, want := range []string{
			"allow-lan: false",
			"secret: keep-this-secret",
			"enable: false",
			"listen: 127.0.0.1:5353",
			"managed-proxy",
			"DOMAIN-SUFFIX,custom-node.example,DIRECT",
			"MATCH,REJECT",
		} {
			if !strings.Contains(got.YAML, want) {
				t.Errorf("attempt %d: synced YAML lost or omitted %q:\n%s", attempt, want, got.YAML)
			}
		}
		if strings.Contains(got.YAML, "mixed-port:") || strings.Contains(got.YAML, "port: 7899") || strings.Contains(got.YAML, "stale-proxy") || strings.Contains(got.YAML, "MATCH,OLD-DIRECT") || strings.Contains(got.YAML, "MATCH,DIRECT") {
			t.Errorf("attempt %d: managed proxy/rule sections were not refreshed:\n%s", attempt, got.YAML)
		}
	}
}

func TestSyncAuthorizedNodeConfigsSkipsUnauthorizedNodeConfigs(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-authorization.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.UpdateSettings(map[string]string{
		"agent_machine_authorized":       "token-authorized",
		"agent_machine_revoked":          "   ",
		"agent_mihomo_secret_authorized": "authorized-secret",
		"tun_enable":                     "true",
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	const authorizedExisting = "mixed-port: 7899\nsecret: preserve-authorized-secret\n"
	const unauthorizedExisting = "mixed-port: 7888\nsecret: preserve-revoked-secret\nproxies: []\nrules: []\n"
	if err := store.SaveNodeConfig("authorized", authorizedExisting); err != nil {
		t.Fatalf("seed authorized config: %v", err)
	}
	if err := store.SaveNodeConfig("revoked", unauthorizedExisting); err != nil {
		t.Fatalf("seed revoked config: %v", err)
	}

	app := &App{store: store}
	if err := app.syncAuthorizedNodeConfigs(); err != nil {
		t.Fatalf("sync authorized nodes: %v", err)
	}

	authorized, err := store.GetNodeConfig("authorized")
	if err != nil {
		t.Fatalf("read authorized config: %v", err)
	}
	if authorized == nil || !strings.Contains(authorized.YAML, "preserve-authorized-secret") || strings.Contains(authorized.YAML, "mixed-port:") {
		t.Fatalf("authorized node's custom settings should be preserved while removing explicit proxy listeners: %+v", authorized)
	}

	revoked, err := store.GetNodeConfig("revoked")
	if err != nil {
		t.Fatalf("read revoked config: %v", err)
	}
	if revoked == nil || revoked.YAML != unauthorizedExisting {
		t.Fatalf("unauthorized node config should not be touched by sync: got=%+v, want YAML %q", revoked, unauthorizedExisting)
	}
}

func TestSyncAuthorizedNodeConfigsWithNoAuthorizedNodesLeavesExistingConfigsUntouched(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-no-agents.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.SaveNodeConfig("historical-node", "mode: rule\n"); err != nil {
		t.Fatalf("SaveNodeConfig: %v", err)
	}
	app := &App{store: store}
	if err := app.syncAuthorizedNodeConfigs(); err != nil {
		t.Fatalf("sync with no authorized nodes should be a no-op: %v", err)
	}
	got, err := store.GetNodeConfig("historical-node")
	if err != nil {
		t.Fatalf("GetNodeConfig: %v", err)
	}
	if got == nil || got.YAML != "mode: rule\n" {
		t.Fatalf("sync with no authorized nodes unexpectedly changed historical config: %+v", got)
	}
}

func TestSaveNodeConfigsRollsBackEntireBatchOnWriteFailure(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-atomic.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.SaveNodeConfig("node-a", "mode: old\n"); err != nil {
		t.Fatalf("seed node-a config: %v", err)
	}
	if _, err := store.db.Exec(`CREATE TRIGGER reject_node_b_config BEFORE INSERT ON node_configs
		WHEN NEW.machine_code = 'node-b'
		BEGIN SELECT RAISE(ABORT, 'simulated node-b write failure'); END`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}

	err = store.SaveNodeConfigs(map[string]string{
		"node-a": "mode: updated\n",
		"node-b": "mode: new\n",
	})
	if err == nil {
		t.Fatal("SaveNodeConfigs should fail when one batch write fails")
	}

	got, err := store.GetNodeConfig("node-a")
	if err != nil {
		t.Fatalf("read node-a after failed batch: %v", err)
	}
	if got == nil || got.YAML != "mode: old\n" {
		t.Fatalf("failed batch partially changed node-a config: got=%+v", got)
	}
	nodeB, err := store.GetNodeConfig("node-b")
	if err != nil {
		t.Fatalf("read node-b after failed batch: %v", err)
	}
	if nodeB != nil {
		t.Fatalf("failed batch unexpectedly persisted node-b config: %+v", nodeB)
	}
}

func TestSaveNodeConfigsEmptyBatchIsNoOp(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-empty.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.SaveNodeConfigs(map[string]string{}); err != nil {
		t.Fatalf("empty batch should be a no-op: %v", err)
	}
}

func TestBuildConfigMapsDisabledCIDRToEnabledEndpoint(t *testing.T) {
	proxies := []Proxy{
		{
			ID: 5, Name: "S5M-23049", Mode: "proxy",
			Type: "socks5", Server: "151.242.11.70", Port: 23049,
			MachineCode: "__GLOBAL__", SourceCIDR: "192.168.1.250/32", Enabled: false,
		},
		{
			ID: 7, Name: "socks5-151.242.11.70:23049", Mode: "proxy",
			Type: "socks5", Server: "151.242.11.70", Port: 23049,
			MachineCode: "__GLOBAL__", SourceCIDR: "0.0.0.0/0", Enabled: true,
		},
		{
			ID: 8, Name: "socks5-2401:b60:e00e:7244:::23050", Mode: "proxy",
			Type: "socks5", Server: "2401:b60:e00e:7244::", Port: 23050,
			MachineCode: "__GLOBAL__", SourceCIDR: "0.0.0.0/0", Enabled: true,
		},
	}

	got, err := buildConfigFromProxies(proxies, "", "test-secret")
	if err != nil {
		t.Fatalf("生成配置失败：%v", err)
	}

	wantRule := "SRC-IP-CIDR,192.168.1.250/32,socks5-151.242.11.70:23049"
	if !strings.Contains(got, wantRule) {
		t.Fatalf("缺少预期分流规则 %q\n生成内容：\n%s", wantRule, got)
	}
	if strings.Contains(got, "NETWORK,UDP,DIRECT") {
		t.Fatal("不应生成全局 UDP 直连规则")
	}
	if !strings.Contains(got, "MATCH,REJECT") {
		t.Fatal("严格规则模式必须以 MATCH,REJECT 收尾")
	}
	if strings.Contains(got, "MATCH,DIRECT") {
		t.Fatal("严格规则模式不能将未命中流量回退为 DIRECT")
	}
	for _, unwanted := range []string{"221111cdn", "^abc.*2222com"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("不应自动生成未配置的拦截规则 %q", unwanted)
		}
	}
	if strings.Contains(got, "name: S5M-23049") {
		t.Fatal("禁用的 ID 5 不应被写入代理出口列表")
	}
}

func TestBuildConfigRejectsDuplicateCIDR(t *testing.T) {
	proxies := []Proxy{
		{
			Name: "proxy-a", Mode: "proxy", Type: "socks5",
			Server: "192.0.2.10", Port: 1080,
			MachineCode: "__GLOBAL__", SourceCIDR: "192.168.1.250/32", Enabled: true,
		},
		{
			Name: "proxy-b", Mode: "proxy", Type: "socks5",
			Server: "192.0.2.11", Port: 1080,
			MachineCode: "__GLOBAL__", SourceCIDR: "192.168.1.250/32", Enabled: true,
		},
	}

	if _, err := buildConfigFromProxies(proxies, "", "test-secret"); err == nil {
		t.Fatal("重复客户端网段应返回错误")
	}
}

func TestBuildConfigRejectsInvalidCIDR(t *testing.T) {
	proxies := []Proxy{
		{
			Name: "proxy-a", Mode: "proxy", Type: "socks5",
			Server: "192.0.2.10", Port: 1080,
			MachineCode: "__GLOBAL__", SourceCIDR: "not-a-cidr", Enabled: true,
		},
	}

	if _, err := buildConfigFromProxies(proxies, "", "test-secret"); err == nil {
		t.Fatal("无效 CIDR 应返回错误")
	}
}

func TestBuildConfigRejectsInvalidPersistedProxy(t *testing.T) {
	tests := []struct {
		name  string
		proxy Proxy
	}{
		{name: "empty name", proxy: Proxy{Mode: "proxy", Type: "socks5", Server: "proxy.example", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true}},
		{name: "unsupported type", proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "vmess+ws", Server: "proxy.example", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true}},
		{name: "invalid mode", proxy: Proxy{Name: "proxy-a", Mode: "unknown", Type: "socks5", Server: "proxy.example", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true}},
		{name: "empty server", proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true}},
		{name: "server contains whitespace", proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Server: "proxy example", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true}},
		{name: "invalid port", proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Server: "proxy.example", Port: 65536, MachineCode: "__GLOBAL__", Enabled: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := buildConfigFromProxies([]Proxy{tt.proxy}, "", "test-secret"); err == nil {
				t.Fatal("invalid persisted proxy should be rejected")
			}
		})
	}
}

func TestBuildConfigNormalizesPersistedProxyFields(t *testing.T) {
	proxy := Proxy{
		Name: " proxy-a ", Mode: " proxy ", Type: " SOCKS5 ",
		Server: " proxy.example ", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true,
	}
	got, err := buildConfigFromProxies([]Proxy{proxy}, "", "test-secret")
	if err != nil {
		t.Fatalf("buildConfigFromProxies() error = %v", err)
	}
	for _, want := range []string{"name: proxy-a", "type: socks5", "server: proxy.example"} {
		if !strings.Contains(got, want) {
			t.Errorf("generated config missing normalized field %q:\\n%s", want, got)
		}
	}
}

func TestMergeManagedRuleValuesRequiresOneTerminalMatchAndValidCustomRules(t *testing.T) {
	generated := []any{
		"DOMAIN-SUFFIX,v2net.cc,DIRECT",
		"DOMAIN,controller.example.com,DIRECT",
		"MATCH,REJECT",
	}
	for _, tc := range []struct {
		name string
		custom any
	}{
		{name: "scalar rules", custom: "DOMAIN-SUFFIX,custom.example,DIRECT"},
		{name: "object rule", custom: []any{map[string]any{"rule": "DOMAIN-SUFFIX,custom.example,DIRECT"}}},
		{name: "empty rule", custom: []any{" "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := mergeManagedRuleValues(tc.custom, generated); err == nil {
				t.Fatal("malformed custom rules must be rejected")
			}
		})
	}
	for _, tc := range []struct {
		name string
		generated []any
	}{
		{name: "missing terminal", generated: []any{"DOMAIN-SUFFIX,v2net.cc,DIRECT"}},
		{name: "multiple terminals", generated: []any{"MATCH,DIRECT", "MATCH,REJECT"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := mergeManagedRuleValues([]any{"DOMAIN-SUFFIX,custom.example,DIRECT"}, tc.generated); err == nil {
				t.Fatal("generated rules must contain exactly one terminal MATCH")
			}
		})
	}

	merged, err := mergeManagedRuleValues([]any{
		"DOMAIN-SUFFIX,custom.example,DIRECT",
		"MATCH,DIRECT",
		"DOMAIN-SUFFIX,custom.example,DIRECT",
	}, generated)
	if err != nil {
		t.Fatalf("merge valid custom rules: %v", err)
	}
	if len(merged) != 4 || merged[0] != generated[0] || merged[1] != generated[1] ||
		merged[2] != "DOMAIN-SUFFIX,custom.example,DIRECT" || merged[3] != "MATCH,REJECT" {
		t.Fatalf("unexpected merged rule order or terminal policy: %#v", merged)
	}
}

func TestMergeManagedProxySectionsPreservesCustomSettings(t *testing.T) {
	custom := `mode: global
mixed-port: 7890
dns:
  enable: true
proxies:
  - name: stale-proxy
    type: socks5
rules:
  - DOMAIN-SUFFIX,custom.example,DIRECT
  - MATCH,DIRECT
`
	generated := `mode: rule
mixed-port: 8080
proxies:
  - name: managed-proxy
    type: http
rules:
  - DOMAIN-SUFFIX,v2net.cc,DIRECT
  - DOMAIN,controller.example.com,DIRECT
  - MATCH,REJECT
`

	got, err := mergeManagedProxySections(custom, generated)
	if err != nil {
		t.Fatalf("合并全局配置失败: %v", err)
	}
	for _, want := range []string{"mode: global", "mixed-port: 7890", "enable: true", "managed-proxy", "DOMAIN-SUFFIX,v2net.cc,DIRECT", "DOMAIN,controller.example.com,DIRECT", "DOMAIN-SUFFIX,custom.example,DIRECT", "MATCH,REJECT"} {
		if !strings.Contains(got, want) {
			t.Errorf("合并配置缺少 %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "stale-proxy") || strings.Contains(got, "MATCH,DIRECT") || strings.Contains(got, "GEOIP,CN,DIRECT") {
		t.Fatalf("严格规则模式必须移除旧终结 MATCH/DIRECT 和大陆自动直连:\n%s", got)
	}
	if strings.Index(got, "DOMAIN-SUFFIX,v2net.cc,DIRECT") > strings.Index(got, "DOMAIN-SUFFIX,custom.example,DIRECT") ||
		strings.Index(got, "DOMAIN-SUFFIX,custom.example,DIRECT") > strings.Index(got, "MATCH,REJECT") {
		t.Fatalf("系统直连规则、自定义规则、最终 MATCH 顺序错误:\n%s", got)
	}
}

func TestMergeManagedProxySectionsRejectsInvalidOrEmptyYAML(t *testing.T) {
	generated := "mode: rule\nproxies: []\nrules: []\n"
	for _, custom := range []string{"not: [valid", "[]", ""} {
		if _, err := mergeManagedProxySections(custom, generated); err == nil {
			t.Errorf("全局配置 %q 应返回错误", custom)
		}
	}
}

func TestGetOrCreateMihomoSecretReusesConfiguredSecret(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "mihomo-secret-test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	app := &App{cfg: Config{MihomoSecret: "configured-secret"}, store: store}
	got, err := app.getOrCreateMihomoSecret("mihomo_secret_controller")
	if err != nil {
		t.Fatalf("getOrCreateMihomoSecret(): %v", err)
	}
	if got != "configured-secret" {
		t.Fatalf("secret = %q, want configured secret", got)
	}
	settings, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings(): %v", err)
	}
	if settings["mihomo_secret_controller"] != "configured-secret" {
		t.Fatalf("persisted secret = %q, want configured secret", settings["mihomo_secret_controller"])
	}
}

func TestBuildConfigForMachineExcludesUnboundProxy(t *testing.T) {
	proxies := []Proxy{
		{Name: "bound-proxy", Mode: "proxy", Type: "socks5", Server: "192.0.2.10", Port: 1080, MachineCode: "node-a", Enabled: true},
		{Name: "unbound-proxy", Mode: "proxy", Type: "socks5", Server: "192.0.2.11", Port: 1081, Enabled: true},
	}
	got, err := buildConfigFromProxies(proxies, "node-a", "test-secret")
	if err != nil {
		t.Fatalf("buildConfigFromProxies() error = %v", err)
	}
	if !strings.Contains(got, "bound-proxy") {
		t.Fatal("node-specific config should include its bound proxy")
	}
	if strings.Contains(got, "unbound-proxy") {
		t.Fatal("node-specific config must exclude unbound proxies")
	}
}

func TestBuildConfigSupportsExplicitGlobalAndUnboundProxies(t *testing.T) {
	proxies := []Proxy{
		{Name: "global-proxy", Mode: "proxy", Type: "socks5", Server: "192.0.2.10", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true},
		{Name: "bound-proxy", Mode: "proxy", Type: "socks5", Server: "192.0.2.11", Port: 1081, MachineCode: "node-a", Enabled: true},
		{Name: "unbound-proxy", Mode: "proxy", Type: "socks5", Server: "192.0.2.12", Port: 1082, Enabled: true},
	}
	nodeConfig, err := buildConfigFromProxies(proxies, "node-a", "test-secret")
	if err != nil {
		t.Fatalf("node config error = %v", err)
	}
	for _, want := range []string{"global-proxy", "bound-proxy"} {
		if !strings.Contains(nodeConfig, want) {
			t.Errorf("node config missing %q", want)
		}
	}
	if strings.Contains(nodeConfig, "unbound-proxy") {
		t.Fatal("node config must exclude unbound proxy")
	}
	globalConfig, err := buildConfigFromProxies(proxies, "", "test-secret")
	if err != nil {
		t.Fatalf("global config error = %v", err)
	}
	if !strings.Contains(globalConfig, "global-proxy") {
		t.Fatal("global config must include explicitly global proxy")
	}
	if strings.Contains(globalConfig, "bound-proxy") || strings.Contains(globalConfig, "unbound-proxy") {
		t.Fatal("global/default config must exclude machine-bound and unbound proxies")
	}
}

func TestBuildConfigRoutingModesAndControllerBypass(t *testing.T) {
	proxies := []Proxy{
		{Name: "proxy-a", Mode: "proxy", Type: "socks5", Server: "192.0.2.10", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true},
		{Name: "game-a", Mode: "game", Type: "socks5", Server: "192.0.2.11", Port: 1081, MachineCode: "__GLOBAL__", Enabled: true},
	}
	tests := []struct {
		mode string
		want []string
	}{
		{mode: "global", want: []string{"MATCH,proxy-a", "DOMAIN,controller.example.com,DIRECT"}},
		{mode: "split", want: []string{"MATCH,proxy-a"}},
		{mode: "rule", want: []string{"DOMAIN-SUFFIX,v2net.cc,DIRECT", "DOMAIN,controller.example.com,DIRECT", "PROCESS-NAME,smartdns,proxy-a", "MATCH,REJECT"}},
		{mode: "return", want: []string{"GEOIP,CN,proxy-a", "MATCH,DIRECT"}},
		{mode: "game", want: []string{"DOMAIN-SUFFIX,steampowered.com,game-a", "MATCH,DIRECT"}},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			got, err := buildConfigFromProxiesWithMode(proxies, "", "test-secret", tt.mode, "controller.example.com")
			if err != nil {
				t.Fatalf("build config: %v", err)
			}
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("mode %s missing %q:\\n%s", tt.mode, want, got)
				}
			}
			if tt.mode == "split" && strings.Contains(got, "GEOIP,CN,DIRECT") {
				t.Errorf("split mode must not force mainland destinations direct:\\n%s", got)
			}
			if tt.mode == "rule" {
				if strings.Contains(got, "MATCH,proxy-a") || strings.Contains(got, "MATCH,DIRECT") || strings.Contains(got, "GEOIP,CN,DIRECT") {
					t.Errorf("rule mode must reject unmatched traffic and must not add implicit proxy/direct fallback:\\n%s", got)
				}
				if strings.Index(got, "DOMAIN,controller.example.com,DIRECT") > strings.Index(got, "MATCH,REJECT") {
					t.Errorf("controller bypass must appear before terminal reject rule:\\n%s", got)
				}
				if strings.Index(got, "PROCESS-NAME,smartdns,proxy-a") > strings.Index(got, "MATCH,REJECT") {
					t.Errorf("SmartDNS encrypted upstream traffic must use the proxy before terminal reject:\\n%s", got)
				}
			}
		})
	}
	ipConfig, err := buildConfigFromProxiesWithMode(proxies, "", "test-secret", "global", "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ipConfig, "IP-CIDR,203.0.113.10/32,DIRECT,no-resolve") {
		t.Fatal("controller IPv4 must be explicitly routed direct")
	}
}

func TestStrictRuleModeIsDefault(t *testing.T) {
	if got := normalizeProxyRoutingMode(""); got != "rule" {
		t.Fatalf("empty routing mode = %q, want rule", got)
	}
	if got := normalizeProxyRoutingMode("unknown"); got != "rule" {
		t.Fatalf("unknown routing mode = %q, want rule", got)
	}
	if got := routingModeForMachine(nil, "node-without-proxy"); got != "rule" {
		t.Fatalf("routing mode without a matching proxy = %q, want rule", got)
	}
	generated, err := buildConfigFromProxies(nil, "node-without-proxy", "test-secret")
	if err != nil {
		t.Fatalf("build default config: %v", err)
	}
	if !strings.Contains(generated, "MATCH,REJECT") || strings.Contains(generated, "MATCH,DIRECT") {
		t.Fatalf("default config must reject unmatched traffic:\\n%s", generated)
	}
}

func TestStoreCreateProxyDefaultsToStrictRuleMode(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "proxy-default-mode.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	proxy := &Proxy{
		Name: "default-mode-proxy", Type: "socks5",
		Server: "192.0.2.20", Port: 1080, Enabled: true,
	}
	if err := store.CreateProxy(proxy); err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}
	if proxy.Mode != "rule" {
		t.Fatalf("stored proxy mode = %q, want rule", proxy.Mode)
	}
}

func TestRoutingModeForMachineUsesNodeMode(t *testing.T) {
	proxies := []Proxy{
		{Name: "node-a-proxy", Mode: "return", MachineCode: "node-a", Enabled: true},
		{Name: "node-b-proxy", Mode: "rule", MachineCode: "node-b", Enabled: true},
		{Name: "global-proxy", Mode: "game", MachineCode: "__GLOBAL__", Enabled: true},
		{Name: "legacy-proxy", Mode: "legacy", MachineCode: "node-legacy", Enabled: true},
	}
	if got := routingModeForMachine(proxies, "node-a"); got != "return" {
		t.Fatalf("node-a routing mode = %q, want return", got)
	}
	if got := routingModeForMachine(proxies, "node-b"); got != "rule" {
		t.Fatalf("node-b routing mode = %q, want rule", got)
	}
	if got := routingModeForMachine(proxies, ""); got != "game" {
		t.Fatalf("global routing mode = %q, want game", got)
	}
	if got := routingModeForMachine(proxies, "node-legacy"); got != "legacy" {
		t.Fatalf("legacy routing mode = %q, want legacy", got)
	}
}

func TestRoutingModeForMachineMixedProxyModesKeepStableFirstMode(t *testing.T) {
	proxies := []Proxy{
		{Name: "legacy-anchor", Mode: "split", MachineCode: "node-mixed", Enabled: true},
		{Name: "additional-rule-proxy", Mode: "rule", MachineCode: "node-mixed", Enabled: true},
	}
	if got := routingModeForMachine(proxies, "node-mixed"); got != "split" {
		t.Fatalf("mixed-mode node routing mode = %q, want stable first persisted mode split", got)
	}
	reordered := []Proxy{proxies[1], proxies[0]}
	if got := routingModeForMachine(reordered, "node-mixed"); got != "rule" {
		t.Fatalf("routing mode must follow persisted proxy order; got %q, want rule", got)
	}
}

func TestBuildConfigRoutesConfiguredDoHThroughProxy(t *testing.T) {
	proxies := []Proxy{{
		Name: "proxy-a", Mode: "proxy", Type: "socks5",
		Server: "192.0.2.10", Port: 1080, MachineCode: "__GLOBAL__", Enabled: true,
	}}
	got, err := buildConfigFromProxies(proxies, "", "test-secret")
	if err != nil {
		t.Fatalf("buildConfigFromProxies() error = %v", err)
	}
	for _, want := range []string{
		"listen: 127.0.0.1:5353",
		"fake-ip-range: 198.18.0.1/16",
		"DOMAIN-SUFFIX,v2net.cc,DIRECT",
		"DOMAIN-SUFFIX,dns.alidns.com,proxy-a",
		"DOMAIN-SUFFIX,doh.pub,proxy-a",
		"DOMAIN-SUFFIX,dns.cloudflare.com,proxy-a",
		"DOMAIN-SUFFIX,dns.google,proxy-a",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("generated config missing %q:\\n%s", want, got)
		}
	}
}

func TestBuildConfigWithoutProxyKeepsDNSBootstrapValid(t *testing.T) {
	got, err := buildConfigFromProxies(nil, "", "test-secret")
	if err != nil {
		t.Fatalf("buildConfigFromProxies() error = %v", err)
	}
	for _, want := range []string{"listen: 127.0.0.1:5353", "nameserver:", "223.5.5.5", "119.29.29.29", "DOMAIN-SUFFIX,v2net.cc,DIRECT"} {
		if !strings.Contains(got, want) {
			t.Fatalf("default DNS configuration missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "DOMAIN-SUFFIX,doh.pub,") {
		t.Fatalf("must not generate DNS proxy rules without an enabled proxy:\n%s", got)
	}
}

func TestBuildConfigIncludesTUNDNSDefaults(t *testing.T) {
	got, err := buildConfigFromProxies(nil, "", "test-secret")
	if err != nil {
		t.Fatalf("buildConfigFromProxies() error = %v", err)
	}
	for _, want := range []string{
		"enable: false",
		"stack: system",
		"auto-route: true",
		"auto-detect-interface: true",
		"enhanced-mode: fake-ip",
		"listen: 127.0.0.1:5353",
		"fake-ip-filter:",
		"'*.local'",
		"'geosite:private'",
		"'+.v2net.cc'",
		"default-nameserver:",
		"proxy-server-nameserver:",
		"fallback:",
		"dns-hijack:",
		"ipv6: false",
		"https://dns.cloudflare.com/dns-query",
		"https://dns.google/dns-query",
		"fallback-filter:",
		"geoip-code: CN",
		"223.5.5.5",
		"119.29.29.29",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("generated TUN/DNS config missing %q:\n%s", want, got)
		}
	}
}

func TestBuildConfigUsesSharedYAMLAnchorForSameProtocolAndServer(t *testing.T) {
	proxies := []Proxy{
		{Name: "node-443", Mode: "proxy", Type: "vless", Server: "1.2.3.4", Port: 443, MachineCode: "__GLOBAL__", Enabled: true,
			Extra: map[string]any{"uuid": "test-uuid", "network": "tcp", "tls": true, "servername": "example.com"}},
		{Name: "node-8443", Mode: "proxy", Type: "vless", Server: "1.2.3.4", Port: 8443, MachineCode: "__GLOBAL__", Enabled: true,
			Extra: map[string]any{"uuid": "test-uuid", "network": "tcp", "tls": true, "servername": "example.com"}},
		{Name: "node-2053", Mode: "proxy", Type: "vless", Server: "1.2.3.4", Port: 2053, MachineCode: "__GLOBAL__", Enabled: true,
			Extra: map[string]any{"uuid": "test-uuid", "network": "tcp", "tls": true, "servername": "example.com"}},
	}
	got, err := buildConfigFromProxies(proxies, "", "test-secret")
	if err != nil {
		t.Fatalf("build config: %v", err)
	}
	if !strings.Contains(got, "&s5m_shared_proxy") || !strings.Contains(got, "<<: *s5m_shared_proxy") {
		t.Fatalf("expected YAML merge anchor for equivalent proxies:\\n%s", got)
	}
	var decoded map[string]any
	if err := yaml.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("generated anchor YAML did not parse: %v\\n%s", err, got)
	}
	items, ok := decoded["proxies"].([]any)
	if !ok || len(items) != 3 {
		t.Fatalf("decoded proxies = %#v, want 3 entries", decoded["proxies"])
	}
	wantPorts := []int{443, 8443, 2053}
	wantNames := []string{"node-443", "node-8443", "node-2053"}
	for i, item := range items {
		p, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("proxy %d has type %T", i, item)
		}
		if p["name"] != wantNames[i] {
			t.Errorf("proxy %d name = %#v, want %q", i, p["name"], wantNames[i])
		}
		if p["port"] != wantPorts[i] {
			t.Errorf("proxy %d port = %#v, want %d", i, p["port"], wantPorts[i])
		}
		for key, want := range map[string]any{"type": "vless", "server": "1.2.3.4", "uuid": "test-uuid", "network": "tcp", "tls": true, "servername": "example.com"} {
			if p[key] != want {
				t.Errorf("proxy %d field %s = %#v, want %#v", i, key, p[key], want)
			}
		}
	}
}

func TestMarshalProxiesWithSharedAnchorFallsBackForDifferentProtocolOptions(t *testing.T) {
	proxies := []proxyOut{
		{Name: "vless-a", Type: "vless", Server: "1.2.3.4", Port: 443, Extra: map[string]any{"uuid": "uuid-a"}},
		{Name: "vless-b", Type: "vless", Server: "1.2.3.4", Port: 8443, Extra: map[string]any{"uuid": "uuid-b"}},
	}
	got, err := marshalProxiesWithSharedAnchor(proxies)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(got), "&s5m_shared_proxy") || strings.Contains(string(got), "<<:") {
		t.Fatalf("different credentials must not be merged through an anchor:\\n%s", got)
	}
	var decoded []map[string]any
	if err := yaml.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("fallback YAML invalid: %v", err)
	}
	if len(decoded) != 2 || decoded[0]["uuid"] != "uuid-a" || decoded[1]["uuid"] != "uuid-b" {
		t.Fatalf("fallback changed protocol options: %#v", decoded)
	}
}

func TestSyncAuthorizedNodeConfigsExpandsSharedProxyAnchors(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-anchor-expansion.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.UpdateSettings(map[string]string{
		"agent_machine_node-a":       "agent-token",
		"agent_mihomo_secret_node-a": "node-secret",
		"tun_enable":                 "true",
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	const existingYAML = "mixed-port: 7899\nsecret: keep-this-secret\ntun:\n  enable: false\n"
	if err := store.SaveNodeConfig("node-a", existingYAML); err != nil {
		t.Fatalf("SaveNodeConfig: %v", err)
	}

	for _, p := range []Proxy{
		{Name: "same-vless-443", Mode: "proxy", Type: "vless", Server: "192.0.2.10", Port: 443, MachineCode: "__GLOBAL__", Enabled: true,
			Extra: map[string]any{"uuid": "123e4567-e89b-12d3-a456-426614174000", "network": "tcp", "tls": true, "servername": "example.com"}},
		{Name: "same-vless-8443", Mode: "proxy", Type: "vless", Server: "192.0.2.10", Port: 8443, MachineCode: "__GLOBAL__", Enabled: true,
			Extra: map[string]any{"uuid": "123e4567-e89b-12d3-a456-426614174000", "network": "tcp", "tls": true, "servername": "example.com"}},
	} {
		proxy := p
		if err := store.CreateProxy(&proxy); err != nil {
			t.Fatalf("CreateProxy(%s): %v", proxy.Name, err)
		}
	}

	app := &App{store: store}
	if err := app.syncAuthorizedNodeConfigs(); err != nil {
		t.Fatalf("syncAuthorizedNodeConfigs: %v", err)
	}
	got, err := store.GetNodeConfig("node-a")
	if err != nil {
		t.Fatalf("GetNodeConfig: %v", err)
	}
	if got == nil {
		t.Fatal("node config missing after sync")
	}
	if strings.Contains(got.YAML, "mixed-port:") || strings.Contains(got.YAML, "&s5m_shared_proxy") || strings.Contains(got.YAML, "<<:") {
		t.Fatalf("saved per-node YAML should contain expanded proxy fields, not merge aliases:\n%s", got.YAML)
	}
	for _, want := range []string{
		"allow-lan: false",
		"secret: keep-this-secret",
		"same-vless-443",
		"same-vless-8443",
		"port: 443",
		"port: 8443",
		"uuid: 123e4567-e89b-12d3-a456-426614174000",
		"servername: example.com",
	} {
		if !strings.Contains(got.YAML, want) {
			t.Errorf("synced config lost %q:\n%s", want, got.YAML)
		}
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(got.YAML), &doc); err != nil {
		t.Fatalf("synced YAML invalid: %v", err)
	}
	proxies, ok := doc["proxies"].([]any)
	if !ok || len(proxies) != 2 {
		t.Fatalf("synced proxies = %#v, want 2 entries", doc["proxies"])
	}
	wantPorts := []int{443, 8443}
	wantNames := []string{"same-vless-443", "same-vless-8443"}
	if output := os.Getenv("S5M_MIHOMO_TEST_CONFIG"); output != "" {
		if err := os.WriteFile(output, []byte(got.YAML), 0o600); err != nil {
			t.Fatalf("write Mihomo integration config: %v", err)
		}
	}
	for i, raw := range proxies {
		proxy, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("proxy %d has type %T", i, raw)
		}
		if proxy["name"] != wantNames[i] || proxy["port"] != wantPorts[i] || proxy["uuid"] != "123e4567-e89b-12d3-a456-426614174000" {
			t.Errorf("proxy %d fields = %#v; want name=%q port=%d uuid=123e4567-e89b-12d3-a456-426614174000", i, proxy, wantNames[i], wantPorts[i])
		}
	}
}

func TestOpenStoreDefaultsTUNDisabled(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "tun-default.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	got, err := store.GetSetting("tun_enable")
	if err != nil {
		t.Fatalf("GetSetting(tun_enable): %v", err)
	}
	if got != "false" {
		t.Fatalf("tun_enable default = %q, want false", got)
	}
}

func TestRouteAgentDNSViaSmartDNSChangesOnlyPrimaryNameserver(t *testing.T) {
	input := `dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
  proxy-server-nameserver:
    - 119.29.29.29
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
tun:
  enable: false
`
	got, err := routeAgentDNSViaSmartDNS(input)
	if err != nil { t.Fatalf("routeAgentDNSViaSmartDNS: %v", err) }
	var config map[string]any
	if err := yaml.Unmarshal([]byte(got), &config); err != nil { t.Fatalf("decode result: %v", err) }
	dns := config["dns"].(map[string]any)
	if got := dns["nameserver"].([]any); len(got) != 1 || got[0] != "127.0.0.1:6053" {
		t.Fatalf("nameserver = %#v, want only local SmartDNS", got)
	}
	if got := dns["default-nameserver"].([]any); len(got) != 1 || got[0] != "223.5.5.5" {
		t.Fatalf("default-nameserver unexpectedly changed: %#v", got)
	}
	if got := dns["proxy-server-nameserver"].([]any); len(got) != 1 || got[0] != "119.29.29.29" {
		t.Fatalf("proxy-server-nameserver unexpectedly changed: %#v", got)
	}
}

func TestAgentHasHealthySmartDNSRequiresFreshProcessAndDNSProbe(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "smartdns-capability.db"))
	if err != nil { t.Fatalf("OpenStore: %v", err) }
	defer store.db.Close()
	app := &App{store: store}
	now := time.Now().Unix()
	healthy := map[string]any{
		"smartdns_available": true, "smartdns_running": true,
		"smartdns_dns_healthy": true, "received_at": now,
	}
	stale := map[string]any{
		"smartdns_available": true, "smartdns_running": true,
		"smartdns_dns_healthy": true, "received_at": now - int64(agentWSHeartbeatTTL.Seconds()) - 1,
	}
	future := map[string]any{
		"smartdns_available": true, "smartdns_running": true,
		"smartdns_dns_healthy": true, "received_at": now + 120,
	}
	cases := []struct{name string; status map[string]any; want bool}{
		{"missing", nil, false},
		{"binary only", map[string]any{"smartdns_available": true, "received_at": now}, false},
		{"running without probe", map[string]any{"smartdns_available": true, "smartdns_running": true, "received_at": now}, false},
		{"healthy and fresh", healthy, true},
		{"healthy but stale", stale, false},
		{"future timestamp", future, false},
		{"missing heartbeat timestamp", map[string]any{"smartdns_available": true, "smartdns_running": true, "smartdns_dns_healthy": true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := ""
			if tc.status != nil {
				data, marshalErr := json.Marshal(tc.status)
				if marshalErr != nil { t.Fatal(marshalErr) }
				raw = string(data)
			}
			if err := store.UpdateSettings(map[string]string{"agent_status_node-a": raw}); err != nil { t.Fatal(err) }
			if got := app.agentHasHealthySmartDNS("node-a"); got != tc.want {
				t.Fatalf("agentHasHealthySmartDNS() = %v, want %v", got, tc.want)
			}
		})
	}
}


func TestApplyAgentRuntimeDNSDoesNotMutateSourceAndFallsBack(t *testing.T) {
	source := "dns:\n  enable: true\n  nameserver:\n    - 1.1.1.1\n    - 8.8.8.8\n  default-nameserver:\n    - 223.5.5.5\n"
	healthy, err := applyAgentRuntimeDNS(source, true)
	if err != nil {
		t.Fatalf("apply healthy SmartDNS runtime DNS: %v", err)
	}
	if !strings.Contains(healthy, "127.0.0.1:6053") {
		t.Fatalf("healthy runtime config did not use local SmartDNS:\n%s", healthy)
	}
	if strings.Contains(source, "127.0.0.1:6053") {
		t.Fatal("runtime transformation mutated the persisted source string")
	}
	fallback, err := applyAgentRuntimeDNS(source, false)
	if err != nil {
		t.Fatalf("apply unhealthy SmartDNS fallback: %v", err)
	}
	if fallback != source {
		t.Fatalf("unhealthy SmartDNS must retain original DNS upstreams\nwant:\n%s\ngot:\n%s", source, fallback)
	}
}

func TestRestoreAgentDNSNameserverOnlyMigratesLegacySmartDNSValue(t *testing.T) {
	current := `dns:
  enable: true
  nameserver:
    - 127.0.0.1:6053
  default-nameserver:
    - 223.5.5.5
  proxy-server-nameserver:
    - 119.29.29.29
tun:
  enable: true
`
	baseline := `dns:
  enable: true
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
  default-nameserver:
    - 9.9.9.9
`
	got, changed, err := restoreAgentDNSNameserver(current, baseline)
	if err != nil || !changed { t.Fatalf("restore legacy DNS: changed=%v err=%v", changed, err) }
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(got), &doc); err != nil { t.Fatal(err) }
	dns := doc["dns"].(map[string]any)
	if got := dns["nameserver"].([]any); len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "8.8.8.8" { t.Fatalf("restored nameserver = %#v", got) }
	if got := dns["default-nameserver"].([]any); len(got) != 1 || got[0] != "223.5.5.5" { t.Fatalf("default-nameserver was overwritten: %#v", got) }
	if got := dns["proxy-server-nameserver"].([]any); len(got) != 1 || got[0] != "119.29.29.29" { t.Fatalf("proxy-server-nameserver was overwritten: %#v", got) }
	if tun, ok := doc["tun"].(map[string]any); !ok || tun["enable"] != true { t.Fatalf("unrelated TUN setting was not retained: %#v", doc["tun"]) }
}
func TestRestoreAgentDNSNameserverSkipsNonLegacyAndRejectsMissingFallback(t *testing.T) {
	ordinary := "dns:\n  nameserver:\n    - 8.8.8.8\n"
	got, changed, err := restoreAgentDNSNameserver(ordinary, "dns:\n  nameserver:\n    - 1.1.1.1\n")
	if err != nil || changed || got != ordinary { t.Fatalf("ordinary config changed: changed=%v err=%v got=%q", changed, err, got) }
	legacy := `dns:
  nameserver:
    - 127.0.0.1:6053
  enable: true
`
	if _, _, err := restoreAgentDNSNameserver(legacy, "dns:\n  enable: true\n"); err == nil { t.Fatal("missing fallback nameserver must fail safely") }
}


func TestRestoreAgentDNSNameserverIsIdempotentAndRejectsMalformedYAML(t *testing.T) {
	legacy := `dns:
  nameserver:
    - 127.0.0.1:6053
  enable: true
`
	baseline := `dns:
  nameserver:
    - 1.1.1.1
`
	first, changed, err := restoreAgentDNSNameserver(legacy, baseline)
	if err != nil || !changed { t.Fatalf("first migration: changed=%v err=%v", changed, err) }
	second, changed, err := restoreAgentDNSNameserver(first, baseline)
	if err != nil || changed || second != first { t.Fatalf("second migration must be stable: changed=%v err=%v", changed, err) }
	if _, _, err := restoreAgentDNSNameserver("dns: [unterminated", baseline); err == nil { t.Fatal("malformed current YAML must fail") }
	if _, _, err := restoreAgentDNSNameserver(legacy, "dns: [unterminated"); err == nil { t.Fatal("malformed baseline YAML must fail") }
}
