package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestAgentBindRequestsAreSerialized(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock := lockAgentBind()
			defer unlock()
			current := active.Add(1)
			for {
				previous := maximum.Load()
				if current <= previous || maximum.CompareAndSwap(previous, current) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			active.Add(-1)
		}()
	}
	wg.Wait()
	if got := maximum.Load(); got != 1 {
		t.Fatalf("maximum concurrent bind operations = %d, want 1", got)
	}
}

func TestAgentWebSocketRejectsStaleBindingGeneration(t *testing.T) {
	previous := agentBindingGeneration.Load()
	agentBindingGeneration.Store(previous + 1)
	t.Cleanup(func() { agentBindingGeneration.Store(previous) })

	if setAgentActiveWebSocket(nil, previous) {
		t.Fatal("websocket with stale binding generation must not become active")
	}
}

func TestStaleAgentSessionCleanupDoesNotClearNewSession(t *testing.T) {
	previousGeneration := agentBindingGeneration.Load()
	previousConnected := agentConnected.Load()
	oldConn := &websocket.Conn{}
	newConn := &websocket.Conn{}
	agentBindingGeneration.Store(previousGeneration + 1)
	agentConnected.Store(false)
	agentActiveWSMu.Lock()
	agentActiveWSConn = oldConn
	agentActiveWSMu.Unlock()
	t.Cleanup(func() {
		agentActiveWSMu.Lock()
		agentActiveWSConn = nil
		agentActiveWSMu.Unlock()
		agentBindingGeneration.Store(previousGeneration)
		agentConnected.Store(previousConnected)
	})

	generation := agentBindingGeneration.Load()
	if !setAgentActiveWebSocket(newConn, generation) {
		t.Fatal("new session should become active")
	}
	if !markAgentWebSocketConnected(newConn, generation) {
		t.Fatal("new session should become connected")
	}
	clearAgentActiveWebSocket(oldConn)
	if !agentConnected.Load() {
		t.Fatal("stale session cleanup must not clear the new session connected state")
	}
	agentActiveWSMu.Lock()
	active := agentActiveWSConn
	agentActiveWSMu.Unlock()
	if active != newConn {
		t.Fatal("stale session cleanup must not replace the active websocket")
	}
	clearAgentActiveWebSocket(newConn)
	if agentConnected.Load() {
		t.Fatal("cleanup of the current session must clear connected state")
	}
}

func TestAgentConnectedRequiresCurrentActiveWebSocket(t *testing.T) {
	previousGeneration := agentBindingGeneration.Load()
	previousConnected := agentConnected.Load()
	agentBindingGeneration.Store(previousGeneration + 1)
	agentConnected.Store(false)
	t.Cleanup(func() {
		agentActiveWSMu.Lock()
		agentActiveWSConn = nil
		agentActiveWSMu.Unlock()
		agentBindingGeneration.Store(previousGeneration)
		agentConnected.Store(previousConnected)
	})

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err == nil {
			defer conn.Close()
			_, _, _ = conn.ReadMessage()
		}
	}))
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial test websocket: %v", err)
	}
	defer conn.Close()

	generation := agentBindingGeneration.Load()
	if !setAgentActiveWebSocket(conn, generation) {
		t.Fatal("expected current websocket to become active")
	}
	if !markAgentWebSocketConnected(conn, generation) {
		t.Fatal("expected active websocket to mark agent connected")
	}
	if !agentConnected.Load() {
		t.Fatal("agentConnected must be true for the active session")
	}
	if markAgentWebSocketConnected(conn, generation-1) {
		t.Fatal("stale binding generation must not mark agent connected")
	}
	if !agentConnected.Load() {
		t.Fatal("rejected stale activation must not clear the current session state")
	}
	agentBindingGeneration.Add(1)
	closeAgentActiveWebSocketForRebind()
	if markAgentWebSocketConnected(conn, generation) {
		t.Fatal("rebound credentials must reject activation of the old socket")
	}
	if agentConnected.Load() {
		t.Fatal("rebind must immediately clear the old session connected state")
	}
}

func TestCloseAgentWebSocketForRebind(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	serverRead := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			serverRead <- err
			return
		}
		defer conn.Close()
		_, _, err = conn.ReadMessage()
		serverRead <- err
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial test websocket: %v", err)
	}
	generation := agentBindingGeneration.Load()
	if !setAgentActiveWebSocket(conn, generation) {
		t.Fatal("expected current binding generation to register websocket")
	}
	closeAgentActiveWebSocketForRebind()
	clearAgentActiveWebSocket(conn)

	select {
	case readErr := <-serverRead:
		closeErr, ok := readErr.(*websocket.CloseError)
		if !ok || closeErr.Code != websocket.CloseNormalClosure {
			t.Fatalf("server read error = %v, want normal websocket close", readErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("active websocket was not closed after rebind")
	}
}

func TestAgentRegistrationClientDoesNotFollowRedirectWithSecretBody(t *testing.T) {
	var redirectTargetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectTargetHits.Add(1)
	}))
	defer target.Close()

	const secret = "one-time-registration-secret"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read registration body: %v", err)
			return
		}
		if !strings.Contains(string(body), secret) {
			t.Errorf("origin did not receive expected registration secret")
		}
		w.Header().Set("Location", target.URL+"/capture")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	resp, err := newAgentRegistrationHTTPClient().Post(origin.URL, "application/json", strings.NewReader(`{"secret":"`+secret+`"}`))
	if err != nil {
		t.Fatalf("registration POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("registration status = %d, want %d", resp.StatusCode, http.StatusTemporaryRedirect)
	}
	if got := redirectTargetHits.Load(); got != 0 {
		t.Fatalf("registration secret was forwarded to redirect target %d times", got)
	}
}

func TestControllerWebSocketResponseErrorPreservesDetails(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		message   string
		want      string
	}{
		{name: "config error", operation: "配置请求", message: "读取节点配置失败", want: "主控端配置请求失败: 读取节点配置失败"},
		{name: "command error", operation: "命令请求", message: "读取待执行命令失败", want: "主控端命令请求失败: 读取待执行命令失败"},
		{name: "empty message", operation: "配置请求", message: "  ", want: "主控端配置请求失败: 主控端未提供错误详情"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := controllerWebSocketResponseError(tt.operation, tt.message)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("controllerWebSocketResponseError() = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestControllerConfigHashUsesExactPayloadBytes(t *testing.T) {
	payload := []byte("mixed-port: 7890\nsecret: test-secret\n\n")
	want := fmt.Sprintf("%x", sha256.Sum256(payload))
	if got := controllerConfigHash(payload); got != want {
		t.Fatalf("controllerConfigHash() = %q, want exact-byte hash %q", got, want)
	}
	trimmedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.TrimSpace(string(payload)))))
	if controllerConfigHash(payload) == trimmedHash {
		t.Fatal("trailing whitespace must remain part of the exact payload hash")
	}
}

func TestAtomicWriteFileReplacesFileWithSyncedPrivateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "controller-config.yaml")
	if err := os.WriteFile(path, []byte("secret: old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	want := []byte("secret: new\ntun:\n  enable: true\n")
	if err := atomicWriteFile(path, want, 0600); err != nil {
		t.Fatalf("atomicWriteFile() error = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("file = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("file mode = %o, want 600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "controller-config.yaml" {
		t.Fatalf("unexpected temporary files after atomic write: %#v", entries)
	}
}

func TestControllerConfigNeedsApplyAfterInterruptedCommit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("MIHOMO_HOME", home)
	payload := []byte("mixed-port: 7890\nsecret: local-secret\n")
	if err := os.WriteFile(mihomoConfigPath(), payload, 0600); err != nil {
		t.Fatal(err)
	}
	if !controllerConfigNeedsApply(payload) {
		t.Fatal("missing controller hash must require reload even when runtime YAML matches")
	}
	if err := writeControllerConfig(payload); err != nil {
		t.Fatal(err)
	}
	if controllerConfigNeedsApply(payload) {
		t.Fatal("matching committed controller payload must not require reload")
	}
	changed := []byte("mixed-port: 7891\nsecret: local-secret\n")
	if !controllerConfigNeedsApply(changed) {
		t.Fatal("different controller payload must require reload")
	}
}

func TestPersistControllerConfigAfterReloadOnlyCommitsAfterSuccess(t *testing.T) {
	payload := []byte("mixed-port: 7890\nsecret: test-secret\n")
	persisted := false
	reloadErr := errors.New("simulated Mihomo reload failure")
	err := persistControllerConfigAfterReload(payload, func() error {
		return reloadErr
	}, func([]byte) error {
		persisted = true
		return nil
	})
	if !errors.Is(err, reloadErr) {
		t.Fatalf("error = %v, want reload error", err)
	}
	if persisted {
		t.Fatal("controller config hash must not be committed when reload fails")
	}

	err = persistControllerConfigAfterReload(payload, func() error {
		return nil
	}, func(got []byte) error {
		persisted = true
		if string(got) != string(payload) {
			t.Fatalf("persisted payload = %q, want exact bytes %q", got, payload)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("persistControllerConfigAfterReload() error = %v", err)
	}
	if !persisted {
		t.Fatal("controller config hash was not committed after successful reload")
	}
}

func TestCentralHostname(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://foodflow.v2net.cc", "foodflow.v2net.cc"},
		{"https://foodflow.v2net.cc:8443/path", "foodflow.v2net.cc"},
		{"https://[2001:db8::1]:8443", "2001:db8::1"},
		{"not a url", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := centralHostname(tt.input); got != tt.want {
			t.Errorf("centralHostname(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestAddCentralRouteExclusionsWithIPLiteral(t *testing.T) {
	t.Setenv("MIHOMO_HOME", t.TempDir())
	cfg := map[string]interface{}{
		"tun": map[string]interface{}{
			"enable":                true,
			"route-exclude-address": []interface{}{"192.0.2.7/32"},
		},
	}
	changed, err := addCentralRouteExclusions(cfg, "https://198.51.100.10")
	if err != nil {
		t.Fatalf("addCentralRouteExclusions() error = %v", err)
	}
	if !changed {
		t.Fatal("expected a new controller IP exclusion")
	}
	tun := cfg["tun"].(map[string]interface{})
	got := tun["route-exclude-address"].([]interface{})
	want := []string{"192.0.2.7/32", "198.51.100.10/32"}
	if len(got) != len(want) {
		t.Fatalf("route exclusions = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("route exclusions = %#v, want %#v", got, want)
		}
	}
	changed, err = addCentralRouteExclusions(cfg, "https://198.51.100.10")
	if err != nil {
		t.Fatalf("idempotent addCentralRouteExclusions() error = %v", err)
	}
	if changed {
		t.Fatal("repeated controller IP should not create duplicate exclusion")
	}
}

func TestSetCentralRouteExclusionsRemovesStaleManagedCIDRs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MIHOMO_HOME", dir)
	if err := writeManagedRouteCIDRs([]string{"198.51.100.10/32"}); err != nil {
		t.Fatalf("write managed route CIDRs: %v", err)
	}
	cfg := map[string]interface{}{
		"tun": map[string]interface{}{
			"enable": true,
			"route-exclude-address": []interface{}{
				"198.51.100.10/32",
				"192.0.2.7/32",
			},
		},
	}
	cidrs, changed, err := setCentralRouteExclusions(cfg, "https://203.0.113.20")
	if err != nil {
		t.Fatalf("setCentralRouteExclusions() error = %v", err)
	}
	if !changed {
		t.Fatal("expected stale managed CIDR to be replaced")
	}
	if len(cidrs) != 1 || cidrs[0] != "203.0.113.20/32" {
		t.Fatalf("managed CIDRs = %#v, want current controller IP", cidrs)
	}
	got := cfg["tun"].(map[string]interface{})["route-exclude-address"].([]interface{})
	want := []interface{}{"192.0.2.7/32", "203.0.113.20/32"}
	if len(got) != len(want) {
		t.Fatalf("route exclusions = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("route exclusions = %#v, want %#v", got, want)
		}
	}
}

func TestResolvedCentralRouteCIDRsRejectsInvalidURL(t *testing.T) {
	if _, err := resolvedCentralRouteCIDRs("not a url"); err == nil {
		t.Fatal("expected invalid controller URL to be rejected")
	}
}

func TestExpectedMihomoRules(t *testing.T) {
	config := []byte("rules:\n  - GEOIP,CN,DIRECT\n  - DOMAIN-SUFFIX,example.com,Proxy\n  - IP-CIDR,192.0.2.0/24,DIRECT,no-resolve\n  - MATCH,Proxy\n")
	got, err := expectedMihomoRules(config)
	if err != nil {
		t.Fatalf("expectedMihomoRules() error = %v", err)
	}
	want := []mihomoRuntimeRule{
		{Type: "GEOIP", Payload: "CN", Proxy: "DIRECT"},
		{Type: "DOMAIN-SUFFIX", Payload: "example.com", Proxy: "Proxy"},
		{Type: "IP-CIDR", Payload: "192.0.2.0/24", Proxy: "DIRECT"},
		{Type: "MATCH", Payload: "", Proxy: "Proxy"},
	}
	if len(got) != len(want) {
		t.Fatalf("rules = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rule[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
	if _, err := expectedMihomoRules([]byte("rules: []\n")); err == nil {
		t.Fatal("expected empty rules to be rejected")
	}
	if _, err := expectedMihomoRules([]byte("rules:\n  - invalid\n")); err == nil {
		t.Fatal("expected malformed rule to be rejected")
	}
}

func TestNormalizeMihomoRuleType(t *testing.T) {
	cases := map[string]string{
		"DOMAIN-SUFFIX":  "domainsuffix",
		"DomainSuffix":   "domainsuffix",
		"IP-CIDR":        "ipcidr",
		"IpCidr":         "ipcidr",
		"DOMAIN_KEYWORD": "domainkeyword",
		"DomainKeyword":  "domainkeyword",
		" MATCH ":        "match",
	}
	for input, want := range cases {
		if got := normalizeMihomoRuleType(input); got != want {
			t.Errorf("normalizeMihomoRuleType(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCompareMihomoRuntimeRulesAcceptsMihomoAPITypeNames(t *testing.T) {
	expected := []mihomoRuntimeRule{
		{Type: "DOMAIN-SUFFIX", Payload: "v2net.cc", Proxy: "DIRECT"},
		{Type: "IP-CIDR", Payload: "192.0.2.1/32", Proxy: "DIRECT"},
		{Type: "MATCH", Proxy: "Proxy"},
	}
	actual := []mihomoRuntimeRule{
		{Type: "DomainSuffix", Payload: "v2net.cc", Proxy: "DIRECT"},
		{Type: "IpCidr", Payload: "192.0.2.1/32", Proxy: "DIRECT"},
		{Type: "Match", Proxy: "Proxy"},
	}
	if err := compareMihomoRuntimeRules(expected, actual); err != nil {
		t.Fatalf("equivalent API rule names rejected: %v", err)
	}
}

func TestCompareMihomoRuntimeRules(t *testing.T) {
	baseRules := []mihomoRuntimeRule{
		{Type: "GEOIP", Payload: "CN", Proxy: "DIRECT"},
		{Type: "GEOIP", Payload: "US", Proxy: "Proxy"},
	}

	tests := []struct {
		name            string
		expected        []mihomoRuntimeRule
		actual          []mihomoRuntimeRule
		wantErrContains string
	}{
		{
			name:     "accepts case-insensitive GEOIP country codes and API rule types",
			expected: baseRules,
			actual: []mihomoRuntimeRule{
				{Type: "GeoIP", Payload: "cn", Proxy: "DIRECT"},
				{Type: "geoip", Payload: "us", Proxy: "Proxy"},
			},
		},
		{
			name: "rejects a different GEOIP country code",
			expected: []mihomoRuntimeRule{
				{Type: "GEOIP", Payload: "CN", Proxy: "DIRECT"},
			},
			actual: []mihomoRuntimeRule{
				{Type: "GeoIP", Payload: "US", Proxy: "DIRECT"},
			},
			wantErrContains: "不匹配",
		},
		{
			name: "keeps non-GEOIP payloads case-sensitive",
			expected: []mihomoRuntimeRule{
				{Type: "DOMAIN", Payload: "Example.COM", Proxy: "DIRECT"},
			},
			actual: []mihomoRuntimeRule{
				{Type: "Domain", Payload: "example.com", Proxy: "DIRECT"},
			},
			wantErrContains: "不匹配",
		},
		{
			name: "keeps proxy policy names case-sensitive",
			expected: []mihomoRuntimeRule{
				{Type: "GEOIP", Payload: "CN", Proxy: "Proxy"},
			},
			actual: []mihomoRuntimeRule{
				{Type: "GeoIP", Payload: "cn", Proxy: "proxy"},
			},
			wantErrContains: "不匹配",
		},
		{
			name:            "rejects rules in a different order",
			expected:        baseRules,
			actual:          []mihomoRuntimeRule{baseRules[1], baseRules[0]},
			wantErrContains: "不匹配",
		},
		{
			name:            "rejects a different rule count",
			expected:        baseRules,
			actual:          baseRules[:1],
			wantErrContains: "数量不匹配",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := compareMihomoRuntimeRules(tt.expected, tt.actual)
			if tt.wantErrContains == "" {
				if err != nil {
					t.Fatalf("compareMihomoRuntimeRules() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("compareMihomoRuntimeRules() error = nil, want error containing %q", tt.wantErrContains)
			}
			if !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Fatalf("compareMihomoRuntimeRules() error = %q, want it to contain %q", err, tt.wantErrContains)
			}
		})
	}
}

func TestCompareMihomoRuntimeRulesKeepsOtherPayloadsCaseSensitive(t *testing.T) {
	expected := []mihomoRuntimeRule{
		{Type: "DOMAIN", Payload: "Example.COM", Proxy: "DIRECT"},
	}
	actual := []mihomoRuntimeRule{
		{Type: "Domain", Payload: "example.com", Proxy: "DIRECT"},
	}
	if err := compareMihomoRuntimeRules(expected, actual); err == nil {
		t.Fatal("non-GEOIP payload case differences must remain detectable")
	}
}

func TestCompareMihomoRuntimeRulesRejectsDifferentGeoIPCountryCodes(t *testing.T) {
	expected := []mihomoRuntimeRule{{Type: "GEOIP", Payload: "CN", Proxy: "DIRECT"}}
	actual := []mihomoRuntimeRule{{Type: "GeoIP", Payload: "US", Proxy: "DIRECT"}}
	if err := compareMihomoRuntimeRules(expected, actual); err == nil {
		t.Fatal("different GEOIP country codes must not be treated as equivalent")
	}
}

func TestCompareMihomoRuntimeRulesKeepsProxyNamesCaseSensitive(t *testing.T) {
	expected := []mihomoRuntimeRule{{Type: "GEOIP", Payload: "CN", Proxy: "Proxy"}}
	actual := []mihomoRuntimeRule{{Type: "GeoIP", Payload: "cn", Proxy: "proxy"}}
	if err := compareMihomoRuntimeRules(expected, actual); err == nil {
		t.Fatal("proxy policy names must remain case-sensitive")
	}
}

func TestCompareMihomoRuntimeRulesStillRequiresSameOrderAndCount(t *testing.T) {
	expected := []mihomoRuntimeRule{
		{Type: "GEOIP", Payload: "CN", Proxy: "DIRECT"},
		{Type: "GEOIP", Payload: "US", Proxy: "DIRECT"},
	}
	reversed := []mihomoRuntimeRule{expected[1], expected[0]}
	if err := compareMihomoRuntimeRules(expected, reversed); err == nil {
		t.Fatal("rule order differences must remain detectable")
	}
	if err := compareMihomoRuntimeRules(expected, expected[:1]); err == nil {
		t.Fatal("rule count differences must remain detectable")
	}
}

func TestRollbackAndVerifyConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("secret: new\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".previous", []byte("secret: old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	reloaded, verified := false, false
	err := rollbackAndVerifyConfig(path, func() error {
		reloaded = true
		return nil
	}, func(data []byte) error {
		verified = true
		if !strings.Contains(string(data), "secret: old") {
			t.Fatal("restored config not passed to verifier")
		}
		return nil
	})
	if err != nil || !reloaded || !verified {
		t.Fatalf("err=%v reloaded=%v verified=%v", err, reloaded, verified)
	}
}

func TestRollbackConfigFromPaths(t *testing.T) {
	t.Run("restores previous config", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		current := []byte("rules:\\n  - MATCH,NewProxy\\n")
		previous := []byte("rules:\\n  - MATCH,OldProxy\\n")
		if err := os.WriteFile(path, current, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".previous", previous, 0600); err != nil {
			t.Fatal(err)
		}
		if err := rollbackConfigFromPaths(path); err != nil {
			t.Fatalf("rollback: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(previous) {
			t.Fatalf("restored config = %q, want %q", got, previous)
		}
	})
	t.Run("missing backup preserves current config", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		current := []byte("rules:\\n  - MATCH,Current\\n")
		if err := os.WriteFile(path, current, 0600); err != nil {
			t.Fatal(err)
		}
		if err := rollbackConfigFromPaths(path); err == nil {
			t.Fatal("expected missing backup error")
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(current) {
			t.Fatalf("current config changed: %q", got)
		}
	})
	t.Run("empty backup preserves current config", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		current := []byte("rules:\\n  - MATCH,Current\\n")
		if err := os.WriteFile(path, current, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".previous", nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := rollbackConfigFromPaths(path); err == nil {
			t.Fatal("expected empty backup error")
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(current) {
			t.Fatalf("current config changed: %q", got)
		}
	})
}

func TestPersistControllerConfigAfterReload(t *testing.T) {
	config := []byte("candidate-config")
	t.Run("reload failure does not persist hash", func(t *testing.T) {
		persistCalled := false
		wantErr := errors.New("runtime rules mismatch")
		err := persistControllerConfigAfterReload(config, func() error { return wantErr }, func([]byte) error {
			persistCalled = true
			return nil
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("error = %v, want %v", err, wantErr)
		}
		if persistCalled {
			t.Fatal("controller config hash persisted after failed runtime verification")
		}
	})
	t.Run("successful reload persists exact config", func(t *testing.T) {
		var persisted []byte
		err := persistControllerConfigAfterReload(config, func() error { return nil }, func(got []byte) error {
			persisted = append([]byte(nil), got...)
			return nil
		})
		if err != nil {
			t.Fatalf("persist: %v", err)
		}
		if string(persisted) != string(config) {
			t.Fatalf("persisted = %q, want %q", persisted, config)
		}
	})
}

func TestVerifyMihomoRuntimeRules(t *testing.T) {
	config := []byte("rules:\n  - GEOIP,CN,DIRECT\n  - MATCH,Proxy\n")
	tests := []struct {
		name     string
		status   int
		body     string
		wantErr  bool
		wantAuth bool
	}{
		{name: "exact active rules", status: http.StatusOK, body: `{"rules":[{"type":"GEOIP","payload":"CN","proxy":"DIRECT"},{"type":"MATCH","payload":"","proxy":"Proxy"}]}`},
		{name: "wrong order", status: http.StatusOK, body: `{"rules":[{"type":"MATCH","payload":"","proxy":"Proxy"},{"type":"GEOIP","payload":"CN","proxy":"DIRECT"}]}`, wantErr: true},
		{name: "wrong target", status: http.StatusOK, body: `{"rules":[{"type":"GEOIP","payload":"CN","proxy":"DIRECT"},{"type":"MATCH","payload":"","proxy":"DIRECT"}]}`, wantErr: true},
		{name: "unauthorized", status: http.StatusUnauthorized, body: `{"message":"Unauthorized"}`, wantErr: true, wantAuth: true},
		{name: "malformed response", status: http.StatusOK, body: `not-json`, wantErr: true},
		{name: "missing rules", status: http.StatusOK, body: `{}`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/rules" || r.Method != http.MethodGet {
					t.Errorf("request = %s %s, want GET /rules", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer test-secret" {
					t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
				}
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer server.Close()
			err := verifyMihomoRuntimeRules(server.Client(), server.URL, "test-secret", config)
			if (err != nil) != tt.wantErr {
				t.Fatalf("verifyMihomoRuntimeRules() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMihomoSecretCandidates(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/config.yaml"
	previousPath := configPath + ".previous"

	if err := os.WriteFile(previousPath, []byte("secret: old-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("secret: \"new-secret\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := mihomoSecretCandidates(configPath)
	if err != nil {
		t.Fatalf("mihomoSecretCandidates() error = %v", err)
	}
	if len(got) != 2 || got[0] != "old-secret" || got[1] != "new-secret" {
		t.Fatalf("secret candidates = %#v, want previous then current", got)
	}

	if err := os.WriteFile(previousPath, []byte("secret: same-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("secret: same-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = mihomoSecretCandidates(configPath)
	if err != nil {
		t.Fatalf("deduplicated candidates returned error: %v", err)
	}
	if len(got) != 1 || got[0] != "same-secret" {
		t.Fatalf("duplicate secret candidates = %#v, want one unique secret", got)
	}

	if err := os.WriteFile(configPath, []byte("secret: \"\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(previousPath); err != nil {
		t.Fatal(err)
	}
	if _, err := mihomoSecretCandidates(configPath); err == nil {
		t.Fatal("expected error when no valid secret exists")
	}
}

func TestHostnameHandler(t *testing.T) {
	t.Setenv("S5M_HOSTNAME", "edge-node-01")
	req := httptest.NewRequest(http.MethodGet, "/api/hostname", nil)
	rec := httptest.NewRecorder()
	hostnameHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/hostname status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode hostname response: %v", err)
	}
	if payload["hostname"] != "edge-node-01" {
		t.Fatalf("hostname = %q, want configured host hostname", payload["hostname"])
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}

	post := httptest.NewRequest(http.MethodPost, "/api/hostname", nil)
	postRec := httptest.NewRecorder()
	hostnameHandler(postRec, post)
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/hostname status = %d, want %d", postRec.Code, http.StatusMethodNotAllowed)
	}
	if got := postRec.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("Allow = %q, want GET", got)
	}
}

func TestValidateCentralURL(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		want      string
		ok        bool
		allowHTTP bool
	}{
		{name: "https", in: " https://controller.example.com/ ", want: "https://controller.example.com", ok: true},
		{name: "http rejected by default", in: "http://192.0.2.10:8080", ok: false},
		{name: "http explicit trusted-network opt-in", in: "http://192.0.2.10:8080", want: "http://192.0.2.10:8080", ok: true, allowHTTP: true},
		{name: "missing scheme", in: "controller.example.com", ok: false},
		{name: "unsupported scheme", in: "ftp://controller.example.com", ok: false},
		{name: "missing host", in: "https://", ok: false},
		{name: "userinfo", in: "https://user:pass@controller.example.com", ok: false},
		{name: "query", in: "https://controller.example.com?token=x", ok: false},
		{name: "fragment", in: "https://controller.example.com#fragment", ok: false},
		{name: "newline", in: "https://controller.example.com\r\nX-Injected: yes", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("S5M_ALLOW_INSECURE_HTTP", "")
			if tt.allowHTTP {
				t.Setenv("S5M_ALLOW_INSECURE_HTTP", "1")
			}
			got, err := validateCentralURL(tt.in)
			if tt.ok {
				if err != nil {
					t.Fatalf("expected valid URL, got error: %v", err)
				}
				if got != tt.want {
					t.Fatalf("URL = %q, want %q", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected invalid URL %q to be rejected; got %q", tt.in, got)
			}
		})
	}
}

func TestNormalizeCentralURLInputDefaultsBareHostToHTTPS(t *testing.T) {
	t.Setenv("S5M_ALLOW_INSECURE_HTTP", "")
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "bare domain", in: "controller.example.com", want: "https://controller.example.com", ok: true},
		{name: "bare IPv4 with port", in: "192.0.2.10:8443", want: "https://192.0.2.10:8443", ok: true},
		{name: "explicit HTTPS", in: "https://controller.example.com/", want: "https://controller.example.com", ok: true},
		{name: "HTTP rejected without opt-in", in: "http://controller.example.com", ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeCentralURLInput(tc.in)
			if tc.ok {
				if err != nil || got != tc.want {
					t.Fatalf("normalizeCentralURLInput(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("normalizeCentralURLInput(%q) should reject HTTP without opt-in", tc.in)
			}
		})
	}
}

func TestValidateKernelUpdateCommand(t *testing.T) {
	tests := []struct {
		name    string
		version string
		sha256  string
		wantErr bool
	}{
		{name: "valid", version: "v1.19.31", sha256: strings.Repeat("a", 64)},
		{name: "missing v prefix", version: "1.19.31", sha256: strings.Repeat("a", 64), wantErr: true},
		{name: "version injection", version: "v1.19.31/../../latest", sha256: strings.Repeat("a", 64), wantErr: true},
		{name: "prerelease unsupported", version: "v1.19.31-rc.1", sha256: strings.Repeat("a", 64), wantErr: true},
		{name: "short checksum", version: "v1.19.31", sha256: "abcd", wantErr: true},
		{name: "non hex checksum", version: "v1.19.31", sha256: strings.Repeat("z", 64), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKernelUpdateCommand(agentCommand{Version: tt.version, SHA256: tt.sha256})
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateKernelUpdateCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateMihomoConfigYAML(t *testing.T) {
	valid := []byte("mixed-port: 7890\nsecret: test-secret\ntun:\n  enable: false\ndns:\n  enable: true\n  nameserver:\n    - 1.1.1.1\n")
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "valid full config", data: valid},
		{name: "empty", data: []byte(""), wantErr: true},
		{name: "malformed yaml", data: []byte("tun: ["), wantErr: true},
		{name: "empty document", data: []byte("---\n"), wantErr: true},
		{name: "missing secret", data: []byte("tun: {}\ndns: {}\n"), wantErr: true},
		{name: "blank secret", data: []byte("secret: '  '\ntun: {}\ndns: {}\n"), wantErr: true},
		{name: "missing tun", data: []byte("secret: test\ndns: {}\n"), wantErr: true},
		{name: "tun wrong type", data: []byte("secret: test\ntun: false\ndns: {}\n"), wantErr: true},
		{name: "missing dns", data: []byte("secret: test\ntun: {}\n"), wantErr: true},
		{name: "dns wrong type", data: []byte("secret: test\ntun: {}\ndns: true\n"), wantErr: true},
		{name: "over size limit", data: append(valid, []byte(strings.Repeat(" ", 2*1024*1024))...), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateMihomoConfigYAML(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateMihomoConfigYAML() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewMihomoRestartRequest(t *testing.T) {
	req, err := newMihomoRestartRequest("test-secret")
	if err != nil {
		t.Fatalf("newMihomoRestartRequest() error = %v", err)
	}
	if req.Method != http.MethodPost {
		t.Fatalf("restart method = %q, want %q", req.Method, http.MethodPost)
	}
	if req.URL.String() != "http://127.0.0.1:8088/restart" {
		t.Fatalf("restart URL = %q", req.URL.String())
	}
	if got := req.Header.Get("Authorization"); got != "Bearer test-secret" {
		t.Fatalf("Authorization = %q, want bearer secret", got)
	}
}

func TestMihomoVersionMatches(t *testing.T) {
	tests := []struct {
		name, actual, expected string
		want                   bool
	}{
		{name: "exact", actual: "1.19.31", expected: "1.19.31", want: true},
		{name: "prefix v", actual: "v1.19.31", expected: "1.19.31", want: true},
		{name: "both prefix v", actual: "v1.19.31", expected: "v1.19.31", want: true},
		{name: "different version", actual: "1.19.30", expected: "1.19.31"},
		{name: "empty actual", actual: "", expected: "1.19.31"},
		{name: "empty expected", actual: "1.19.31", expected: ""},
		{name: "suffix mismatch", actual: "1.19.31-dev", expected: "1.19.31"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mihomoVersionMatches(tt.actual, tt.expected); got != tt.want {
				t.Fatalf("mihomoVersionMatches(%q, %q) = %v, want %v", tt.actual, tt.expected, got, tt.want)
			}
		})
	}
}

func TestReplaceFileAtomically(t *testing.T) {
	t.Run("replaces destination with backup", func(t *testing.T) {
		dir := t.TempDir()
		destination := filepath.Join(dir, "mihomo")
		source := filepath.Join(dir, "mihomo.previous")
		if err := os.WriteFile(destination, []byte("broken-new-binary"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source, []byte("known-good-old-binary"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := replaceFileAtomically(source, destination); err != nil {
			t.Fatalf("replaceFileAtomically() error = %v", err)
		}
		got, err := os.ReadFile(destination)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "known-good-old-binary" {
			t.Fatalf("destination = %q, want old backup content", got)
		}
		if _, err := os.Stat(source); !os.IsNotExist(err) {
			t.Fatalf("backup source should be moved, stat error = %v", err)
		}
	})
	t.Run("keeps destination when backup is missing", func(t *testing.T) {
		dir := t.TempDir()
		destination := filepath.Join(dir, "mihomo")
		if err := os.WriteFile(destination, []byte("current-binary"), 0755); err != nil {
			t.Fatal(err)
		}
		err := replaceFileAtomically(filepath.Join(dir, "missing.previous"), destination)
		if err == nil {
			t.Fatal("expected error for missing backup")
		}
		got, readErr := os.ReadFile(destination)
		if readErr != nil {
			t.Fatalf("destination was lost after failed replacement: %v", readErr)
		}
		if string(got) != "current-binary" {
			t.Fatalf("destination = %q, want current binary unchanged", got)
		}
	})
}

func TestRestoreMihomoKernelWithRestart(t *testing.T) {
	restartFailure := errors.New("controller connection refused")

	t.Run("restores old binary before restart", func(t *testing.T) {
		dir := t.TempDir()
		binaryPath := filepath.Join(dir, "mihomo")
		backupPath := binaryPath + ".previous"
		if err := os.WriteFile(binaryPath, []byte("bad-new-binary"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(backupPath, []byte("good-old-binary"), 0755); err != nil {
			t.Fatal(err)
		}
		restartCalled := false
		err := restoreMihomoKernelWithRestart(binaryPath, backupPath, func() error {
			restartCalled = true
			got, readErr := os.ReadFile(binaryPath)
			if readErr != nil {
				return readErr
			}
			if string(got) != "good-old-binary" {
				return errors.New("old binary was not restored before restart")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("restoreMihomoKernelWithRestart() error = %v", err)
		}
		if !restartCalled {
			t.Fatal("restart callback was not called")
		}
	})
	t.Run("reports restart failure after restoring old binary", func(t *testing.T) {
		dir := t.TempDir()
		binaryPath := filepath.Join(dir, "mihomo")
		backupPath := binaryPath + ".previous"
		if err := os.WriteFile(binaryPath, []byte("bad-new-binary"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(backupPath, []byte("good-old-binary"), 0755); err != nil {
			t.Fatal(err)
		}
		err := restoreMihomoKernelWithRestart(binaryPath, backupPath, func() error {
			return restartFailure
		})
		if !errors.Is(err, restartFailure) {
			t.Fatalf("error = %v, want wrapped restart failure", err)
		}
		got, readErr := os.ReadFile(binaryPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(got) != "good-old-binary" {
			t.Fatalf("binary = %q, want restored old binary", got)
		}
	})
	t.Run("preserves current binary if backup is missing", func(t *testing.T) {
		dir := t.TempDir()
		binaryPath := filepath.Join(dir, "mihomo")
		if err := os.WriteFile(binaryPath, []byte("current-binary"), 0755); err != nil {
			t.Fatal(err)
		}
		restartCalled := false
		err := restoreMihomoKernelWithRestart(binaryPath, binaryPath+".previous", func() error {
			restartCalled = true
			return nil
		})
		if err == nil {
			t.Fatal("expected error for missing backup")
		}
		if restartCalled {
			t.Fatal("restart must not be requested if file restoration fails")
		}
		got, readErr := os.ReadFile(binaryPath)
		if readErr != nil || string(got) != "current-binary" {
			t.Fatalf("current binary not preserved: content=%q error=%v", got, readErr)
		}
	})
}

func TestVerifyKernelUpgrade(t *testing.T) {
	restartFailure := errors.New("restart connection closed")
	healthFailure := errors.New("version health check timed out")
	rollbackFailure := errors.New("restore failed")

	tests := []struct {
		name         string
		restartErr   error
		healthErr    error
		rollbackErr  error
		wantErr      bool
		wantRollback bool
		wantErrParts []string
	}{
		{
			name:       "restart transport error but new version healthy",
			restartErr: restartFailure,
		},
		{
			name:         "health check fails and rollback succeeds",
			healthErr:    healthFailure,
			wantErr:      true,
			wantRollback: true,
			wantErrParts: []string{"健康检查失败", "已恢复旧内核"},
		},
		{
			name:         "health and rollback both fail",
			healthErr:    healthFailure,
			rollbackErr:  rollbackFailure,
			wantErr:      true,
			wantRollback: true,
			wantErrParts: []string{"健康检查失败", "恢复旧内核失败", "restore failed"},
		},
		{
			name:         "restart and health fail but rollback succeeds",
			restartErr:   restartFailure,
			healthErr:    healthFailure,
			wantErr:      true,
			wantRollback: true,
			wantErrParts: []string{"重启请求返回错误", "健康检查", "已恢复旧内核"},
		},
		{
			name:         "restart fails and rollback fails",
			restartErr:   restartFailure,
			healthErr:    healthFailure,
			rollbackErr:  rollbackFailure,
			wantErr:      true,
			wantRollback: true,
			wantErrParts: []string{"重启请求返回错误", "健康检查失败", "恢复旧内核失败"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rollbackCalled := false
			err := verifyKernelUpgrade(
				func() error { return tt.restartErr },
				func() error { return tt.healthErr },
				func() error {
					rollbackCalled = true
					return tt.rollbackErr
				},
			)
			if (err != nil) != tt.wantErr {
				t.Fatalf("verifyKernelUpgrade() error = %v, wantErr %v", err, tt.wantErr)
			}
			if rollbackCalled != tt.wantRollback {
				t.Fatalf("rollback called = %v, want %v", rollbackCalled, tt.wantRollback)
			}
			if !tt.wantErr && rollbackCalled {
				t.Fatal("successful health check must not trigger rollback")
			}
			if err != nil {
				for _, part := range tt.wantErrParts {
					if !strings.Contains(err.Error(), part) {
						t.Errorf("error %q does not contain %q", err, part)
					}
				}
			}
		})
	}
}

func TestCalculateMihomoSpeeds(t *testing.T) {
	mihomoSpeedMu.Lock()
	mihomoSpeedLastTime = time.Time{}
	mihomoSpeedLastUpload = 0
	mihomoSpeedLastDownload = 0
	mihomoSpeedMu.Unlock()

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	up, down := calculateMihomoSpeeds(100, 200, start)
	if up != 0 || down != 0 {
		t.Fatalf("first sample should have zero speed, got up=%d down=%d", up, down)
	}
	up, down = calculateMihomoSpeeds(500, 800, start.Add(2*time.Second))
	if up != 200 || down != 300 {
		t.Fatalf("speed = up:%d down:%d, want up:200 down:300", up, down)
	}
	up, down = calculateMihomoSpeeds(10, 20, start.Add(4*time.Second))
	if up != 0 || down != 0 {
		t.Fatalf("counter reset should not report negative speed, got up=%d down=%d", up, down)
	}
}

func TestTrafficCounter(t *testing.T) {
	if got, ok := trafficCounter(float64(123)); !ok || got != 123 {
		t.Fatalf("trafficCounter(float64(123)) = %d, %v", got, ok)
	}
	if _, ok := trafficCounter("123"); ok {
		t.Fatal("trafficCounter should reject string counters")
	}
}
func TestRollbackConfigAfterReloadFailure(t *testing.T) {
	t.Run("restores previous config atomically", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("MIHOMO_HOME", home)
		mainPath := filepath.Join(home, "config.yaml")
		previousPath := mainPath + ".previous"
		current := []byte("secret: new-secret\ntun: {}\ndns: {}\n")
		previous := []byte("secret: old-secret\ntun: {}\ndns: {}\n")
		if err := os.WriteFile(mainPath, current, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(previousPath, previous, 0600); err != nil {
			t.Fatal(err)
		}
		if err := rollbackConfigAtPath(mainPath, func() error { return nil }); err != nil {
			t.Fatalf("rollbackConfigAfterReloadFailure() error = %v", err)
		}
		got, err := os.ReadFile(mainPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(previous) {
			t.Fatalf("restored config = %q, want %q", got, previous)
		}
		if _, err := os.Stat(mainPath + ".restore"); !os.IsNotExist(err) {
			t.Fatalf("restore temporary file should be removed, stat error = %v", err)
		}
	})

	t.Run("reports missing backup and preserves current config", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("MIHOMO_HOME", home)
		mainPath := filepath.Join(home, "config.yaml")
		current := []byte("secret: new-secret\ntun: {}\ndns: {}\n")
		if err := os.WriteFile(mainPath, current, 0600); err != nil {
			t.Fatal(err)
		}
		if err := rollbackConfigAtPath(mainPath, func() error { t.Fatal("reload must not run without backup"); return nil }); err == nil {
			t.Fatal("expected error when previous config backup is missing")
		}
		got, err := os.ReadFile(mainPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(current) {
			t.Fatalf("current config changed after failed rollback: %q", got)
		}
	})
}

func TestPreserveMihomoSecret(t *testing.T) {
	incoming := map[string]interface{}{"secret": "controller-supplied", "mode": "rule"}
	current := map[string]interface{}{"secret": "local-secret"}
	if err := preserveMihomoSecret(current, incoming); err != nil {
		t.Fatalf("preserveMihomoSecret() error = %v", err)
	}
	if incoming["secret"] != "local-secret" {
		t.Fatalf("incoming secret = %#v, want local secret", incoming["secret"])
	}

	for name, config := range map[string]map[string]interface{}{
		"missing":    {},
		"blank":      {"secret": "  "},
		"wrong type": {"secret": true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := preserveMihomoSecret(config, map[string]interface{}{}); err == nil {
				t.Fatal("missing or invalid local secret should be rejected")
			}
		})
	}
}

func TestNormalizeMachineID(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "valid id", data: []byte("0123456789abcdef0123456789abcdef\n"), want: "0123456789a"},
		{name: "valid legacy id", data: []byte("abc123def456"), want: "abc123def45"},
		{name: "empty", data: []byte(""), want: ""},
		{name: "too short", data: []byte("abc123"), want: ""},
		{name: "invalid characters", data: []byte("0123456789gabcdef0123456789abcde"), want: ""},
		{name: "all zero", data: []byte("00000000000000000000000000000000"), want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeMachineID(tt.data)
			if len(got) > 11 {
				got = got[:11]
			}
			if got != tt.want {
				t.Fatalf("normalizeMachineID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadSystemMachineID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine-id")
	if _, err := readSystemMachineID(path); err == nil {
		t.Fatal("missing file should fail")
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSystemMachineID(path); err == nil {
		t.Fatal("empty file should fail")
	}
	if err := os.WriteFile(path, []byte("fedcba9876543210fedcba9876543210\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readSystemMachineID(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "fedcba98765" {
		t.Fatalf("readSystemMachineID() = %q", got)
	}
}

func TestLoadOrCreateMachineIDFallbackIsStableAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	systemPath := filepath.Join(dir, "missing-machine-id")
	storagePath := filepath.Join(dir, "persistent-data", "machine-id")
	first, err := loadOrCreateMachineID(systemPath, storagePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 11 {
		t.Fatalf("machine ID length = %d, want 11", len(first))
	}
	info, err := os.Stat(storagePath)
	if err != nil {
		t.Fatalf("fallback was not persisted: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("fallback permissions = %o, want 600", info.Mode().Perm())
	}
	// A second invocation simulates restart while /data stays mounted.
	second, err := loadOrCreateMachineID(systemPath, storagePath)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("machine ID changed after restart: %q != %q", first, second)
	}
}

func TestLoadOrCreateMachineIDReplacesEmptyPersistedFallback(t *testing.T) {
	dir := t.TempDir()
	systemPath := filepath.Join(dir, "missing-machine-id")
	storagePath := filepath.Join(dir, "data", "machine-id")
	if err := os.MkdirAll(filepath.Dir(storagePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storagePath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	id, err := loadOrCreateMachineID(systemPath, storagePath)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(storagePath)
	if err != nil {
		t.Fatal(err)
	}
	if validStoredFallbackMachineID(data) == "" {
		t.Fatal("empty persisted fallback was not replaced by a valid ID")
	}
	if id != string(data[:11]) {
		t.Fatalf("returned machine ID %q does not match persisted ID", id)
	}
}

func TestLoadOrCreateMachineIDRejectsUnwritableStorage(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := loadOrCreateMachineID(filepath.Join(dir, "missing"), filepath.Join(blocker, "machine-id"))
	if err == nil {
		t.Fatal("expected a clear storage error")
	}
}

func TestMachineIDHandler(t *testing.T) {
	t.Setenv("MIHOMO_HOME", t.TempDir())
	req := httptest.NewRequest(http.MethodGet, "/api/machine-id", nil)
	rec := httptest.NewRecorder()
	machineIDHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result["machine_id"]) != 11 {
		t.Fatalf("unexpected response: %#v", result)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/machine-id", nil)
	rec = httptest.NewRecorder()
	machineIDHandler(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rec.Code)
	}
}

func TestMihomoBinaryPathForRouterOS(t *testing.T) {
	t.Setenv("S5M_ROUTEROS", "1")
	t.Setenv("MIHOMO_HOME", "/routeros-persist")
	if got, want := mihomoBinaryPath(), "/routeros-persist/bin/mihomo"; got != want {
		t.Fatalf("RouterOS mihomoBinaryPath() = %q, want %q", got, want)
	}
	t.Setenv("S5M_ROUTEROS", "0")
	if got, want := mihomoBinaryPath(), "/usr/local/bin/mihomo"; got != want {
		t.Fatalf("default mihomoBinaryPath() = %q, want %q", got, want)
	}
}

func TestReportHeartbeatWebSocketSuccess(t *testing.T) {
	// WebSocket must be selected by default, without an opt-in environment variable.
	var httpFallbackCalled bool
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/ws":
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("WebSocket Authorization header = %q", r.Header.Get("Authorization"))
			}
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				t.Errorf("upgrade websocket: %v", err)
				return
			}
			defer conn.Close()
			if err := conn.WriteJSON(map[string]any{"type": "welcome"}); err != nil {
				t.Errorf("write welcome: %v", err)
				return
			}
			var msg struct {
				Type   string         `json:"type"`
				ID     string         `json:"id"`
				Status map[string]any `json:"status"`
			}
			if err := conn.ReadJSON(&msg); err != nil {
				t.Errorf("read heartbeat: %v", err)
				return
			}
			if msg.Type != "heartbeat" || msg.ID == "" || msg.Status["mihomo_version"] != "test-version" {
				t.Errorf("unexpected heartbeat payload: %#v", msg)
				return
			}
			wantSmartDNS := map[string]any{
				"smartdns_available": true,
				"smartdns_running": true,
				"smartdns_dns_healthy": true,
				"smartdns_version": "SmartDNS 1.2026.01",
				"smartdns_config_sha256": "abc123",
				"smartdns_last_error": "",
			}
			for key, want := range wantSmartDNS {
				if got := msg.Status[key]; got != want {
					t.Errorf("heartbeat SmartDNS field %q = %#v, want %#v", key, got, want)
				}
			}
			if err := conn.WriteJSON(map[string]any{"type": "heartbeat.ack", "id": msg.ID, "ok": true}); err != nil {
				t.Errorf("write ack: %v", err)
			}
		case "/api/v1/agent/heartbeat":
			httpFallbackCalled = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	err := reportHeartbeat(Config{CentralURL: server.URL, Token: "test-token"}, map[string]any{
		"mihomo_version": "test-version",
		"smartdns_available": true,
		"smartdns_running": true,
		"smartdns_dns_healthy": true,
		"smartdns_version": "SmartDNS 1.2026.01",
		"smartdns_config_sha256": "abc123",
		"smartdns_last_error": "",
	})
	if err != nil {
		t.Fatalf("reportHeartbeat() error = %v", err)
	}
	if httpFallbackCalled {
		t.Fatal("HTTP fallback was called even though WebSocket heartbeat succeeded")
	}
}

func TestReportHeartbeatDoesNotFallBackToHTTPWhenWebSocketFails(t *testing.T) {
	t.Setenv("S5M_AGENT_WEBSOCKET", "1")
	var httpCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/heartbeat" {
			http.NotFound(w, r)
			return
		}
		httpCalled = true
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("HTTP Authorization header = %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := reportHeartbeat(Config{CentralURL: server.URL, Token: "test-token"}, map[string]any{"mihomo_version": "test-version"})
	if err == nil {
		t.Fatal("reportHeartbeat() should return the WebSocket failure")
	}
	if httpCalled {
		t.Fatal("runtime heartbeat must not fall back to HTTP")
	}
}

func TestReportHeartbeatDoesNotFallBackWhenWebSocketIsUnauthorized(t *testing.T) {
	t.Setenv("S5M_AGENT_WEBSOCKET", "1")
	var httpCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/ws":
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("WebSocket Authorization header = %q", r.Header.Get("Authorization"))
			}
			http.Error(w, "websocket endpoint not enabled", http.StatusUnauthorized)
		case "/api/v1/agent/heartbeat":
			httpCalled = true
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("HTTP Authorization header = %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	err := reportHeartbeat(Config{CentralURL: server.URL, Token: "test-token"}, map[string]any{"mihomo_version": "test-version"})
	if err == nil {
		t.Fatal("reportHeartbeat() should return the WebSocket authorization failure")
	}
	if httpCalled {
		t.Fatal("runtime heartbeat must not fall back to HTTP")
	}
}

func TestReportHeartbeatDoesNotFallBackWhenWebSocketAckIDDoesNotMatch(t *testing.T) {
	t.Setenv("S5M_AGENT_WEBSOCKET", "1")
	var httpCalled bool
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/ws":
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				t.Errorf("upgrade websocket: %v", err)
				return
			}
			defer conn.Close()
			if err := conn.WriteJSON(map[string]any{"type": "welcome"}); err != nil {
				t.Errorf("write welcome: %v", err)
				return
			}
			var msg map[string]any
			if err := conn.ReadJSON(&msg); err != nil {
				t.Errorf("read heartbeat: %v", err)
				return
			}
			if err := conn.WriteJSON(map[string]any{"type": "heartbeat.ack", "id": "wrong-id", "ok": true}); err != nil {
				t.Errorf("write ack: %v", err)
			}
		case "/api/v1/agent/heartbeat":
			httpCalled = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	err := reportHeartbeat(Config{CentralURL: server.URL, Token: "test-token"}, map[string]any{"mihomo_version": "test-version"})
	if err == nil {
		t.Fatal("reportHeartbeat() should reject mismatched WebSocket ACK ID")
	}
	if httpCalled {
		t.Fatal("runtime heartbeat must not fall back to HTTP")
	}
}

func TestReportHeartbeatDoesNotFallBackWhenWebSocketAckIsInvalid(t *testing.T) {
	for _, ack := range []struct {
		name string
		msg  map[string]any
	}{
		{name: "wrong message type", msg: map[string]any{"type": "welcome", "id": "ignored", "ok": true}},
		{name: "negative acknowledgement", msg: map[string]any{"type": "heartbeat.ack", "id": "matching-id", "ok": false}},
	} {
		t.Run(ack.name, func(t *testing.T) {
			t.Setenv("S5M_AGENT_WEBSOCKET", "1")
			httpCalled := false
			upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/agent/ws":
					conn, err := upgrader.Upgrade(w, r, nil)
					if err != nil {
						t.Errorf("upgrade websocket: %v", err)
						return
					}
					defer conn.Close()
					if err := conn.WriteJSON(map[string]any{"type": "welcome"}); err != nil {
						t.Errorf("write welcome: %v", err)
						return
					}
					var heartbeat map[string]any
					if err := conn.ReadJSON(&heartbeat); err != nil {
						t.Errorf("read heartbeat: %v", err)
						return
					}
					response := map[string]any{}
					for k, v := range ack.msg {
						response[k] = v
					}
					if ack.name == "negative acknowledgement" {
						response["id"] = heartbeat["id"]
					}
					if err := conn.WriteJSON(response); err != nil {
						t.Errorf("write ack: %v", err)
					}
				case "/api/v1/agent/heartbeat":
					httpCalled = true
					w.WriteHeader(http.StatusNoContent)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			err := reportHeartbeat(Config{CentralURL: server.URL, Token: "test-token"}, map[string]any{"mihomo_version": "test-version"})
			if err == nil {
				t.Fatal("reportHeartbeat() should reject invalid WebSocket ACK")
			}
			if httpCalled {
				t.Fatal("runtime heartbeat must not fall back to HTTP")
			}
		})
	}
}

func TestReportHeartbeatWebSocketPreservesCentralBasePath(t *testing.T) {
	t.Setenv("S5M_AGENT_WEBSOCKET", "1")
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gateway/api/v1/agent/ws" {
			http.NotFound(w, r)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer conn.Close()
		if err := conn.WriteJSON(map[string]any{"type": "welcome"}); err != nil {
			t.Errorf("write welcome: %v", err)
			return
		}
		var msg struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}
		if err := conn.ReadJSON(&msg); err != nil {
			t.Errorf("read heartbeat: %v", err)
			return
		}
		if err := conn.WriteJSON(map[string]any{"type": "heartbeat.ack", "id": msg.ID, "ok": true}); err != nil {
			t.Errorf("write ack: %v", err)
		}
	}))
	defer server.Close()

	cfg := Config{CentralURL: server.URL + "/gateway", Token: "test-token"}
	if err := reportHeartbeatWebSocket(cfg, map[string]any{"mihomo_version": "test-version"}); err != nil {
		t.Fatalf("reportHeartbeatWebSocket() error = %v", err)
	}
}

func TestProbeControllerHTTPOnlyChecksReachability(t *testing.T) {
	called := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called <- struct{}{}
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/health" {
			t.Errorf("unexpected probe request: %s %s", r.Method, r.URL.Path)
		}
		// A 503 still proves the controller is reachable; this probe must not
		// become an application-data or HTTP fallback channel.
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	if err := probeControllerHTTP(Config{CentralURL: server.URL}); err != nil {
		t.Fatalf("probeControllerHTTP() error = %v", err)
	}
	select {
	case <-called:
	default:
		t.Fatal("controller reachability endpoint was not called")
	}
}

func TestProbeControllerHTTPFailsWhenNetworkUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()

	if err := probeControllerHTTP(Config{CentralURL: url}); err == nil {
		t.Fatal("expected network error after controller listener closed")
	}
}

func TestNextReconnectDelayCapsAtSixtySeconds(t *testing.T) {
	cases := []struct {
		current time.Duration
		want    time.Duration
	}{
		{0, 2 * time.Second},
		{2 * time.Second, 4 * time.Second},
		{30 * time.Second, 60 * time.Second},
		{60 * time.Second, 60 * time.Second},
	}
	for _, tc := range cases {
		if got := nextReconnectDelay(tc.current); got != tc.want {
			t.Errorf("nextReconnectDelay(%s) = %s, want %s", tc.current, got, tc.want)
		}
	}
}

func TestAgentConfigHandlerDistinguishesBindingFromConnection(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MIHOMO_HOME", dir)
	if err := os.WriteFile(filepath.Join(dir, "agent.json"), []byte(`{"central_url":"https://controller.example","token":"saved-token"}`), 0600); err != nil {
		t.Fatal(err)
	}
	previous := agentConnected.Load()
	defer agentConnected.Store(previous)

	cases := []struct {
		name      string
		connected bool
	}{
		{name: "bound but disconnected", connected: false},
		{name: "active websocket", connected: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agentConnected.Store(tc.connected)
			req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
			rec := httptest.NewRecorder()
			agentConfigHandler(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			var got map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if got["has_token"] != true {
				t.Fatalf("has_token = %#v, want true", got["has_token"])
			}
			if got["connected"] != tc.connected {
				t.Fatalf("connected = %#v, want %v", got["connected"], tc.connected)
			}
			if got["central_url"] != "https://controller.example" {
				t.Fatalf("central_url = %#v", got["central_url"])
			}
		})
	}
}

func TestAgentConfigHandlerReportsMissingAndInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MIHOMO_HOME", dir)
	previous := agentConnected.Load()
	defer agentConnected.Store(previous)
	agentConnected.Store(false)

	readConfig := func() map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		agentConfigHandler(rec, httptest.NewRequest(http.MethodGet, "/api/config", nil))
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		return got
	}

	got := readConfig()
	if got["config_exists"] != false || got["config_readable"] != true || got["config_valid"] != true || got["has_token"] != false {
		t.Fatalf("unexpected missing-config status: %#v", got)
	}

	if err := os.WriteFile(filepath.Join(dir, "agent.json"), []byte("{invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	got = readConfig()
	if got["config_exists"] != true || got["config_valid"] != false || got["has_token"] != false {
		t.Fatalf("unexpected invalid-config status: %#v", got)
	}
}

func TestReconnectDelayWithJitterStaysWithinExpectedBounds(t *testing.T) {
	cases := []struct {
		name    string
		current time.Duration
		min     time.Duration
		max     time.Duration
	}{
		{"initial", 0, 2 * time.Second, 3 * time.Second},
		{"normal", 8 * time.Second, 8 * time.Second, 12 * time.Second},
		{"capped", 90 * time.Second, 60 * time.Second, 90 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				got := reconnectDelayWithJitter(tc.current)
				if got < tc.min || got >= tc.max {
					t.Fatalf("reconnectDelayWithJitter(%s) = %s, want >= %s and < %s",
						tc.current, got, tc.min, tc.max)
				}
			}
		})
	}
}

func TestAgentWebSocketHelpersRefreshExpiredDeadlines(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer conn.Close()

		var request map[string]string
		if err := conn.ReadJSON(&request); err != nil {
			t.Errorf("read websocket request: %v", err)
			return
		}
		if request["type"] != "command.ack" {
			t.Errorf("request type = %q, want command.ack", request["type"])
			return
		}
		if err := conn.WriteJSON(map[string]any{
			"type": "command.acknowledged",
			"id":   request["id"],
			"ok":   true,
		}); err != nil {
			t.Errorf("write websocket acknowledgement: %v", err)
		}
	}))
	defer server.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.Close()

	// Simulate a command that outlived the deadlines configured at connection
	// startup. The helpers must set fresh deadlines for the ACK exchange.
	if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := writeAgentWSJSON(conn, map[string]string{
		"type": "command.ack",
		"id":   "command-123",
	}); err != nil {
		t.Fatalf("writeAgentWSJSON should refresh an expired deadline: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	var ack struct {
		Type string `json:"type"`
		ID   string `json:"id"`
		OK   bool   `json:"ok"`
	}
	if err := readAgentWSJSON(conn, &ack, 2*time.Second); err != nil {
		t.Fatalf("readAgentWSJSON should refresh an expired deadline: %v", err)
	}
	if ack.Type != "command.acknowledged" || ack.ID != "command-123" || !ack.OK {
		t.Fatalf("unexpected acknowledgement: %+v", ack)
	}
}

func TestGeoIPDownloadFailureDetection(t *testing.T) {
	if !isGeoIPDownloadFailure([]byte("can't initial GeoIP: can't download MMDB: EOF")) {
		t.Fatal("expected transient GeoIP download failure to be recognized")
	}
	if isGeoIPDownloadFailure([]byte("yaml: line 4: did not find expected key")) {
		t.Fatal("YAML syntax errors must not be classified as GeoIP download failures")
	}
}

func TestDisableGeoIPFallbackForValidationOnly(t *testing.T) {
	cfg := map[string]interface{}{
		"fallback-filter": map[string]interface{}{"geoip": true, "geoip-code": "CN"},
	}
	if !disableGeoIPFallbackForValidation(cfg) {
		t.Fatal("expected enabled GeoIP fallback filter to be disabled for validation copy")
	}
	fallback := cfg["fallback-filter"].(map[string]interface{})
	if fallback["geoip"] != false || fallback["geoip-code"] != "CN" {
		t.Fatalf("unexpected validation-only fallback filter: %#v", fallback)
	}
	if disableGeoIPFallbackForValidation(map[string]interface{}{"fallback-filter": map[string]interface{}{"geoip": false}}) {
		t.Fatal("must not modify a disabled GeoIP fallback filter")
	}
}

func TestSafeMihomoValidationDiagnosticRedactsSecretsAndPaths(t *testing.T) {
	got := safeMihomoValidationDiagnostic([]byte("error loading /opt/s5m-agent/data/config.yaml secret: abc123\ncan't download MMDB: EOF"))
	if strings.Contains(got, "/opt/s5m-agent") || strings.Contains(got, "abc123") {
		t.Fatalf("diagnostic leaked a path or secret: %q", got)
	}
	if !strings.Contains(got, "can't download MMDB: EOF") {
		t.Fatalf("diagnostic lost useful validation detail: %q", got)
	}
}

func TestSetCentralRouteExclusionsKeepsCurrentManagedCIDRWithoutChange(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MIHOMO_HOME", dir)
	if err := writeManagedRouteCIDRs([]string{"198.51.100.10/32"}); err != nil {
		t.Fatalf("write managed route CIDRs: %v", err)
	}
	cfg := map[string]interface{}{
		"rules": []interface{}{"DOMAIN-SUFFIX,v2net.cc,DIRECT", "MATCH,Proxy"},
		"tun": map[string]interface{}{
			"enable": true,
			"route-exclude-address": []interface{}{
				"192.0.2.7/32",
				"198.51.100.10/32",
			},
		},
	}
	cidrs, changed, err := setCentralRouteExclusions(cfg, "https://198.51.100.10")
	if err != nil {
		t.Fatalf("setCentralRouteExclusions() error = %v", err)
	}
	if changed {
		t.Fatal("unchanged managed controller CIDR must not trigger a config reload")
	}
	if len(cidrs) != 1 || cidrs[0] != "198.51.100.10/32" {
		t.Fatalf("managed CIDRs = %#v, want current controller IP", cidrs)
	}
	got := cfg["tun"].(map[string]interface{})["route-exclude-address"].([]interface{})
	want := []interface{}{"192.0.2.7/32", "198.51.100.10/32"}
	if len(got) != len(want) {
		t.Fatalf("route exclusions = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("route exclusions = %#v, want %#v", got, want)
		}
	}
}

func TestApplyAgentControlErrorReportsConfigFailureWithoutLosingMihomoError(t *testing.T) {
	status := map[string]any{"last_error": "读取 Mihomo 版本失败: HTTP 503"}
	applyAgentControlError(status, "主控配置应用失败: YAML 无效")
	got, ok := status["last_error"].(string)
	if !ok || !strings.Contains(got, "主控配置应用失败") || !strings.Contains(got, "读取 Mihomo 版本失败") {
		t.Fatalf("last_error = %#v; want both config and Mihomo errors", status["last_error"])
	}
	if strings.Contains(got, "/opt/s5m-agent") {
		t.Fatalf("last_error must not expose local filesystem paths: %q", got)
	}
}

func TestApplyAgentControlErrorNoopWhenEmpty(t *testing.T) {
	status := map[string]any{"last_error": "existing diagnostic"}
	applyAgentControlError(status, "  ")
	if status["last_error"] != "existing diagnostic" {
		t.Fatalf("empty control error changed existing diagnostic: %#v", status["last_error"])
	}
}

func TestEnsureV2NetDirectRulePrecedesMatchAndIsIdempotent(t *testing.T) {
	cfg := map[string]interface{}{
		"rules": []interface{}{
			"DOMAIN,example.com,Proxy",
			"MATCH,Proxy",
		},
	}
	if !ensureV2NetDirectRule(cfg) {
		t.Fatal("expected v2net.cc direct rule to be inserted")
	}
	rules := cfg["rules"].([]interface{})
	if len(rules) != 3 || rules[1] != "DOMAIN-SUFFIX,v2net.cc,DIRECT" || rules[2] != "MATCH,Proxy" {
		t.Fatalf("unexpected rule order: %#v", rules)
	}
	if ensureV2NetDirectRule(cfg) {
		t.Fatal("existing v2net.cc direct rule should not be inserted twice")
	}
}

func TestEnsureV2NetDirectRuleAddsRulesWhenMissing(t *testing.T) {
	cfg := map[string]interface{}{}
	if !ensureV2NetDirectRule(cfg) {
		t.Fatal("expected direct rule to be added when rules block is missing")
	}
	rules, ok := cfg["rules"].([]interface{})
	if !ok || len(rules) != 1 || rules[0] != "DOMAIN-SUFFIX,v2net.cc,DIRECT" {
		t.Fatalf("unexpected rules: %#v", cfg["rules"])
	}
}

func TestEnsureV2NetDirectRuleMovesRuleBeforeMatch(t *testing.T) {
	cfg := map[string]interface{}{
		"rules": []interface{}{
			"MATCH,Proxy",
			"DOMAIN-SUFFIX,v2net.cc,DIRECT",
			"DOMAIN,example.com,DIRECT",
		},
	}
	if !ensureV2NetDirectRule(cfg) {
		t.Fatal("expected misplaced direct rule to be moved before MATCH")
	}
	rules := cfg["rules"].([]interface{})
	if len(rules) != 3 || rules[0] != "DOMAIN-SUFFIX,v2net.cc,DIRECT" || rules[1] != "MATCH,Proxy" || rules[2] != "DOMAIN,example.com,DIRECT" {
		t.Fatalf("unexpected rule order after repair: %#v", rules)
	}
	if ensureV2NetDirectRule(cfg) {
		t.Fatal("correctly placed direct rule should remain unchanged")
	}
}

func TestEnsureV2NetDirectRuleDeduplicatesExistingRules(t *testing.T) {
	cfg := map[string]interface{}{
		"rules": []interface{}{
			"DOMAIN-SUFFIX,v2net.cc,DIRECT",
			"DOMAIN,example.com,DIRECT",
			"DOMAIN-SUFFIX,v2net.cc,DIRECT",
			"MATCH,Proxy",
		},
	}
	if !ensureV2NetDirectRule(cfg) {
		t.Fatal("expected duplicate direct rules to be normalized")
	}
	rules := cfg["rules"].([]interface{})
	if len(rules) != 3 || rules[0] != "DOMAIN,example.com,DIRECT" || rules[1] != "DOMAIN-SUFFIX,v2net.cc,DIRECT" || rules[2] != "MATCH,Proxy" {
		t.Fatalf("unexpected deduplicated rule order: %#v", rules)
	}
}

func TestAgentSyncErrorsPersistAcrossWebSocketSessions(t *testing.T) {
	clearAgentConfigSyncError()
	setAgentRouteSyncError("")
	t.Cleanup(func() {
		clearAgentConfigSyncError()
		setAgentRouteSyncError("")
	})

	configErr := errors.New("配置 SHA-256 不匹配")
	if got := recordAgentConfigSyncFailure(configErr); !errors.Is(got, configErr) {
		t.Fatalf("recordAgentConfigSyncFailure() = %v, want original error", got)
	}
	setAgentRouteSyncError("主控直连路由更新失败: DNS timeout")

	// A new WebSocket session reads the same process-level error state.
	configState, routeState := agentControlSyncErrors()
	if !strings.Contains(configState, "配置 SHA-256 不匹配") {
		t.Fatalf("config error was lost across reconnect: %q", configState)
	}
	if !strings.Contains(routeState, "DNS timeout") {
		t.Fatalf("route error was lost across reconnect: %q", routeState)
	}

	clearAgentConfigSyncError()
	configState, routeState = agentControlSyncErrors()
	if configState != "" {
		t.Fatalf("config error was not cleared after successful sync: %q", configState)
	}
	if routeState == "" {
		t.Fatal("clearing config error must not clear independent route error")
	}
	setAgentRouteSyncError("")
	configState, routeState = agentControlSyncErrors()
	if configState != "" || routeState != "" {
		t.Fatalf("sync errors remain after independent recovery: config=%q route=%q", configState, routeState)
	}
}

func TestApplyAgentControlErrorPreservesMihomoDiagnosticAndBoundsOutput(t *testing.T) {
	status := map[string]any{"last_error": "Mihomo API unavailable at /opt/s5m/data/config.yaml"}
	applyAgentControlError(status, "主控配置同步失败: token=private-token rejected by controller")
	got, ok := status["last_error"].(string)
	if !ok {
		t.Fatalf("last_error has unexpected type: %#v", status["last_error"])
	}
	if !strings.Contains(got, "主控配置同步失败") || !strings.Contains(got, "Mihomo:") {
		t.Fatalf("combined diagnostic lost one error source: %q", got)
	}
	for _, secret := range []string{"private-token", "/opt/s5m"} {
		if strings.Contains(got, secret) {
			t.Fatalf("combined diagnostic leaked %q: %q", secret, got)
		}
	}

	largeStatus := map[string]any{"last_error": strings.Repeat("M", 700)}
	applyAgentControlError(largeStatus, strings.Repeat("C", 700))
	bounded, _ := largeStatus["last_error"].(string)
	if len(bounded) > 704 {
		t.Fatalf("combined diagnostic exceeds safe 700-byte bound: %d", len(bounded))
	}
}

func TestSafeMihomoValidationDiagnosticRedactsQuotedCredentialsAndBearerTokens(t *testing.T) {
	input := `{"token":"secret with spaces","password":"value with \"quote\"","api_key":"key with spaces"} Authorization: Bearer bearer-secret`
	got := safeMihomoValidationDiagnostic([]byte(input))
	for _, secret := range []string{"secret with spaces", "value with", "quote", "key with spaces", "bearer-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("diagnostic leaked sensitive value %q: %q", secret, got)
		}
	}
	if strings.Count(got, "[已隐藏]") < 4 {
		t.Fatalf("expected credential values and bearer token to be redacted: %q", got)
	}
}
