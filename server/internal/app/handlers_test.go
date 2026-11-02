package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"
)

func TestDecodeErrorStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "oversized body", err: errRequestBodyTooLarge, want: http.StatusRequestEntityTooLarge},
		{name: "wrapped oversized body", err: fmt.Errorf("decode failed: %w", errRequestBodyTooLarge), want: http.StatusRequestEntityTooLarge},
		{name: "lookalike message is not oversized", err: errors.New("请求体超过 8 KiB 限制"), want: http.StatusBadRequest},
		{name: "malformed JSON", err: errors.New("invalid character"), want: http.StatusBadRequest},
		{name: "nil error", err: nil, want: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeErrorStatus(tt.err); got != tt.want {
				t.Fatalf("decodeErrorStatus() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestDecodeLimitedRejectsOversizedAndTrailingJSON(t *testing.T) {
	t.Run("oversized body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"value":"12345"}`))
		var got map[string]string
		err := decodeLimited(r, 8, "8 bytes", &got)
		if !errors.Is(err, errRequestBodyTooLarge) {
			t.Fatalf("decodeLimited() error = %v, want oversized-body sentinel", err)
		}
	})

	t.Run("trailing JSON value", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"value":"ok"} {}`))
		var got map[string]string
		if err := decodeLimited(r, 64, "64 bytes", &got); err == nil {
			t.Fatal("decodeLimited() accepted a second trailing JSON value")
		}
	})

	t.Run("valid JSON at limit", func(t *testing.T) {
		body := `{"x":1}`
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		var got map[string]int
		if err := decodeLimited(r, int64(len(body)), "exact limit", &got); err != nil {
			t.Fatalf("decodeLimited() rejected body at exact limit: %v", err)
		}
		if got["x"] != 1 {
			t.Fatalf("decoded value = %v, want x=1", got)
		}
	})
}

func TestIsInternalSettingKey(t *testing.T) {
	internal := []string{
		"agent_token",
		"agent_machine_abc",
		"agent_mihomo_secret_abc",
		"agent_secret_abc",
		"agent_command_abc",
		"agent_command_result_abc",
		"agent_lastseen_abc",
		"agent_status_abc",
		"mihomo_secret_controller",
	}
	for _, key := range internal {
		if !isInternalSettingKey(key) {
			t.Errorf("expected %q to be internal", key)
		}
	}
	public := []string{"tun_enable", "subscribe_url", "sub_url", "theme"}
	for _, key := range public {
		if isInternalSettingKey(key) {
			t.Errorf("expected %q to remain a public setting", key)
		}
	}
}

func TestValidateProxyRejectsUnknownModeAndInvalidPorts(t *testing.T) {
	tests := []struct {
		name  string
		proxy Proxy
		want  string
	}{
		{
			name:  "legacy unknown mode is ignored",
			proxy: Proxy{Name: "proxy-a", Mode: "proxxy", Type: "socks5", Server: "example.com", Port: 1080},
		},
		{
			name:  "legacy direct mode is ignored",
			proxy: Proxy{Name: "proxy-a", Mode: "direct", Type: "socks5", Server: "example.com", Port: 1080},
		},
		{
			name:  "zero port",
			proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Server: "example.com", Port: 0},
			want:  "代理端口必须在 1-65535 之间",
		},
		{
			name:  "port above maximum",
			proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Server: "example.com", Port: 65536},
			want:  "代理端口必须在 1-65535 之间",
		},
		{
			name:  "valid upper-bound port",
			proxy: Proxy{Name: "proxy-a", Mode: "proxy", Type: "socks5", Server: "example.com", Port: 65535},
		},
		{
			name:  "strict rule mode is accepted",
			proxy: Proxy{Name: "proxy-a", Mode: "rule", Type: "socks5", Server: "example.com", Port: 1080},
		},
		{
			name:  "empty mode defaults to strict rule mode",
			proxy: Proxy{Name: "proxy-a", Type: "socks5", Server: "example.com", Port: 1080},
		},
		{
			name:  "empty machine code stays unbound",
			proxy: Proxy{Name: "proxy-a", Type: "socks5", Server: "example.com", Port: 1080, MachineCode: ""},
		},
		{
			name:  "explicit global association is valid",
			proxy: Proxy{Name: "proxy-a", Type: "socks5", Server: "example.com", Port: 1080, MachineCode: "__GLOBAL__"},
		},
		{
			name:  "valid machine association is trimmed",
			proxy: Proxy{Name: "proxy-a", Type: "socks5", Server: "example.com", Port: 1080, MachineCode: " node-a "},
		},
		{
			name:  "machine code containing whitespace is rejected",
			proxy: Proxy{Name: "proxy-a", Type: "socks5", Server: "example.com", Port: 1080, MachineCode: "node a"},
			want:  "关联机器码格式错误",
		},
		{
			name:  "machine code containing slash is rejected",
			proxy: Proxy{Name: "proxy-a", Type: "socks5", Server: "example.com", Port: 1080, MachineCode: "../node"},
			want:  "关联机器码格式错误",
		},
		{
			name:  "machine code exceeding 64 characters is rejected",
			proxy: Proxy{Name: "proxy-a", Type: "socks5", Server: "example.com", Port: 1080, MachineCode: strings.Repeat("a", 65)},
			want:  "关联机器码格式错误",
		},
	}
	app := &App{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := app.validateProxy(&tt.proxy)
			if tt.want == "" && got != "" {
				t.Fatalf("validateProxy() = %q, want success", got)
			}
			if tt.want != "" && !strings.Contains(got, tt.want) {
				t.Fatalf("validateProxy() = %q, want error containing %q", got, tt.want)
			}
		})
	}
}

func TestProxyHandlersRejectInvalidMachineAssociation(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "proxy-association-api.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	app := &App{store: store}
	invalidBody := `{"name":"invalid-association","mode":"proxy","type":"socks5","server":"192.0.2.30","port":1080,"machine_code":"node/a"}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/proxies", strings.NewReader(invalidBody))
	createRec := httptest.NewRecorder()
	app.handleCreateProxy(createRec, createReq)
	if createRec.Code != http.StatusBadRequest {
		t.Fatalf("create status = %d, want %d; body=%s", createRec.Code, http.StatusBadRequest, createRec.Body.String())
	}
	proxies, err := store.ListProxies()
	if err != nil {
		t.Fatalf("ListProxies after rejected create: %v", err)
	}
	if len(proxies) != 0 {
		t.Fatalf("invalid proxy was persisted: count=%d", len(proxies))
	}

	existing := &Proxy{Name: "valid-proxy", Mode: "proxy", Type: "socks5", Server: "192.0.2.31", Port: 1080, MachineCode: "node-a", Enabled: true}
	if err := store.CreateProxy(existing); err != nil {
		t.Fatalf("CreateProxy fixture: %v", err)
	}
	updateReq := httptest.NewRequest(http.MethodPut, "/api/v1/proxies/"+strconv.FormatInt(existing.ID, 10), strings.NewReader(invalidBody))
	updateReq.SetPathValue("id", strconv.FormatInt(existing.ID, 10))
	updateRec := httptest.NewRecorder()
	app.handleUpdateProxy(updateRec, updateReq)
	if updateRec.Code != http.StatusBadRequest {
		t.Fatalf("update status = %d, want %d; body=%s", updateRec.Code, http.StatusBadRequest, updateRec.Body.String())
	}
	proxies, err = store.ListProxies()
	if err != nil {
		t.Fatalf("ListProxies after rejected update: %v", err)
	}
	if len(proxies) != 1 || proxies[0].MachineCode != "node-a" {
		t.Fatalf("rejected update changed persisted association: proxies=%+v", proxies)
	}
}

func TestCreateProxyPersistsIndependentRuleMode(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "proxy-rule-mode.db"))
	if err != nil { t.Fatalf("OpenStore: %v", err) }
	defer store.db.Close()
	app := &App{store: store}
	body := `{"name":"strict-rule-proxy","mode":"rule","type":"socks5","server":"192.0.2.55","port":1080,"machine_code":"node-rule","enabled":true,"source_cidr":"0.0.0.0/0"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/proxies", strings.NewReader(body))
	rec := httptest.NewRecorder()
	app.handleCreateProxy(rec, req)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("create rule proxy status = %d; body=%s", rec.Code, rec.Body.String())
	}
	proxies, err := store.ListProxies()
	if err != nil { t.Fatalf("ListProxies: %v", err) }
	if len(proxies) != 1 || proxies[0].Mode != "rule" {
		t.Fatalf("backend did not persist independent rule mode: %#v", proxies)
	}
}

func TestParseProxyLineRejectsInvalidPort(t *testing.T) {
	for _, line := range []string{
		"socks5://user:pass@example.com:not-a-port",
		"socks5://user:pass@example.com:0",
		"socks5://user:pass@example.com:65536",
	} {
		if _, err := parseProxyLine(line); err == nil {
			t.Errorf("parseProxyLine(%q) should reject invalid port", line)
		}
	}
}

func TestParseProxyLineAcceptsValidPort(t *testing.T) {
	proxy, err := parseProxyLine("socks5://user:pass@example.com:65535#valid")
	if err != nil {
		t.Fatalf("parseProxyLine() error = %v", err)
	}
	if proxy.Port != 65535 {
		t.Fatalf("port = %d, want 65535", proxy.Port)
	}
	if proxy.Mode != "rule" {
		t.Fatalf("imported proxy mode = %q, want rule", proxy.Mode)
	}
	if msg := (&App{}).validateProxy(proxy); msg != "" {
		t.Fatalf("validateProxy() = %q, want success", msg)
	}
}

func TestValidateProxyRejectsUnsupportedProtocol(t *testing.T) {
	for _, protocol := range []string{"", "unknown", "socks", "vmess+ws"} {
		proxy := Proxy{Name: "proxy-a", Mode: "proxy", Type: protocol, Server: "example.com", Port: 1080}
		if msg := (&App{}).validateProxy(&proxy); !strings.Contains(msg, "代理类型无效") {
			t.Errorf("validateProxy(type=%q) = %q, want unsupported-protocol error", protocol, msg)
		}
	}
}

func TestValidateProxyNormalizesSupportedProtocol(t *testing.T) {
	proxy := Proxy{Name: "proxy-a", Mode: "proxy", Type: " SOCKS5 ", Server: "example.com", Port: 1080}
	if msg := (&App{}).validateProxy(&proxy); msg != "" {
		t.Fatalf("validateProxy() = %q, want success", msg)
	}
	if proxy.Type != "socks5" {
		t.Fatalf("type = %q, want normalized socks5", proxy.Type)
	}
}

func TestValidateInstance(t *testing.T) {
	tests := []struct {
		name    string
		input   Instance
		wantErr string
	}{
		{name: "blank name", input: Instance{Name: "  "}, wantErr: "实例名称不能为空"},
		{name: "name too long", input: Instance{Name: strings.Repeat("a", 101)}, wantErr: "不能超过 100 个字符"},
		{name: "machine code too long", input: Instance{Name: "node-a", MachineCode: strings.Repeat("a", 129)}, wantErr: "机器码不能超过 128 个字符"},
		{name: "malformed URL", input: Instance{Name: "node-a", APIURL: "://bad"}, wantErr: "API 地址必须是有效的 HTTP 或 HTTPS URL"},
		{name: "unsupported URL scheme", input: Instance{Name: "node-a", APIURL: "ftp://example.com"}, wantErr: "API 地址必须是有效的 HTTP 或 HTTPS URL"},
		{name: "URL with credentials", input: Instance{Name: "node-a", APIURL: "https://user:pass@example.com/api"}, wantErr: "不能包含用户名或密码"},
		{name: "valid URL and normalization", input: Instance{Name: " node-a ", MachineCode: " code-1 ", APIURL: " https://example.com/api "}},
		{name: "optional API URL", input: Instance{Name: "node-a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input
			msg := validateInstance(&got)
			if tt.wantErr != "" {
				if !strings.Contains(msg, tt.wantErr) {
					t.Fatalf("validateInstance() = %q, want error containing %q", msg, tt.wantErr)
				}
				return
			}
			if msg != "" {
				t.Fatalf("validateInstance() = %q, want success", msg)
			}
			if got.Name != strings.TrimSpace(tt.input.Name) || got.MachineCode != strings.TrimSpace(tt.input.MachineCode) || got.APIURL != strings.TrimSpace(tt.input.APIURL) {
				t.Fatalf("instance fields were not normalized: %#v", got)
			}
		})
	}
}

func TestDecodeBoundsJSONRequestBody(t *testing.T) {
	t.Run("rejects oversized body", func(t *testing.T) {
		body := strings.NewReader(`{"value":"` + strings.Repeat("a", maxJSONRequestBody) + `"}`)
		req := httptest.NewRequest("POST", "/", body)
		var dst map[string]string
		if err := decode(req, &dst); err == nil || !strings.Contains(err.Error(), "2 MiB") {
			t.Fatalf("decode() error = %v, want request-size error", err)
		}
	})
	t.Run("rejects trailing JSON value", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ok":true} {"extra":true}`))
		var dst map[string]bool
		if err := decode(req, &dst); err == nil {
			t.Fatal("decode() accepted multiple JSON values")
		}
	})
	t.Run("accepts valid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ok":true}`))
		var dst map[string]bool
		if err := decode(req, &dst); err != nil || !dst["ok"] {
			t.Fatalf("decode() = %#v, %v; want valid JSON", dst, err)
		}
	})
}

func TestValidateAgentRegistrationInput(t *testing.T) {
	tests := []struct {
		name        string
		machineCode string
		secret      string
		wantErr     string
	}{
		{name: "trims valid values", machineCode: " node_01-abc ", secret: " token "},
		{name: "rejects blank machine code", machineCode: "   ", secret: "token", wantErr: "机器码格式错误"},
		{name: "rejects invalid machine code characters", machineCode: "node/01", secret: "token", wantErr: "机器码格式错误"},
		{name: "rejects oversized machine code", machineCode: strings.Repeat("a", 65), secret: "token", wantErr: "机器码格式错误"},
		{name: "rejects blank secret", machineCode: "node01", secret: "  ", wantErr: "专属 Token 长度无效"},
		{name: "rejects oversized secret", machineCode: "node01", secret: strings.Repeat("x", 257), wantErr: "专属 Token 长度无效"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machineCode, secret, gotErr := validateAgentRegistrationInput(tt.machineCode, tt.secret)
			if !strings.Contains(gotErr, tt.wantErr) && tt.wantErr != "" {
				t.Fatalf("error = %q, want %q", gotErr, tt.wantErr)
			}
			if tt.wantErr == "" {
				if gotErr != "" || machineCode != strings.TrimSpace(tt.machineCode) || secret != strings.TrimSpace(tt.secret) {
					t.Fatalf("normalized values = %q, %q, error %q", machineCode, secret, gotErr)
				}
			}
		})
	}
}

func TestAgentAuthorizationUsesOneValidatorAndRevokesChangedTokens(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "agent-auth-test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const machineCode = "node_01"
	const machineSecret = "dedicated-secret"
	const globalSecret = "global-secret"
	app := &App{store: store, jwtKey: []byte("test-jwt-secret")}
	if err := store.UpdateSettings(map[string]string{
		"agent_token":                  globalSecret,
		"agent_machine_" + machineCode: machineSecret,
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	version := sha256.Sum256([]byte(machineSecret))
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  machineCode,
		"role": "agent",
		"ver":  hex.EncodeToString(version[:]),
	}).SignedString(app.jwtKey)
	if err != nil {
		t.Fatalf("sign Agent token: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/config", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	code, err := app.agentMachineFromRequest(req)
	if err != nil || code != machineCode {
		t.Fatalf("agentMachineFromRequest() = %q, %v; want %q", code, err, machineCode)
	}
	if got, ok := app.agentMachineCode(req); !ok || got != machineCode {
		t.Fatalf("agentMachineCode() = %q, %v; want %q, true", got, ok, machineCode)
	}

	if err := store.UpdateSettings(map[string]string{"agent_machine_" + machineCode: "rotated-secret"}); err != nil {
		t.Fatalf("rotate dedicated token: %v", err)
	}
	if _, err := app.agentMachineFromRequest(req); err == nil {
		t.Fatal("old Agent JWT remained valid after dedicated token rotation")
	}
	if _, ok := app.agentMachineCode(req); ok {
		t.Fatal("boolean Agent validator accepted a revoked JWT")
	}
}

func TestSaveNodeConfigRejectsTrailingJSON(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-json.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const code = "node_json"
	if err := store.UpdateSettings(map[string]string{
		"agent_token":           "global-secret",
		"agent_machine_" + code: "dedicated-secret",
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	app := &App{store: store}
	body := `{"config_yaml":"secret: node-secret\ntun:\n  enable: false\ndns:\n  enable: false\n"} {"unexpected":true}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/nodes/"+code+"/config", strings.NewReader(body))
	req.SetPathValue("code", code)
	rec := httptest.NewRecorder()

	app.handleSaveNodeConfig(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if _, err := store.GetNodeConfig(code); err != nil {
		t.Fatalf("GetNodeConfig: %v", err)
	} else if cfg, _ := store.GetNodeConfig(code); cfg != nil {
		t.Fatal("invalid request unexpectedly persisted a node config")
	}
}

func TestDecodeLimitedRejectsTrailingJSONAndOversizedBody(t *testing.T) {
	t.Run("trailing JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(`{"ok":true} {"extra":true}`))
		var dst map[string]bool
		if err := decodeLimited(req, 128, "128 bytes", &dst); err == nil {
			t.Fatal("decodeLimited() accepted multiple JSON values")
		}
	})
	t.Run("oversized body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(`{"value":"`+strings.Repeat("x", 129)+`"}`))
		var dst map[string]string
		if err := decodeLimited(req, 128, "128 bytes", &dst); err == nil || !strings.Contains(err.Error(), "128 bytes") {
			t.Fatalf("decodeLimited() error = %v, want size-limit error", err)
		}
	})
}

func TestFilterDuplicateProxyImportsIsIdempotent(t *testing.T) {
	existing := []Proxy{{
		Type: "socks5", Server: "EXAMPLE.com", Port: 1080,
		Extra: map[string]any{"username": "user", "password": "secret"},
	}}
	incoming := []*Proxy{
		{Type: "socks5", Server: "example.com", Port: 1080, Extra: map[string]any{"username": "user", "password": "secret"}},
		{Type: "socks5", Server: "example.com", Port: 1080, Extra: map[string]any{"username": "other", "password": "secret"}},
		{Type: "vless", Server: "example.com", Port: 443, Extra: map[string]any{"uuid": "uuid"}},
	}
	unique, skipped := filterDuplicateProxyImports(existing, incoming)
	if skipped != 1 { t.Fatalf("skipped = %d, want 1", skipped) }
	if len(unique) != 2 { t.Fatalf("unique count = %d, want 2", len(unique)) }
	secondExisting := append([]Proxy(nil), existing...)
	for _, proxy := range unique { secondExisting = append(secondExisting, *proxy) }
	again, skippedAgain := filterDuplicateProxyImports(secondExisting, unique)
	if skippedAgain != len(unique) || len(again) != 0 {
		t.Fatalf("second import was not idempotent: unique=%d skipped=%d", len(again), skippedAgain)
	}
}

func TestImportProxiesRejectsOversizedBodyWith413(t *testing.T) {
	app := &App{}
	body := `{"content":"` + strings.Repeat("x", (1<<20)+1) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/proxies/import", strings.NewReader(body))
	rec := httptest.NewRecorder()

	app.handleImportProxies(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}
}

func TestSaveNodeConfigRejectsOversizedBodyWith413(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-oversize.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const code = "node_oversize"
	if err := store.UpdateSettings(map[string]string{
		"agent_token":           "global-secret",
		"agent_machine_" + code: "dedicated-secret",
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	app := &App{store: store}
	body := `{"config_yaml":"` + strings.Repeat("x", (2<<20)+1) + `"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/nodes/"+code+"/config", strings.NewReader(body))
	req.SetPathValue("code", code)
	rec := httptest.NewRecorder()

	app.handleSaveNodeConfig(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}
	cfg, err := store.GetNodeConfig(code)
	if err != nil {
		t.Fatalf("GetNodeConfig: %v", err)
	}
	if cfg != nil {
		t.Fatal("oversized request unexpectedly persisted a node config")
	}
}

func TestParseProxyImportContentSOCKS5JSONIPv4IPv6(t *testing.T) {
	content := `{
		"protocol":"socks5",
		"authentication":{"enabled":true,"username":"global-user","password":"global-pass"},
		"servers":[
			{"server":"151.242.11.70","port":23049,"username":"","password":"","udp":true},
			{"server":"2401:b60:e00e:7244::","port":23050,"username":"","password":"","udp":true}
		]
	}`
	proxies, failures := parseProxyImportContent(content)
	if len(failures) != 0 {
		t.Fatalf("unexpected failures: %v", failures)
	}
	if len(proxies) != 2 {
		t.Fatalf("got %d proxies, want 2", len(proxies))
	}
	if proxies[0].Server != "151.242.11.70" || proxies[0].Port != 23049 {
		t.Fatalf("unexpected IPv4 proxy: %+v", proxies[0])
	}
	if proxies[1].Server != "2401:b60:e00e:7244::" || proxies[1].Port != 23050 {
		t.Fatalf("unexpected IPv6 proxy: %+v", proxies[1])
	}
	for i, p := range proxies {
		if p.Type != "socks5" {
			t.Errorf("proxy %d type = %q", i, p.Type)
		}
		if p.Extra["username"] != "global-user" || p.Extra["password"] != "global-pass" {
			t.Errorf("proxy %d authentication not inherited: %#v", i, p.Extra)
		}
		if p.Extra["udp"] != true {
			t.Errorf("proxy %d UDP flag not preserved", i)
		}
	}
}

func TestParseProxyLinePreservesVMessTCPHTTPAndTLSOptions(t *testing.T) {
	vmessJSON := `{"v":"2","ps":"vmess-http","add":"vmess.example.test","port":"443","id":"vmess-http-uuid","aid":"0","scy":"auto","net":"tcp","type":"http","host":"cdn.example.test","path":"/edge","tls":"tls","sni":"sni.example.test","alpn":"h2,http/1.1","fp":"chrome"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON))
	proxy, err := parseProxyLine(link)
	if err != nil { t.Fatalf("parseProxyLine: %v", err) }
	if proxy.Extra["network"] != "tcp" || proxy.Extra["tls"] != true ||
		proxy.Extra["servername"] != "sni.example.test" || proxy.Extra["client-fingerprint"] != "chrome" {
		t.Fatalf("VMess TLS/transport fields lost: %#v", proxy.Extra)
	}
	alpn, ok := proxy.Extra["alpn"].([]string)
	if !ok || len(alpn) != 2 || alpn[0] != "h2" || alpn[1] != "http/1.1" {
		t.Fatalf("VMess ALPN lost: %#v", proxy.Extra["alpn"])
	}
	httpOpts, ok := proxy.Extra["http-opts"].(map[string]any)
	if !ok || httpOpts["method"] != "GET" {
		t.Fatalf("VMess TCP HTTP header type lost: %#v", proxy.Extra["http-opts"])
	}
	paths, ok := httpOpts["path"].([]string)
	if !ok || len(paths) != 1 || paths[0] != "/edge" {
		t.Fatalf("VMess TCP HTTP path lost: %#v", httpOpts["path"])
	}
	headers, ok := httpOpts["headers"].(map[string]any)
	if !ok || headers["Host"] == nil {
		t.Fatalf("VMess TCP HTTP Host lost: %#v", httpOpts["headers"])
	}
}

func TestParseProxyLinePreservesVMessGRPCServiceName(t *testing.T) {
	vmessJSON := `{"v":"2","ps":"vmess-grpc","add":"grpc.example.test","port":"443","id":"grpc-uuid","aid":"0","scy":"auto","net":"grpc","path":"grpc-service"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON))
	proxy, err := parseProxyLine(link)
	if err != nil { t.Fatalf("parseProxyLine: %v", err) }
	grpcOpts, ok := proxy.Extra["grpc-opts"].(map[string]any)
	if !ok || grpcOpts["grpc-service-name"] != "grpc-service" {
		t.Fatalf("VMess gRPC service name lost: %#v", proxy.Extra["grpc-opts"])
	}
}

func TestParseProxyImportContentPreservesVLESSRealityOptions(t *testing.T) {
	content := "vless://test-uuid@example.com:443?type=tcp&security=reality&sni=www.example.com&pbk=public-key-value&sid=short-id&fp=chrome&flow=xtls-rprx-vision#reality-node"
	proxies, failures := parseProxyImportContent(content)
	if len(failures) != 0 || len(proxies) != 1 {
		t.Fatalf("proxies=%v failures=%v", proxies, failures)
	}
	p := proxies[0]
	if p.Type != "vless" || p.Server != "example.com" || p.Port != 443 {
		t.Fatalf("unexpected endpoint: %+v", p)
	}
	if p.Extra["uuid"] != "test-uuid" || p.Extra["flow"] != "xtls-rprx-vision" || p.Extra["servername"] != "www.example.com" {
		t.Fatalf("VLESS identity/TLS fields lost: %#v", p.Extra)
	}
	reality, ok := p.Extra["reality-opts"].(map[string]any)
	if !ok || reality["public-key"] != "public-key-value" || reality["short-id"] != "short-id" {
		t.Fatalf("Reality options lost: %#v", p.Extra["reality-opts"])
	}
	if p.Extra["client-fingerprint"] != "chrome" {
		t.Fatalf("client fingerprint lost: %#v", p.Extra)
	}
}

func TestParseProxyImportContentLegacyV2RayNServersJSON(t *testing.T) {
	var content strings.Builder
	content.WriteString(`{"version":"1.0","remarks":"Mihomo IPv6 配置","servers":[`)
	for i := 0; i < 80; i++ {
		if i > 0 { content.WriteByte(',') }
		port := 24580 + i
		fmt.Fprintf(&content, `{"address":"109.176.19.70","port":%d,"id":"legacy-vmess-uuid","alterId":0,"security":"auto","network":"ws","path":"/ws","remarks":"Mihomo-IPv6-%d"}`, port, port)
	}
	content.WriteString(`]}`)

	proxies, failures := parseProxyImportContent(content.String())
	if len(failures) != 0 { t.Fatalf("unexpected failures: %v", failures) }
	if len(proxies) != 80 { t.Fatalf("got %d proxies, want 80", len(proxies)) }
	for i, p := range proxies {
		wantPort := 24580 + i
		if p.Type != "vmess" || p.Server != "109.176.19.70" || p.Port != wantPort {
			t.Errorf("node %d endpoint/type mismatch: type=%q server=%q port=%d", i+1, p.Type, p.Server, p.Port)
		}
		if p.Name != fmt.Sprintf("Mihomo-IPv6-%d", wantPort) || p.Extra["uuid"] != "legacy-vmess-uuid" {
			t.Errorf("node %d name/UUID not preserved: name=%q extra=%#v", i+1, p.Name, p.Extra)
		}
		if p.Extra["network"] != "ws" || p.Extra["cipher"] != "auto" {
			t.Errorf("node %d VMess fields not preserved: %#v", i+1, p.Extra)
		}
		ws, ok := p.Extra["ws-opts"].(map[string]any)
		if !ok || ws["path"] != "/ws" {
			t.Errorf("node %d WebSocket path not preserved: %#v", i+1, p.Extra["ws-opts"])
		}
	}
}

func TestParseProxyImportContentPreservesVMessLinkOptions(t *testing.T) {
	vmessJSON := `{"v":"2","ps":"link-name","add":"109.176.19.70","port":"22080","id":"test-uuid","aid":"0","scy":"auto","net":"ws","type":"none","host":"ws.example.test","path":"/ws","tls":""}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON))
	content := fmt.Sprintf(`{"protocol":"vmess","servers":[{"name":"imported-vmess","vmess_link":%q}]}`, link)

	proxies, failures := parseProxyImportContent(content)
	if len(failures) != 0 {
		t.Fatalf("unexpected failures: %v", failures)
	}
	if len(proxies) != 1 {
		t.Fatalf("got %d proxies, want 1", len(proxies))
	}
	p := proxies[0]
	if p.Type != "vmess" || p.Server != "109.176.19.70" || p.Port != 22080 {
		t.Fatalf("unexpected VMess endpoint: %+v", p)
	}
	if p.Name != "imported-vmess" || p.Extra["uuid"] != "test-uuid" {
		t.Fatalf("name/UUID not preserved: name=%q extra=%#v", p.Name, p.Extra)
	}
	if p.Extra["network"] != "ws" || p.Extra["cipher"] != "auto" {
		t.Fatalf("VMess transport/cipher not preserved: %#v", p.Extra)
	}
	ws, ok := p.Extra["ws-opts"].(map[string]any)
	if !ok || ws["path"] != "/ws" {
		t.Fatalf("WebSocket path not preserved: %#v", p.Extra["ws-opts"])
	}
	headers, ok := ws["headers"].(map[string]any)
	if !ok || headers["Host"] != "ws.example.test" {
		t.Fatalf("WebSocket Host not preserved: %#v", ws)
	}
}

func TestParseProxyImportContentPreservesStructuredVMessOptions(t *testing.T) {
	content := `{
		"protocol":"vmess",
		"servers":[
			{"name":"vmess-json","server":"109.176.19.70","port":22081,
			 "uuid":"structured-uuid","alterId":0,"cipher":"auto",
			 "network":"ws","host":"ws.example.test","path":"/ws","tls":false}
		]
	}`
	proxies, failures := parseProxyImportContent(content)
	if len(failures) != 0 || len(proxies) != 1 {
		t.Fatalf("proxies=%v failures=%v", proxies, failures)
	}
	p := proxies[0]
	if p.Extra["uuid"] != "structured-uuid" || p.Extra["network"] != "ws" {
		t.Fatalf("structured VMess fields not preserved: %#v", p.Extra)
	}
	ws, ok := p.Extra["ws-opts"].(map[string]any)
	if !ok || ws["path"] != "/ws" {
		t.Fatalf("structured WebSocket path not preserved: %#v", p.Extra["ws-opts"])
	}
}

func TestParseProxyImportContentRejectsMalformedJSON(t *testing.T) {
	proxies, failures := parseProxyImportContent(`{"protocol":"socks5","servers":[`)
	if len(proxies) != 0 || len(failures) == 0 {
		t.Fatalf("expected malformed JSON failure, got proxies=%v failures=%v", proxies, failures)
	}
}

func TestWaitForMihomoAPIVersionConfirmsRunningVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"v1.2.3"}`))
	}))
	defer server.Close()

	app := &App{cfg: Config{MihomoAPI: server.URL}}
	if err := app.waitForMihomoAPIVersion("v1.2.3", time.Second); err != nil {
		t.Fatalf("waitForMihomoAPIVersion() unexpected error: %v", err)
	}
}

func TestWaitForMihomoAPIVersionRejectsWrongRunningVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"v1.2.2"}`))
	}))
	defer server.Close()

	app := &App{cfg: Config{MihomoAPI: server.URL}}
	err := app.waitForMihomoAPIVersion("v1.2.3", 25*time.Millisecond)
	if err == nil {
		t.Fatal("waitForMihomoAPIVersion() accepted a mismatched running version")
	}
	if !strings.Contains(err.Error(), "运行版本不匹配") {
		t.Fatalf("error = %q, want version mismatch diagnostic", err)
	}
}

func TestHandleGetAgentsExposesPendingAndCompletedCommandState(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "agent-command-state.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const machineCode = "node_status"
	pending := `{"id":"cmd-2","type":"update_mihomo","version":"v1.2.3","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	previous := `{"id":"cmd-1","type":"update_mihomo","status":"failed","message":"previous update failed","updated_at":123}`
	if err := store.UpdateSettings(map[string]string{
		"agent_token":                         "global-secret",
		"agent_machine_" + machineCode:        "dedicated-secret",
		"agent_command_" + machineCode:        pending,
		"agent_command_result_" + machineCode: previous,
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}

	app := &App{store: store}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	rec := httptest.NewRecorder()
	app.handleGetAgents(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var payload map[string]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	node := payload[machineCode]
	if node["token_configured"] != true {
		t.Fatalf("token_configured = %#v, want true for an authorized Agent", node["token_configured"])
	}
	pendingCommand, ok := node["pending_command"].(map[string]any)
	if !ok || pendingCommand["id"] != "cmd-2" || pendingCommand["version"] != "v1.2.3" {
		t.Fatalf("pending_command = %#v, want pending Mihomo update cmd-2/v1.2.3", node["pending_command"])
	}
	commandResult, ok := node["command_result"].(map[string]any)
	if !ok || commandResult["id"] != "cmd-1" || commandResult["status"] != "failed" {
		t.Fatalf("command_result = %#v, want previous failed result cmd-1", node["command_result"])
	}
}

func TestRunningMihomoAPIVersionReportsControllerVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"v1.19.33"}`))
	}))
	defer server.Close()

	app := &App{cfg: Config{MihomoAPI: server.URL}}
	version, err := app.runningMihomoAPIVersion()
	if err != nil {
		t.Fatalf("runningMihomoAPIVersion() error = %v", err)
	}
	if version != "v1.19.33" {
		t.Fatalf("running version = %q, want v1.19.33", version)
	}
}

func TestRunningMihomoAPIVersionRejectsUnavailableController(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "controller unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	app := &App{cfg: Config{MihomoAPI: server.URL}}
	if version, err := app.runningMihomoAPIVersion(); err == nil {
		t.Fatalf("runningMihomoAPIVersion() = %q, nil error; want API error", version)
	}
}

func TestDecodeLimitedRejectsTrailingJSONAndOversizedBodies(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		max  int64
		want string
	}{
		{name: "trailing JSON value", body: `{"status":"succeeded"} {}`, max: 128, want: "invalid character"},
		{name: "oversized body", body: `{"status":"succeeded"}`, max: 8, want: "超过"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			var payload map[string]any
			err := decodeLimited(req, tc.max, "test limit", &payload)
			if err == nil {
				t.Fatal("decodeLimited() succeeded, want error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("decodeLimited() error = %q, want substring %q", err, tc.want)
			}
		})
	}
}

func TestHandleOverviewUsesDashboardRemoteAgentFieldNames(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "overview-agent-fields.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const code = "node_overview"
	if err := store.UpdateSettings(map[string]string{
		"agent_token":                 "global-secret",
		"agent_machine_" + code:       "dedicated-secret",
		"agent_status_" + code:        `{"received_at":` + strconv.FormatInt(time.Now().Unix(), 10) + `,"mihomo_version":"v1.19.3","mihomo_healthy":true,"connections":4,"download_speed":100,"upload_speed":50,"download_total":1000,"upload_total":2000}`,
		"agent_machine_blank_token":   "   ",
		"agent_lastseen_blank_token":  strconv.FormatInt(time.Now().Unix(), 10),
		"agent_status_blank_token":    `{"received_at":` + strconv.FormatInt(time.Now().Unix(), 10) + `,"mihomo_healthy":true}`,
		"agent_machine_global_token":  "global-secret",
		"agent_lastseen_global_token": strconv.FormatInt(time.Now().Unix(), 10),
		"agent_status_global_token":   `{"received_at":` + strconv.FormatInt(time.Now().Unix(), 10) + `,"mihomo_healthy":true}`,
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/connections" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"downloadTotal":0,"uploadTotal":0,"connections":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	app := &App{store: store, cfg: Config{MihomoAPI: upstream.URL}}
	rec := httptest.NewRecorder()
	app.handleOverview(rec, httptest.NewRequest(http.MethodGet, "/api/v1/monitor/overview", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	for key, want := range map[string]float64{
		"remote_node_total":     1,
		"remote_online":         1,
		"remote_mihomo_healthy": 1,
		"agent_total":           1,
		"agent_online":          1,
		"mihomo_healthy":        1,
	} {
		if got, ok := payload[key].(float64); !ok || got != want {
			t.Errorf("%s = %#v, want %v", key, payload[key], want)
		}
	}
	nodes, ok := payload["remote_nodes"].([]any)
	if !ok || len(nodes) != 1 {
		t.Fatalf("remote_nodes = %#v, want one node", payload["remote_nodes"])
	}
	node, ok := nodes[0].(map[string]any)
	if !ok {
		t.Fatalf("remote_nodes[0] = %#v, want object", nodes[0])
	}
	if node["mihomo_version"] != "v1.19.3" || node["updated_at"] == "" {
		t.Fatalf("node telemetry missing version or update timestamp: %#v", node)
	}
}

func TestHandleAgentMihomoUpdateInfoUsesHeartbeatSettings(t *testing.T) {
	tests := []struct {
		name       string
		status     string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "unsupported architecture is rejected without legacy table",
			status:     `{"os":"linux","arch":"mips"}`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "尚未上报受支持的架构",
		},
		{
			name:       "missing architecture is rejected without legacy table",
			status:     `{"os":"linux"}`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "尚未上报受支持的架构",
		},
		{
			name:       "malformed heartbeat JSON is rejected",
			status:     `{"os":`,
			wantStatus: http.StatusBadRequest,
			wantBody:   "状态数据格式无效",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := OpenStore(filepath.Join(t.TempDir(), "agent-mihomo-update.db"))
			if err != nil {
				t.Fatalf("OpenStore: %v", err)
			}
			defer store.db.Close()

			const code = "node_update_test"
			if err := store.UpdateSettings(map[string]string{
				"agent_machine_" + code: "dedicated-secret",
				"agent_status_" + code:  tt.status,
			}); err != nil {
				t.Fatalf("UpdateSettings: %v", err)
			}
			app := &App{store: store}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/mihomo/update?machine_code="+code, nil)
			rec := httptest.NewRecorder()
			app.handleAgentMihomoUpdateInfo(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Fatalf("body = %q, want substring %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestImportedProxiesRemainUnboundUntilExplicitlyAssociated(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "proxy-import-unbound.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	app := &App{store: store}
	content := `{"protocol":"socks5","servers":[{"name":"imported-unbound","server":"192.0.2.20","port":1080}]}`
	body, err := json.Marshal(map[string]string{"content": content})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/proxies/import", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	app.handleImportProxies(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	proxies, err := store.ListProxies()
	if err != nil {
		t.Fatalf("ListProxies: %v", err)
	}
	if len(proxies) != 1 {
		t.Fatalf("stored proxy count = %d, want 1", len(proxies))
	}
	if proxies[0].MachineCode != "" {
		t.Fatalf("imported proxy machine_code = %q, want empty/unbound", proxies[0].MachineCode)
	}
	generated, err := buildConfigFromProxies(proxies, "node-a", "test-secret")
	if err != nil {
		t.Fatalf("buildConfigFromProxies: %v", err)
	}
	if strings.Contains(generated, "imported-unbound") {
		t.Fatal("imported proxy without an association must not enter any node config")
	}
}

func TestImportProxiesPersistsAndFeedsGeneratedConfig(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "proxy-import-integration.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	app := &App{store: store}
	content := `{
		"protocol":"socks5",
		"authentication":{"enabled":true,"username":"import-user","password":"import-pass"},
		"servers":[
			{"name":"imported-proxy-a","server":"192.0.2.10","port":1080,"udp":true},
			{"name":"imported-proxy-b","server":"192.0.2.11","port":1081,"udp":false}
		]
	}`
	body, err := json.Marshal(map[string]string{"content": content})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/proxies/import", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	app.handleImportProxies(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var result struct {
		Success    int  `json:"success"`
		Fail       int  `json:"fail"`
		SyncFailed bool `json:"sync_failed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	if result.Success != 2 || result.Fail != 0 || result.SyncFailed {
		t.Fatalf("unexpected import result: %+v", result)
	}

	proxies, err := store.ListProxies()
	if err != nil {
		t.Fatalf("ListProxies: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("stored proxy count = %d, want 2", len(proxies))
	}
	for _, proxy := range proxies {
		if proxy.Mode != "rule" {
			t.Errorf("imported proxy %q mode = %q, want rule", proxy.Name, proxy.Mode)
		}
	}
	for i := range proxies {
		proxies[i].MachineCode = "__GLOBAL__"
	}
	generated, err := buildConfigFromProxies(proxies, "", "test-secret")
	if err != nil {
		t.Fatalf("buildConfigFromProxies: %v", err)
	}
	for _, want := range []string{
		"name: imported-proxy-a",
		"name: imported-proxy-b",
		"server: 192.0.2.10",
		"server: 192.0.2.11",
		"DOMAIN-SUFFIX,dns.alidns.com,imported-proxy-a",
		"MATCH,REJECT",
	} {
		if !strings.Contains(generated, want) {
			t.Errorf("generated config missing %q:\\n%s", want, generated)
		}
	}
}

func TestAgentCommandAckIsAtomicAndRejectsStaleIDs(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "command-ack.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const code = "cmd_atomic_01"
	if err := store.UpdateSettings(map[string]string{
		"agent_command_" + code: `{"id":"cmd-1","type":"update_mihomo","version":"v1.2.3"}`,
	}); err != nil {
		t.Fatalf("seed pending command: %v", err)
	}
	duplicate, matched, err := store.AckAgentCommand(code, "wrong-id", "success", "", 1)
	if err != nil || matched || duplicate {
		t.Fatalf("stale command ACK = duplicate:%v matched:%v err:%v", duplicate, matched, err)
	}
	settings, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings after stale ACK: %v", err)
	}
	if settings["agent_command_"+code] == "" || settings["agent_command_result_"+code] != "" {
		t.Fatalf("stale ACK changed queue state: %#v", settings)
	}

	duplicate, matched, err = store.AckAgentCommand(code, "cmd-1", "success", "", 2)
	if err != nil || !matched || duplicate {
		t.Fatalf("valid command ACK = duplicate:%v matched:%v err:%v", duplicate, matched, err)
	}
	settings, err = store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings after completion: %v", err)
	}
	if settings["agent_command_"+code] != "" || settings["agent_command_result_"+code] == "" {
		t.Fatalf("completion was not committed as a unit: %#v", settings)
	}
	duplicate, matched, err = store.AckAgentCommand(code, "cmd-1", "success", "", 3)
	if err != nil || !matched || !duplicate {
		t.Fatalf("duplicate ACK = duplicate:%v matched:%v err:%v", duplicate, matched, err)
	}
}

func TestHandleAgentCommandSerializesWithQueueAndAck(t *testing.T) {
	app, code, token := websocketTestApp(t)
	if err := app.store.UpdateSettings(map[string]string{
		"agent_command_" + code: `{"id":"cmd-http-1","type":"update_mihomo"}`,
	}); err != nil {
		t.Fatalf("seed pending command: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/command", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	app.handleAgentCommand(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Command map[string]string `json:"command"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode command response: %v", err)
	}
	if body.Command["id"] != "cmd-http-1" {
		t.Fatalf("command ID = %q, want cmd-http-1", body.Command["id"])
	}
}

// TestAgentTokenGenerateAndRegisterLifecycle covers the full dedicated-token
// issuance and registration path, including duplicate issuance and global-token rejection.
func TestAgentTokenGenerateAndRegisterLifecycle(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "agent-token-lifecycle.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const machineCode = "a1b2c3d4e5f"
	const globalToken = "global-token-for-test"
	app := &App{store: store, jwtKey: []byte("test-agent-jwt-signing-key")}
	if err := store.UpdateSettings(map[string]string{"agent_token": globalToken}); err != nil {
		t.Fatalf("seed global token: %v", err)
	}

	requestGenerate := func(code string) *httptest.ResponseRecorder {
		body := strings.NewReader(`{"machine_code":` + strconv.Quote(code) + `}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/generate", body)
		req = req.WithContext(context.WithValue(req.Context(), userKey, &User{Role: "admin"}))
		rec := httptest.NewRecorder()
		app.handleGenerateAgentToken(rec, req)
		return rec
	}

	generated := requestGenerate(machineCode)
	if generated.Code != http.StatusOK {
		t.Fatalf("generate status = %d, body=%s", generated.Code, generated.Body.String())
	}
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(generated.Body.Bytes(), &issued); err != nil || strings.TrimSpace(issued.Token) == "" {
		t.Fatalf("decode generated token: token=%q err=%v", issued.Token, err)
	}

	// A second generation must not rotate or overwrite the credential.
	duplicate := requestGenerate(machineCode)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate generate status = %d, want %d; body=%s", duplicate.Code, http.StatusConflict, duplicate.Body.String())
	}
	settings, err := store.GetSettings()
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if settings["agent_machine_"+machineCode] != issued.Token {
		t.Fatal("duplicate generation changed the original dedicated token")
	}

	register := func(secret string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"machine_code": machineCode, "secret": secret})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register", strings.NewReader(string(body)))
		rec := httptest.NewRecorder()
		app.handleAgentRegister(rec, req)
		return rec
	}

	if rejected := register(globalToken); rejected.Code != http.StatusForbidden {
		t.Fatalf("global token registration status = %d, want %d; body=%s", rejected.Code, http.StatusForbidden, rejected.Body.String())
	}
	if rejected := register("wrong-dedicated-token"); rejected.Code != http.StatusForbidden {
		t.Fatalf("wrong token registration status = %d, want %d; body=%s", rejected.Code, http.StatusForbidden, rejected.Body.String())
	}

	registered := register(issued.Token)
	if registered.Code != http.StatusOK {
		t.Fatalf("valid registration status = %d, body=%s", registered.Code, registered.Body.String())
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(registered.Body.Bytes(), &result); err != nil || strings.TrimSpace(result.Token) == "" {
		t.Fatalf("decode registered JWT: token=%q err=%v", result.Token, err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/ws", nil)
	req.Header.Set("Authorization", "Bearer "+result.Token)
	if code, err := app.agentMachineFromRequest(req); err != nil || code != machineCode {
		t.Fatalf("registered JWT authorization = %q, %v; want %q", code, err, machineCode)
	}

	// Removing the binding invalidates the already-issued JWT immediately.
	if err := store.DeleteAgentBinding(machineCode); err != nil {
		t.Fatalf("revoke binding: %v", err)
	}
	if _, err := app.agentMachineFromRequest(req); err == nil {
		t.Fatal("JWT remained valid after dedicated token binding was revoked")
	}
}

func TestParseProxyLineAutoDetectsProtocols(t *testing.T) {
	vmessPayload := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"vmess-node","add":"vmess.example.com","port":"443","id":"uuid-123","aid":"0","scy":"auto","net":"ws","tls":"tls","sni":"cdn.example.com","host":"cdn.example.com","path":"/ws"}`))
	tests := []struct {
		name       string
		line       string
		wantType   string
		wantServer string
		wantPort   int
	}{
		{name: "SOCKS5", line: "SOCKS5://user:pass@socks.example.com:1080#socks", wantType: "socks5", wantServer: "socks.example.com", wantPort: 1080},
		{name: "HTTP", line: "http://user:pass@http.example.com:8080#http", wantType: "http", wantServer: "http.example.com", wantPort: 8080},
		{name: "VLESS WebSocket TLS", line: "vless://uuid-456@vless.example.com:443?type=ws&security=tls&sni=cdn.example.com&host=cdn.example.com&path=%2Fws#vless", wantType: "vless", wantServer: "vless.example.com", wantPort: 443},
		{name: "Trojan", line: "trojan://secret@trojan.example.com:443?sni=cdn.example.com#trojan", wantType: "trojan", wantServer: "trojan.example.com", wantPort: 443},
		{name: "VMess", line: "vmess://" + vmessPayload, wantType: "vmess", wantServer: "vmess.example.com", wantPort: 443},
		{name: "Shadowsocks SIP002", line: "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:secret")) + "@ss.example.com:8388#ss", wantType: "ss", wantServer: "ss.example.com", wantPort: 8388},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parseProxyLine(tt.line)
			if err != nil {
				t.Fatalf("parseProxyLine() error = %v", err)
			}
			if p.Type != tt.wantType || p.Server != tt.wantServer || p.Port != tt.wantPort {
				t.Fatalf("parsed proxy = type %q server %q port %d", p.Type, p.Server, p.Port)
			}
			if p.Name == "" {
				t.Fatal("expected an automatically assigned name")
			}
			if msg := (&App{}).validateProxy(p); msg != "" {
				t.Fatalf("validateProxy() = %q", msg)
			}
		})
	}
}

func TestParseProxyLinePreservesProtocolOptions(t *testing.T) {
	p, err := parseProxyLine("vless://uuid-456@vless.example.com:443?type=ws&security=tls&sni=cdn.example.com&host=cdn.example.com&path=%2Fws#edge")
	if err != nil {
		t.Fatal(err)
	}
	if p.Extra["uuid"] != "uuid-456" || p.Extra["tls"] != true || p.Extra["servername"] != "cdn.example.com" {
		t.Fatalf("VLESS options not detected: %#v", p.Extra)
	}
	ws, ok := p.Extra["ws-opts"].(map[string]any)
	if !ok || ws["path"] != "/ws" {
		t.Fatalf("WebSocket options not detected: %#v", p.Extra["ws-opts"])
	}
}

func TestGetNodeConfigRemovesExplicitProxyListeners(t *testing.T) {
	app, code, _ := websocketTestApp(t)
	staleYAML := "mixed-port: 8080\nsecret: keep-this-secret\ntun:\n  enable: false\ndns:\n  enable: true\n"
	if err := app.store.SaveNodeConfig(code, staleYAML); err != nil {
		t.Fatalf("save stale node config: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/"+code+"/config", nil)
	req.SetPathValue("code", code)
	rec := httptest.NewRecorder()
	app.handleGetNodeConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var response struct {
		YAML string `json:"config_yaml"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode node config response: %v", err)
	}
	var normalized map[string]any
	if err := yaml.Unmarshal([]byte(response.YAML), &normalized); err != nil {
		t.Fatalf("decode normalized response YAML: %v", err)
	}
	if normalized["mixed-port"] != 7890 {
		t.Errorf("Agent mixed-port = %#v, want 7890: %s", normalized["mixed-port"], response.YAML)
	}
	for _, key := range []string{"port", "socks-port", "redir-port", "tproxy-port", "listeners"} {
		if _, exists := normalized[key]; exists {
			t.Errorf("Agent config must not expose additional listener %q: %s", key, response.YAML)
		}
	}
	if normalized["allow-lan"] != true || normalized["external-controller"] != "127.0.0.1:8088" {
		t.Fatalf("Agent listener security normalization failed: %s", response.YAML)
	}
	if !strings.Contains(response.YAML, "secret: keep-this-secret") || strings.Contains(response.YAML, "authentication:") ||
		!strings.Contains(response.YAML, "enable: false") ||
		!strings.Contains(response.YAML, "enable: true") {
		t.Fatalf("normalization did not preserve node-specific settings: %s", response.YAML)
	}

	stored, err := app.store.GetNodeConfig(code)
	if err != nil {
		t.Fatalf("read persisted node config: %v", err)
	}
	if stored == nil || stored.YAML != response.YAML {
		t.Fatalf("normalized config was not persisted: stored=%#v response=%q", stored, response.YAML)
	}
}

func TestSaveNodeConfigReportsYAMLParseError(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-yaml-error.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()
	const code = "node_yaml_error"
	if err := store.UpdateSettings(map[string]string{"agent_token": "global-secret", "agent_machine_" + code: "dedicated-secret"}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	app := &App{store: store}
	body := `{"config_yaml":"secret: node-secret\ntun:\n  enable: [invalid\ndns:\n  enable: true\n"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/nodes/"+code+"/config", strings.NewReader(body))
	req.SetPathValue("code", code)
	rec := httptest.NewRecorder()
	app.handleSaveNodeConfig(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Mihomo YAML 解析失败") || !strings.Contains(rec.Body.String(), "line") {
		t.Fatalf("response should include parser detail and line: %s", rec.Body.String())
	}
	cfg, err := store.GetNodeConfig(code)
	if err != nil {
		t.Fatalf("GetNodeConfig: %v", err)
	}
	if cfg != nil {
		t.Fatal("invalid YAML unexpectedly persisted")
	}
}

func TestSaveNodeConfigDistinguishesEmptyYAMLDocument(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-yaml-empty.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()
	const code = "node_yaml_empty"
	if err := store.UpdateSettings(map[string]string{"agent_token": "global-secret", "agent_machine_" + code: "dedicated-secret"}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	app := &App{store: store}
	body := `{"config_yaml":"---\n# empty\n"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/nodes/"+code+"/config", strings.NewReader(body))
	req.SetPathValue("code", code)
	rec := httptest.NewRecorder()
	app.handleSaveNodeConfig(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "配置为空") {
		t.Fatalf("expected explicit empty YAML error, status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSaveNodeConfigRemovesUnpublishedProxyPort(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-port.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const code = "node_port"
	if err := store.UpdateSettings(map[string]string{
		"agent_token":           "global-secret",
		"agent_machine_" + code: "dedicated-secret",
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	app := &App{store: store}
	body := `{"config_yaml":"mixed-port: 7899\nsecret: node-secret\ntun:\n  enable: false\ndns:\n  enable: false\n"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/nodes/"+code+"/config", strings.NewReader(body))
	req.SetPathValue("code", code)
	rec := httptest.NewRecorder()

	app.handleSaveNodeConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	cfg, err := store.GetNodeConfig(code)
	if err != nil {
		t.Fatalf("GetNodeConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("normalized node config was not persisted")
	}
	if !strings.Contains(cfg.YAML, "mixed-port: 7890") || strings.Contains(cfg.YAML, "port: 7899") {
		t.Fatalf("Agent mixed listener was not normalized to 7890 before persistence: %s", cfg.YAML)
	}
	if !strings.Contains(cfg.YAML, "secret: node-secret") {
		t.Fatalf("unrelated node settings were not preserved: %s", cfg.YAML)
	}
}

func TestMachineProxyModeAPIStoresModeIndependently(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "machine-proxy-mode-api.db"))
	if err != nil { t.Fatalf("OpenStore: %v", err) }
	defer store.db.Close()
	app := &App{store: store}

	put := httptest.NewRequest(http.MethodPut, "/api/v1/nodes/node-a/proxy-mode", strings.NewReader(`{"routing_mode":"return"}`))
	put.SetPathValue("code", "node-a")
	putRec := httptest.NewRecorder()
	app.handleSetMachineProxyMode(putRec, put)
	if putRec.Code != http.StatusOK { t.Fatalf("PUT status=%d body=%s", putRec.Code, putRec.Body.String()) }

	get := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/node-a/proxy-mode", nil)
	get.SetPathValue("code", "node-a")
	getRec := httptest.NewRecorder()
	app.handleGetMachineProxyMode(getRec, get)
	if getRec.Code != http.StatusOK || !strings.Contains(getRec.Body.String(), `"routing_mode":"return"`) { t.Fatalf("GET status=%d body=%s", getRec.Code, getRec.Body.String()) }

	bad := httptest.NewRequest(http.MethodPut, "/api/v1/nodes/node-a/proxy-mode", strings.NewReader(`{"routing_mode":"unknown"}`))
	bad.SetPathValue("code", "node-a")
	badRec := httptest.NewRecorder()
	app.handleSetMachineProxyMode(badRec, bad)
	if badRec.Code != http.StatusBadRequest { t.Fatalf("invalid mode status=%d body=%s", badRec.Code, badRec.Body.String()) }
}

func TestHandleUpdateSettingsReportsNodeSyncFailureAfterPersistingSettings(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "settings-node-sync.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.UpdateSettings(map[string]string{
		"agent_machine_node-a": "authorized-token",
		"agent_mihomo_secret_node-a": "test-secret",
	}); err != nil {
		t.Fatalf("seed Agent authorization: %v", err)
	}
	if err := store.SaveNodeConfig("node-a", "not: [valid: yaml"); err != nil {
		t.Fatalf("seed invalid node YAML: %v", err)
	}

	app := &App{store: store}
	body := `{"smartdns_routing_config":"{\"mode\":\"shared\",\"strategy\":\"fallback\"}"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings", strings.NewReader(body))
	rec := httptest.NewRecorder()
	app.handleUpdateSettings(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "设置已保存，但节点配置同步失败") {
		t.Fatalf("response must clearly report persisted settings and failed node sync: %s", rec.Body.String())
	}
	settings, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["smartdns_routing_config"] == "" {
		t.Fatal("validated setting should remain persisted when node sync fails")
	}
}
