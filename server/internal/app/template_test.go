package app

import (
	"strings"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateMihomoTemplate(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{name: "valid mapping", yaml: "mixed-port: 7890\nmode: rule\n"},
		{name: "empty", yaml: "  \n", wantErr: true},
		{name: "invalid syntax", yaml: "mixed-port: [\n", wantErr: true},
		{name: "empty document", yaml: "{}\n", wantErr: true},
		{name: "invalid secret type", yaml: "secret: 123\n", wantErr: true},
		{name: "invalid tun type", yaml: "tun: true\n", wantErr: true},
		{name: "invalid dns type", yaml: "dns: true\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMihomoTemplate(tt.yaml)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateMihomoTemplate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultMihomoTemplateIsUsableStarter(t *testing.T) {
	if err := validateMihomoTemplate(defaultMihomoTemplate); err != nil {
		t.Fatalf("default Mihomo template should be valid YAML: %v", err)
	}
	for _, want := range []string{
		"allow-lan: false",
		"127.0.0.1:6053",
		"external-controller: 127.0.0.1:8088",
		"listen: 127.0.0.1:5353",
		"DOMAIN-SUFFIX,v2net.cc,DIRECT",
		"enable: true",
	} {
		if !strings.Contains(defaultMihomoTemplate, want) {
			t.Errorf("default template missing %q", want)
		}
	}
	if strings.Contains(defaultMihomoTemplate, "151.242.11.70") ||
		strings.Contains(defaultMihomoTemplate, "0103da505e81003e") {
		t.Fatal("starter template must not expose a user's proxy endpoint or API secret")
	}

	for _, want := range []string{"proxies: []", "proxy-groups: []", "rules:", "tun:", "auto-route: true"} {
		if !strings.Contains(defaultMihomoTemplate, want) {
			t.Errorf("default template missing baseline section %q", want)
		}
	}
	for _, unwanted := range []string{"mixed-port:", "socks-port:", "redir-port:", "tproxy-port:", "listeners:", "allow-lan: true", "YOUR_PROXY_SERVER", "221111cdn"} {
		if strings.Contains(defaultMihomoTemplate, unwanted) {
			t.Fatalf("default template must not contain placeholder/hard-coded rule %q", unwanted)
		}
	}
}

func TestHashConfigIsStable(t *testing.T) {
	yaml := "mixed-port: 7890\nmode: rule\n"
	if got, want := hashConfig(yaml), hashConfig(yaml); got != want {
		t.Fatalf("hashConfig is not stable: %q != %q", got, want)
	}
	if hashConfig(yaml) == hashConfig(yaml+"# changed\n") {
		t.Fatal("different YAML unexpectedly produced the same hash")
	}
}


func TestPublishMihomoTemplateRejectsMalformedJSON(t *testing.T) {
	a, cleanup := newTemplateRollbackTestApp(t)
	defer cleanup()
	if err := a.store.UpdateSettings(map[string]string{"mihomo_template_draft": defaultMihomoTemplate}); err != nil {
		t.Fatalf("seed draft: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mihomo/template/publish", strings.NewReader("{"))
	rec := httptest.NewRecorder()
	a.handlePublishMihomoTemplate(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	var count int
	if err := a.store.db.QueryRow("SELECT COUNT(*) FROM mihomo_template_versions").Scan(&count); err != nil {
		t.Fatalf("count versions: %v", err)
	}
	if count != 0 {
		t.Fatalf("malformed publish request created %d versions", count)
	}
}

func TestGetNodeTemplateStatusFailsOnConfigReadError(t *testing.T) {
	a, cleanup := newTemplateRollbackTestApp(t)
	defer cleanup()
	if _, err := a.store.db.Exec("INSERT INTO node_template_bindings(machine_code,template_version,config_sha256,source,updated_at) VALUES('node-a',1,'hash','template','now')"); err != nil {
		t.Fatalf("seed binding: %v", err)
	}
	if _, err := a.store.db.Exec("DROP TABLE node_configs"); err != nil {
		t.Fatalf("drop node configs: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mihomo/template/status", nil)
	rec := httptest.NewRecorder()
	a.handleGetNodeTemplateStatus(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}
