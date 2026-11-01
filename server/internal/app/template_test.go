package app

import (
	"strings"
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
		"external-controller: 127.0.0.1:8088",
		"listen: 127.0.0.1:5353",
		"DOMAIN-SUFFIX,v2net.cc,DIRECT",
		"enable: false",
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

func TestValidateAgentPublishedProxyPort(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{name: "published port", yaml: "mixed-port: 7890\nmode: rule\n"},
		{name: "controller port", yaml: "mixed-port: 8080\nmode: rule\n", wantErr: true},
		{name: "custom unexposed port", yaml: "mixed-port: 7899\nmode: rule\n", wantErr: true},
		{name: "missing mixed port", yaml: "socks-port: 7890\nmode: rule\n", wantErr: true},
		{name: "string port", yaml: "mixed-port: \"7890\"\nmode: rule\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAgentPublishedProxyPort(tt.yaml)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateAgentPublishedProxyPort() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
