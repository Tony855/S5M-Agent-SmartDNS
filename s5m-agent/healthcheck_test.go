package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHealthcheckSupportsSmartDNSDisabledMode(t *testing.T) {
	runHealthcheckFixture(t, true, false)
}

func TestHealthcheckRejectsRunningSmartDNSWhenDisabled(t *testing.T) {
	runHealthcheckFixtureExpected(t, true, true, false)
}

func TestHealthcheckRequiresSmartDNSWhenEnabled(t *testing.T) {
	runHealthcheckFixture(t, false, true)
}

func runHealthcheckFixture(t *testing.T, disabled, smartDNSRunning bool) {
	t.Helper()
	runHealthcheckFixtureExpected(t, disabled, smartDNSRunning, true)
}

func runHealthcheckFixtureExpected(t *testing.T, disabled, smartDNSRunning, wantSuccess bool) {
	t.Helper()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(dataDir, 0700); err != nil { t.Fatal(err) }
	if err := os.MkdirAll(binDir, 0700); err != nil { t.Fatal(err) }

	configPath := filepath.Join(dataDir, "config.yaml")
	config := "dns:\n  ipv6: true\n  listen: 127.0.0.1:5353\n"
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil { t.Fatal(err) }
	smartConfigPath := filepath.Join(dataDir, "smartdns.conf")
	smartConfig := "bind 127.0.0.1:6054 -group china-dot\nbind-tcp 127.0.0.1:6054 -group china-dot\n"
	if err := os.WriteFile(smartConfigPath, []byte(smartConfig), 0600); err != nil { t.Fatal(err) }

	markerPath := filepath.Join(dataDir, "smartdns.disabled")
	if disabled {
		if err := os.WriteFile(markerPath, []byte("disabled\n"), 0600); err != nil { t.Fatal(err) }
	}

	stubs := map[string]string{
		"wget": "#!/bin/sh\nexit 0\n",
		"pidof": "#!/bin/sh\ncase \"$1\" in mihomo) exit 0 ;; smartdns) [ \"$MOCK_SMARTDNS\" = 1 ] ;; *) exit 1 ;; esac\n",
		"dig": "#!/bin/sh\nfor arg in \"$@\"; do last=\"$arg\"; done\ncase \"$last\" in AAAA) echo 2001:db8::1 ;; *) echo 192.0.2.1 ;; esac\n",
	}
	for name, content := range stubs {
		path := filepath.Join(binDir, name)
		if err := os.WriteFile(path, []byte(content), 0700); err != nil { t.Fatal(err) }
	}

	for _, scriptName := range []string{"healthcheck.sh", filepath.Join("smartdns", "healthcheck.sh")} {
		t.Run(scriptName, func(t *testing.T) {
			script, err := os.ReadFile(scriptName)
			if err != nil { t.Fatal(err) }
			body := strings.ReplaceAll(string(script), "/data/smartdns.disabled", markerPath)
			body = strings.ReplaceAll(body, "/data/config.yaml", configPath)
			body = strings.ReplaceAll(body, "/data/smartdns.conf", smartConfigPath)
			scriptPath := filepath.Join(root, "healthcheck.sh")
			if err := os.WriteFile(scriptPath, []byte(body), 0700); err != nil { t.Fatal(err) }

			cmd := exec.Command("sh", scriptPath)
			cmd.Env = append(os.Environ(),
				"PATH="+binDir+":"+os.Getenv("PATH"),
				"MOCK_SMARTDNS="+map[bool]string{true:"1", false:"0"}[smartDNSRunning],
			)
			output, err := cmd.CombinedOutput()
			if wantSuccess && err != nil {
				t.Fatalf("healthcheck disabled=%v smartDNSRunning=%v failed: %v\n%s", disabled, smartDNSRunning, err, output)
			}
			if !wantSuccess && err == nil {
				t.Fatalf("healthcheck disabled=%v smartDNSRunning=%v unexpectedly succeeded:\n%s", disabled, smartDNSRunning, output)
			}
		})
	}
}
