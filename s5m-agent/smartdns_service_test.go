package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSmartDNSServiceRunWakesAfterDisabledMarkerRemoved(t *testing.T) {
	scriptPath := filepath.Join("smartdns", "services", "smartdns", "run")
	script, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read SmartDNS service run script: %v", err)
	}

	dir := t.TempDir()
	marker := filepath.Join(dir, "smartdns.disabled")
	started := filepath.Join(dir, "smartdns.started")
	mockSmartDNS := filepath.Join(dir, "smartdns")
	mock := "#!/bin/sh\nprintf started > " + started + "\nexec sleep 30\n"
	if err := os.WriteFile(mockSmartDNS, []byte(mock), 0700); err != nil {
		t.Fatalf("write mock SmartDNS: %v", err)
	}
	if err := os.WriteFile(marker, []byte("disabled\n"), 0600); err != nil {
		t.Fatalf("create disabled marker: %v", err)
	}

	runScript := strings.ReplaceAll(string(script), "/data/smartdns.disabled", marker)
	runScript = strings.ReplaceAll(runScript, "/usr/sbin/smartdns", mockSmartDNS)
	cmd := exec.Command("sh", "-c", runScript)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start service run script: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(started); !os.IsNotExist(err) {
		t.Fatalf("SmartDNS started while disabled marker exists, stat err=%v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatalf("remove disabled marker: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(started); err == nil && string(data) == "started" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("SmartDNS service did not start after the disabled marker was removed")
}
