package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSmartDNSServiceRunWaitsForIngressProofAndStopsWhenProofIsLost(t *testing.T) {
	scriptPath := filepath.Join("smartdns", "services", "smartdns", "run")
	script, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read SmartDNS service run script: %v", err)
	}

	dir := t.TempDir()
	ready := filepath.Join(dir, "ingress.ready")
	started := filepath.Join(dir, "smartdns.started")
	stopped := filepath.Join(dir, "smartdns.stopped")
	mockAgent := filepath.Join(dir, "agent")
	mockSmartDNS := filepath.Join(dir, "smartdns")
	if err := os.WriteFile(mockAgent, []byte("#!/bin/sh\n[ -f \"$READY_FILE\" ]\n"), 0700); err != nil {
		t.Fatalf("write mock Agent guard: %v", err)
	}
	mock := "#!/bin/sh\ntrap 'printf stopped > \"$STOPPED_FILE\"; exit 0' TERM INT\nprintf started > \"$STARTED_FILE\"\nwhile :; do sleep 1; done\n"
	if err := os.WriteFile(mockSmartDNS, []byte(mock), 0700); err != nil {
		t.Fatalf("write mock SmartDNS: %v", err)
	}

	runScript := strings.ReplaceAll(string(script), "/data/smartdns.disabled", filepath.Join(dir, "smartdns.disabled"))
	runScript = strings.ReplaceAll(runScript, "/usr/sbin/smartdns", mockSmartDNS)
	runScript = strings.ReplaceAll(runScript, "/app/s5m-agent", mockAgent)
	runScript = strings.ReplaceAll(runScript, "sleep 5", "sleep 0.05")
	cmd := exec.Command("sh", "-c", runScript)
	cmd.Env = append(os.Environ(), "READY_FILE="+ready, "STARTED_FILE="+started, "STOPPED_FILE="+stopped)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start service run script: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_, _ = cmd.Process.Wait()
		}
	})

	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(started); !os.IsNotExist(err) {
		t.Fatalf("SmartDNS started without ingress proof, stat err=%v", err)
	}
	if err := os.WriteFile(ready, []byte("ready"), 0600); err != nil {
		t.Fatalf("publish mock ingress proof: %v", err)
	}
	waitFor := func(path string) bool {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(path); err == nil {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}
	if !waitFor(started) {
		t.Fatal("SmartDNS did not start after ingress proof became valid")
	}
	if err := os.Remove(ready); err != nil {
		t.Fatalf("remove mock ingress proof: %v", err)
	}
	if !waitFor(stopped) {
		t.Fatal("SmartDNS listener was not stopped after ingress proof was lost")
	}
}

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
	mockAgent := filepath.Join(dir, "agent")
	mock := "#!/bin/sh\nprintf started > " + started + "\nexec sleep 30\n"
	if err := os.WriteFile(mockSmartDNS, []byte(mock), 0700); err != nil {
		t.Fatalf("write mock SmartDNS: %v", err)
	}
	if err := os.WriteFile(mockAgent, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatalf("write mock Agent guard: %v", err)
	}
	if err := os.WriteFile(marker, []byte("disabled\n"), 0600); err != nil {
		t.Fatalf("create disabled marker: %v", err)
	}

	runScript := strings.ReplaceAll(string(script), "/data/smartdns.disabled", marker)
	runScript = strings.ReplaceAll(runScript, "/usr/sbin/smartdns", mockSmartDNS)
	runScript = strings.ReplaceAll(runScript, "/app/s5m-agent", mockAgent)
	cmd := exec.Command("sh", "-c", runScript)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start service run script: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
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
