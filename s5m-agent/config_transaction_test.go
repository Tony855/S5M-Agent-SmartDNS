package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotFileForTransactionPreservesExactPreviousBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	old := []byte("{\n  \"cidrs\": [\"198.51.100.8/32\"]\n}\n")
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}

	got, existed, err := snapshotFileForTransaction(path)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !existed || !bytes.Equal(got, old) {
		t.Fatalf("snapshot mismatch: existed=%v got=%q", existed, got)
	}
	backup, err := os.ReadFile(path + ".previous")
	if err != nil {
		t.Fatalf("read durable snapshot: %v", err)
	}
	if !bytes.Equal(backup, old) {
		t.Fatalf("backup mismatch: got %q want %q", backup, old)
	}
}

func TestSnapshotFileForTransactionRecordsMissingFileAndRemovesStaleBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path+".previous", []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}

	got, existed, err := snapshotFileForTransaction(path)
	if err != nil {
		t.Fatalf("snapshot missing file: %v", err)
	}
	if existed || got != nil {
		t.Fatalf("expected absent snapshot, existed=%v data=%q", existed, got)
	}
	if _, err := os.Lstat(path + ".previous"); !os.IsNotExist(err) {
		t.Fatalf("stale backup must be removed, Lstat error=%v", err)
	}
}

func TestRestoreFileSnapshotRestoresExactBytesAndRemovesFirstInstall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	old := []byte("old state\n")
	if err := os.WriteFile(path, []byte("candidate state"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreFileSnapshot(path, old, true); err != nil {
		t.Fatalf("restore old state: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, old) {
		t.Fatalf("restored bytes differ: got %q want %q", got, old)
	}
	if err := restoreFileSnapshot(path, nil, false); err != nil {
		t.Fatalf("restore first-install absence: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("first-install rollback must remove the file, Lstat error=%v", err)
	}
}

func TestRemoveTransactionBackupDeletesSidecar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path+".previous", []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeTransactionBackup(path); err != nil {
		t.Fatalf("remove transaction backup: %v", err)
	}
	if _, err := os.Lstat(path + ".previous"); !os.IsNotExist(err) {
		t.Fatalf("transaction backup should be removed, Lstat error=%v", err)
	}
}


func setupConfigTransactionFixture(t *testing.T) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("MIHOMO_HOME", dir)
	oldSmartPath := smartDNSConfigPath
	smartDNSConfigPath = filepath.Join(dir, "smartdns.conf")
	oldMerge := transactionMergeMihomo
	oldReload := transactionReloadMihomo
	oldApplySmart := transactionApplySmartDNS
	oldWait := transactionWaitSmartDNSHealthy
	oldRestart := transactionRestartSmartDNS
	oldWriteController := transactionWriteControllerConfig
	restore := func() {
		smartDNSConfigPath = oldSmartPath
		transactionMergeMihomo = oldMerge
		transactionReloadMihomo = oldReload
		transactionApplySmartDNS = oldApplySmart
		transactionWaitSmartDNSHealthy = oldWait
		transactionRestartSmartDNS = oldRestart
		transactionWriteControllerConfig = oldWriteController
	}
	t.Cleanup(restore)

	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("config.yaml", []byte("old-mihomo"))
	write("controller-route-cidrs.json", []byte("[\"192.0.2.10/32\"]"))
	write("controller-config.yaml", []byte("old-controller-hash"))
	if err := os.WriteFile(smartDNSConfigPath, []byte("old-smartdns"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir, restore
}

func TestConfigTransactionRestoresAllSnapshotsWhenMihomoReloadFails(t *testing.T) {
	dir, _ := setupConfigTransactionFixture(t)
	reloadCalls := 0
	transactionMergeMihomo = func(_ []byte, _ string) (bool, error) {
		if err := atomicWriteFile(mihomoConfigPath(), []byte("candidate-mihomo"), 0600); err != nil {
			return false, err
		}
		if err := atomicWriteFile(managedRouteCIDRsPath(), []byte("[\"198.51.100.20/32\"]"), 0600); err != nil {
			return false, err
		}
		return true, nil
	}
	transactionReloadMihomo = func() error {
		reloadCalls++
		if reloadCalls == 1 {
			return errors.New("injected Mihomo reload failure")
		}
		return nil // old configuration has been restored and reloads cleanly
	}
	restarts := 0
	transactionRestartSmartDNS = func() error { restarts++; return nil }
	transactionWaitSmartDNSHealthy = func(time.Duration) bool { return true }

	err := applyAgentConfigTransaction([]byte("desired-controller"), nil, false, "")
	if err == nil {
		t.Fatal("expected injected Mihomo reload failure")
	}
	assertFile := func(name string, want []byte) {
		t.Helper()
		got, readErr := os.ReadFile(filepath.Join(dir, name))
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s not restored: got %q want %q", name, got, want)
		}
	}
	assertFile("config.yaml", []byte("old-mihomo"))
	assertFile("controller-route-cidrs.json", []byte("[\"192.0.2.10/32\"]"))
	assertFile("controller-config.yaml", []byte("old-controller-hash"))
	assertFile("smartdns.conf", []byte("old-smartdns"))
	if reloadCalls != 2 {
		t.Fatalf("expected candidate and rollback reload, got %d calls", reloadCalls)
	}
	if restarts != 1 {
		t.Fatalf("expected SmartDNS restart during rollback, got %d", restarts)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.yaml.previous")); err != nil {
		t.Fatalf("Mihomo rollback copy should remain available after failed transaction: %v", err)
	}
}

func TestConfigTransactionRestoresSmartDNSAndManagedCIDRsWhenDNSHealthFails(t *testing.T) {
	dir, _ := setupConfigTransactionFixture(t)
	reloadCalls := 0
	transactionMergeMihomo = func(_ []byte, _ string) (bool, error) {
		if err := atomicWriteFile(mihomoConfigPath(), []byte("candidate-mihomo"), 0600); err != nil {
			return false, err
		}
		if err := atomicWriteFile(managedRouteCIDRsPath(), []byte("[\"203.0.113.30/32\"]"), 0600); err != nil {
			return false, err
		}
		return true, nil
	}
	transactionReloadMihomo = func() error { reloadCalls++; return nil }
	transactionApplySmartDNS = func(data []byte, cleanup bool) (string, error) {
		if cleanup {
			t.Fatal("joint transaction must retain SmartDNS backup until joint commit")
		}
		return "", atomicWriteFile(smartDNSConfigPath, data, 0600)
	}
	healthCalls := 0
	transactionWaitSmartDNSHealthy = func(time.Duration) bool {
		healthCalls++
		return healthCalls > 1 // candidate fails, restored configuration passes
	}
	restarts := 0
	transactionRestartSmartDNS = func() error { restarts++; return nil }

	err := applyAgentConfigTransaction([]byte("desired-controller"), []byte("candidate-smartdns"), true, "")
	if err == nil {
		t.Fatal("expected injected SmartDNS health-check failure")
	}
	for name, want := range map[string][]byte{
		"config.yaml":                  []byte("old-mihomo"),
		"controller-route-cidrs.json":  []byte("[\"192.0.2.10/32\"]"),
		"controller-config.yaml":       []byte("old-controller-hash"),
		"smartdns.conf":                []byte("old-smartdns"),
	} {
		got, readErr := os.ReadFile(filepath.Join(dir, name))
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s not restored: got %q want %q", name, got, want)
		}
	}
	if reloadCalls != 2 {
		t.Fatalf("expected candidate and rollback Mihomo reloads, got %d", reloadCalls)
	}
	if healthCalls != 2 || restarts != 1 {
		t.Fatalf("expected failed candidate DNS check plus successful rollback check; health=%d restarts=%d", healthCalls, restarts)
	}
	if _, err := os.Stat(filepath.Join(dir, "smartdns.conf.previous")); err != nil {
		t.Fatalf("SmartDNS rollback copy should remain available after failed transaction: %v", err)
	}
}
