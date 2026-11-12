package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func writeRecoveryFixtureFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverInterruptedConfigTransactionRestoresAllSnapshots(t *testing.T) {
	dir, _ := setupConfigTransactionFixture(t)
	transactionReloadMihomo = func() error { return nil }
	transactionRestartSmartDNS = func() error { return nil }
	transactionWaitSmartDNSHealthy = func(time.Duration) bool { return true }
	old := configTransactionRecoveryRecord{
		Version: 1, Phase: "prepared",
		SmartDNS: transactionRecoveryFile{Data: []byte("old-smartdns"), Existed: true},
		Mihomo: transactionRecoveryFile{Data: []byte("old-mihomo"), Existed: true},
		ManagedRoutes: transactionRecoveryFile{Data: []byte("old-routes"), Existed: true},
		Controller: transactionRecoveryFile{Data: []byte("old-controller-hash"), Existed: true},
	}
	for name, data := range map[string][]byte{
		"smartdns.conf": []byte("candidate-smartdns"),
		"config.yaml": []byte("candidate-mihomo"),
		"controller-route-cidrs.json": []byte("candidate-routes"),
		"controller-config.yaml": []byte("candidate-controller-hash"),
	} {
		writeRecoveryFixtureFile(t, filepath.Join(dir, name), data)
	}
	if err := writeConfigTransactionRecoveryRecord(old); err != nil {
		t.Fatalf("write recovery journal: %v", err)
	}

	if err := recoverInterruptedConfigTransaction(); err != nil {
		t.Fatalf("recover interrupted transaction: %v", err)
	}
	for name, want := range map[string][]byte{
		"smartdns.conf": []byte("old-smartdns"),
		"config.yaml": []byte("old-mihomo"),
		"controller-route-cidrs.json": []byte("old-routes"),
		"controller-config.yaml": []byte("old-controller-hash"),
	} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s = %q, err=%v; want %q", name, got, err, want)
		}
	}
	if _, err := os.Lstat(configTransactionRecoveryPath()); !os.IsNotExist(err) {
		t.Fatalf("recovery journal should be removed after successful recovery: %v", err)
	}
}

func TestRecoverCommittedConfigTransactionKeepsNewStateAndCleansJournal(t *testing.T) {
	dir, _ := setupConfigTransactionFixture(t)
	transactionReloadMihomo = func() error { t.Fatal("committed transaction must not roll back/reload"); return nil }
	record := configTransactionRecoveryRecord{
		Version: 1, Phase: "committed",
		SmartDNS: transactionRecoveryFile{},
		Mihomo: transactionRecoveryFile{Data: []byte("old-mihomo"), Existed: true},
		ManagedRoutes: transactionRecoveryFile{Data: []byte("old-routes"), Existed: true},
		Controller: transactionRecoveryFile{Data: []byte("old-controller-hash"), Existed: true},
	}
	writeRecoveryFixtureFile(t, filepath.Join(dir, "config.yaml"), []byte("committed-mihomo"))
	if err := writeConfigTransactionRecoveryRecord(record); err != nil {
		t.Fatal(err)
	}
	if err := recoverInterruptedConfigTransaction(); err != nil {
		t.Fatalf("clean committed transaction journal: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil || string(got) != "committed-mihomo" {
		t.Fatalf("committed config changed: %q, err=%v", got, err)
	}
	if _, err := os.Lstat(configTransactionRecoveryPath()); !os.IsNotExist(err) {
		t.Fatalf("committed journal should be removed: %v", err)
	}
}

func TestRecoverInterruptedConfigTransactionRetainsJournalOnRestoreFailure(t *testing.T) {
	dir, _ := setupConfigTransactionFixture(t)
	transactionReloadMihomo = func() error { return nil }
	if err := os.Remove(filepath.Join(dir, "config.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "config.yaml"), 0700); err != nil {
		t.Fatal(err)
	}
	record := configTransactionRecoveryRecord{
		Version: 1, Phase: "prepared",
		SmartDNS: transactionRecoveryFile{},
		Mihomo: transactionRecoveryFile{Data: []byte("old-mihomo"), Existed: true},
		ManagedRoutes: transactionRecoveryFile{Data: []byte("old-routes"), Existed: true},
		Controller: transactionRecoveryFile{Data: []byte("old-controller-hash"), Existed: true},
	}
	if err := writeConfigTransactionRecoveryRecord(record); err != nil {
		t.Fatal(err)
	}
	if err := recoverInterruptedConfigTransaction(); err == nil {
		t.Fatal("expected restore failure for directory at Mihomo config path")
	}
	if _, err := os.Stat(configTransactionRecoveryPath()); err != nil {
		t.Fatalf("recovery journal must remain for retry: %v", err)
	}
}

func TestReadConfigTransactionRecoveryRecordRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MIHOMO_HOME", dir)
	target := filepath.Join(dir, "operator-state")
	writeRecoveryFixtureFile(t, target, []byte("malformed"))
	if err := os.Symlink(target, configTransactionRecoveryPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigTransactionRecoveryRecord(); err == nil {
		t.Fatal("symlink recovery journal must be rejected")
	}
}


func TestPreServiceRecoveryRestoresFilesWithoutRuntimeReload(t *testing.T) {
	dir, _ := setupConfigTransactionFixture(t)
	transactionReloadMihomo = func() error { t.Fatal("Mihomo is not started during cont-init"); return nil }
	transactionRestartSmartDNS = func() error { t.Fatal("SmartDNS is not started during cont-init"); return nil }
	record := configTransactionRecoveryRecord{
		Version: 1, Phase: "prepared",
		SmartDNS: transactionRecoveryFile{Data: []byte("old-smartdns"), Existed: true},
		Mihomo: transactionRecoveryFile{Data: []byte("old-mihomo"), Existed: true},
		ManagedRoutes: transactionRecoveryFile{Data: []byte("old-routes"), Existed: true},
		Controller: transactionRecoveryFile{Data: []byte("old-controller-hash"), Existed: true},
	}
	writeRecoveryFixtureFile(t, filepath.Join(dir, "config.yaml"), []byte("candidate-mihomo"))
	writeRecoveryFixtureFile(t, filepath.Join(dir, "smartdns.conf"), []byte("candidate-smartdns"))
	if err := writeConfigTransactionRecoveryRecord(record); err != nil {
		t.Fatal(err)
	}
	if err := recoverInterruptedConfigTransactionBeforeServices(); err != nil {
		t.Fatalf("pre-service recovery: %v", err)
	}
	for name, want := range map[string]string{
		"config.yaml": "old-mihomo",
		"smartdns.conf": "old-smartdns",
		"controller-route-cidrs.json": "old-routes",
		"controller-config.yaml": "old-controller-hash",
	} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, err=%v; want %q", name, got, err, want)
		}
	}
	if _, err := os.Lstat(configTransactionRecoveryPath()); !os.IsNotExist(err) {
		t.Fatalf("journal should be removed after durable pre-service restore: %v", err)
	}
}

func TestRecoverInterruptedConfigTransactionRetainsJournalWhenSmartDNSDirectorySyncFails(t *testing.T) {
	dir, _ := setupConfigTransactionFixture(t)
	oldSync := smartDNSDirectorySync
	oldReload := transactionReloadMihomo
	oldRestart := transactionRestartSmartDNS
	oldWait := transactionWaitSmartDNSHealthy
	t.Cleanup(func() {
		smartDNSDirectorySync = oldSync
		transactionReloadMihomo = oldReload
		transactionRestartSmartDNS = oldRestart
		transactionWaitSmartDNSHealthy = oldWait
	})
	syncErr := errors.New("injected SmartDNS directory fsync failure")
	smartDNSDirectorySync = func(string) error { return syncErr }
	restartCalls := 0
	transactionRestartSmartDNS = func() error { restartCalls++; return nil }
	transactionWaitSmartDNSHealthy = func(time.Duration) bool { return true }
	transactionReloadMihomo = func() error { return nil }

	record := configTransactionRecoveryRecord{
		Version: 1, Phase: "prepared",
		SmartDNS: transactionRecoveryFile{Data: []byte("old-smartdns"), Existed: true},
		Mihomo: transactionRecoveryFile{Data: []byte("old-mihomo"), Existed: true},
		ManagedRoutes: transactionRecoveryFile{Data: []byte("old-routes"), Existed: true},
		Controller: transactionRecoveryFile{Data: []byte("old-controller-hash"), Existed: true},
	}
	writeRecoveryFixtureFile(t, filepath.Join(dir, "smartdns.conf"), []byte("candidate-smartdns"))
	if err := writeConfigTransactionRecoveryRecord(record); err != nil {
		t.Fatal(err)
	}

	err := recoverInterruptedConfigTransaction()
	if !errors.Is(err, syncErr) {
		t.Fatalf("expected durability warning, got %v", err)
	}
	if restartCalls != 1 {
		t.Fatalf("restored SmartDNS bytes must be restarted and health-checked, calls=%d", restartCalls)
	}
	if _, statErr := os.Stat(configTransactionRecoveryPath()); statErr != nil {
		t.Fatalf("journal must remain until directory sync succeeds: %v", statErr)
	}
	got, readErr := os.ReadFile(filepath.Join(dir, "smartdns.conf"))
	if readErr != nil || string(got) != "old-smartdns" {
		t.Fatalf("SmartDNS bytes were not restored: %q err=%v", got, readErr)
	}
}


func TestConfigTransactionRecoverySubprocessHelper(t *testing.T) {
	if os.Getenv("S5M_TEST_CONFIG_RECOVERY_CHILD") != "1" {
		return
	}
	smartDNSConfigPath = filepath.Join(mihomoHome(), "smartdns.conf")
	if err := recoverInterruptedConfigTransactionBeforeServices(); err != nil {
		t.Fatalf("subprocess startup recovery: %v", err)
	}
}

func TestConfigTransactionRecoverySurvivesAgentProcessRestart(t *testing.T) {
	dir, _ := setupConfigTransactionFixture(t)
	record := configTransactionRecoveryRecord{
		Version: 1, Phase: "prepared",
		SmartDNS: transactionRecoveryFile{Data: []byte("pre-crash-smartdns"), Existed: true},
		Mihomo: transactionRecoveryFile{Data: []byte("pre-crash-mihomo"), Existed: true},
		ManagedRoutes: transactionRecoveryFile{Data: []byte("pre-crash-routes"), Existed: true},
		Controller: transactionRecoveryFile{Data: []byte("pre-crash-controller"), Existed: true},
	}
	for name, data := range map[string][]byte{
		"smartdns.conf": []byte("partially-applied-smartdns"),
		"config.yaml": []byte("partially-applied-mihomo"),
		"controller-route-cidrs.json": []byte("partially-applied-routes"),
		"controller-config.yaml": []byte("partially-applied-controller"),
	} {
		writeRecoveryFixtureFile(t, filepath.Join(dir, name), data)
	}
	if err := writeConfigTransactionRecoveryRecord(record); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestConfigTransactionRecoverySubprocessHelper$")
	cmd.Env = append(os.Environ(), "S5M_TEST_CONFIG_RECOVERY_CHILD=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("new Agent process failed recovery: %v; output=%s", err, output)
	}
	for name, want := range map[string]string{
		"smartdns.conf": "pre-crash-smartdns",
		"config.yaml": "pre-crash-mihomo",
		"controller-route-cidrs.json": "pre-crash-routes",
		"controller-config.yaml": "pre-crash-controller",
	} {
		got, readErr := os.ReadFile(filepath.Join(dir, name))
		if readErr != nil || string(got) != want {
			t.Fatalf("%s after subprocess recovery = %q, err=%v; want %q", name, got, readErr, want)
		}
	}
	if _, err := os.Lstat(configTransactionRecoveryPath()); !os.IsNotExist(err) {
		t.Fatalf("subprocess recovery must clear journal after durable restore: %v", err)
	}
}
