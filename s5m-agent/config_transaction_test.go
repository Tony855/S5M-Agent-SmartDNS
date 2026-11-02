package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	oldRemoveBackup := transactionRemoveBackup
	oldSnapshotFile := transactionSnapshotFile
	restore := func() {
		smartDNSConfigPath = oldSmartPath
		transactionMergeMihomo = oldMerge
		transactionReloadMihomo = oldReload
		transactionApplySmartDNS = oldApplySmart
		transactionWaitSmartDNSHealthy = oldWait
		transactionRestartSmartDNS = oldRestart
		transactionWriteControllerConfig = oldWriteController
		transactionRemoveBackup = oldRemoveBackup
		transactionSnapshotFile = oldSnapshotFile
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


func TestConfigTransactionReportsSmartDNSRollbackRestartFailure(t *testing.T) {
	_, _ = setupConfigTransactionFixture(t)
	transactionMergeMihomo = func(_ []byte, _ string) (bool, error) { return true, nil }
	transactionReloadMihomo = func() error { return nil }
	transactionApplySmartDNS = func(data []byte, _ bool) (string, error) {
		return "", atomicWriteFile(smartDNSConfigPath, data, 0600)
	}
	healthCalls := 0
	transactionWaitSmartDNSHealthy = func(time.Duration) bool {
		healthCalls++
		return false // candidate fails; rollback restart must still be attempted
	}
	restartCalls := 0
	transactionRestartSmartDNS = func() error {
		restartCalls++
		return errors.New("injected SmartDNS restart failure")
	}

	err := applyAgentConfigTransaction([]byte("controller-candidate"), []byte("smartdns-candidate"), true, "")
	if err == nil {
		t.Fatal("expected rollback restart failure to be returned")
	}
	if !strings.Contains(err.Error(), "重启回滚后的 SmartDNS 失败") {
		t.Fatalf("error should identify SmartDNS rollback restart failure, got: %v", err)
	}
	if restartCalls != 1 {
		t.Fatalf("expected one rollback restart attempt, got %d", restartCalls)
	}
	if healthCalls != 1 {
		t.Fatalf("must not probe health after restart failed, got %d probes", healthCalls)
	}
}

func TestConfigTransactionKeepsBackupWhenCleanupFailsAfterHealthyCommit(t *testing.T) {
	dir, _ := setupConfigTransactionFixture(t)
	transactionMergeMihomo = func(_ []byte, _ string) (bool, error) { return false, nil }
	transactionReloadMihomo = func() error { return nil }
	transactionWaitSmartDNSHealthy = func(time.Duration) bool { return true }
	transactionWriteControllerConfig = func([]byte) error { return nil }

	var cleanupAttempts int
	transactionRemoveBackup = func(path string) error {
		if path == smartDNSConfigPath {
			cleanupAttempts++
			return errors.New("injected directory sync failure")
		}
		return removeTransactionBackup(path)
	}

	err := applyAgentConfigTransaction([]byte("controller-candidate"), nil, false, "")
	if err != nil {
		t.Fatalf("healthy joint commit must not be reported as failed solely because cleanup failed: %v", err)
	}
	if cleanupAttempts != 1 {
		t.Fatalf("expected SmartDNS backup cleanup attempt, got %d", cleanupAttempts)
	}
	if _, err := os.Stat(filepath.Join(dir, "smartdns.conf.previous")); err != nil {
		t.Fatalf("failed cleanup must retain SmartDNS recovery copy: %v", err)
	}
}


func TestSnapshotFileForTransactionPropagatesStaleBackupRemovalFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.json")
	backupDir := path + ".previous"
	if err := os.Mkdir(backupDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "keep"), []byte("not empty"), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err := snapshotFileForTransaction(path)
	if err == nil || !strings.Contains(err.Error(), "清理过期事务备份失败") {
		t.Fatalf("expected stale backup cleanup error, got %v", err)
	}
}

func TestConfigTransactionCleansPreparedBackupsWhenLaterSnapshotFails(t *testing.T) {
	dir, _ := setupConfigTransactionFixture(t)
	snapshotCalls := 0
	transactionSnapshotFile = func(path string) ([]byte, bool, error) {
		snapshotCalls++
		if path == managedRouteCIDRsPath() {
			return nil, false, errors.New("injected managed CIDR snapshot failure")
		}
		return snapshotFileForTransaction(path)
	}
	mergeCalls := 0
	transactionMergeMihomo = func(_ []byte, _ string) (bool, error) {
		mergeCalls++
		return false, nil
	}

	err := applyAgentConfigTransaction([]byte("controller-candidate"), nil, false, "")
	if err == nil || !strings.Contains(err.Error(), "保存 managed CIDR 事务回滚点失败") {
		t.Fatalf("expected managed CIDR snapshot failure, got %v", err)
	}
	if mergeCalls != 0 {
		t.Fatalf("configuration mutation must not begin when snapshot preparation fails, got %d merge calls", mergeCalls)
	}
	for _, name := range []string{"smartdns.conf.previous", "config.yaml.previous"} {
		if _, statErr := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(statErr) {
			t.Fatalf("partial prepared backup %s should be cleaned, stat error=%v", name, statErr)
		}
	}
}


func TestConfigTransactionRestoresPartialMihomoMutationWhenMergeReturnsError(t *testing.T) {
	dir, _ := setupConfigTransactionFixture(t)
	transactionMergeMihomo = func(_ []byte, _ string) (bool, error) {
		if err := atomicWriteFile(mihomoConfigPath(), []byte("partially-written-mihomo"), 0600); err != nil {
			return false, err
		}
		if err := atomicWriteFile(managedRouteCIDRsPath(), []byte("partially-written-cidrs"), 0600); err != nil {
			return false, err
		}
		return false, errors.New("injected managed CIDR write failure after Mihomo update")
	}
	reloadCalls := 0
	transactionReloadMihomo = func() error { reloadCalls++; return nil }
	transactionRestartSmartDNS = func() error { return nil }
	transactionWaitSmartDNSHealthy = func(time.Duration) bool { return true }

	err := applyAgentConfigTransaction([]byte("candidate-controller"), nil, false, "")
	if err == nil || !strings.Contains(err.Error(), "应用 Mihomo 配置失败") {
		t.Fatalf("expected merge failure, got %v", err)
	}
	for name, want := range map[string][]byte{
		"config.yaml":                 []byte("old-mihomo"),
		"controller-route-cidrs.json": []byte("[\"192.0.2.10/32\"]"),
		"controller-config.yaml":      []byte("old-controller-hash"),
		"smartdns.conf":               []byte("old-smartdns"),
	} {
		got, readErr := os.ReadFile(filepath.Join(dir, name))
		if readErr != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s not restored: got=%q err=%v want=%q", name, got, readErr, want)
		}
	}
	if reloadCalls != 1 {
		t.Fatalf("expected one reload to validate restored Mihomo config, got %d", reloadCalls)
	}
}

func TestConfigTransactionsSerializeBothConfigurationLocks(t *testing.T) {
	_, _ = setupConfigTransactionFixture(t)
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondEntered := make(chan struct{})
	var mergeCalls int
	transactionMergeMihomo = func(_ []byte, _ string) (bool, error) {
		mergeCalls++
		if mergeCalls == 1 {
			close(firstEntered)
			<-releaseFirst
		} else {
			close(secondEntered)
		}
		return false, nil
	}
	transactionReloadMihomo = func() error { return nil }
	transactionWaitSmartDNSHealthy = func(time.Duration) bool { return true }
	transactionWriteControllerConfig = func([]byte) error { return nil }

	firstDone := make(chan error, 1)
	go func() { firstDone <- applyAgentConfigTransaction([]byte("first"), nil, false, "") }()
	<-firstEntered
	secondDone := make(chan error, 1)
	go func() { secondDone <- applyAgentConfigTransaction([]byte("second"), nil, false, "") }()

	select {
	case <-secondEntered:
		close(releaseFirst)
		t.Fatal("second transaction entered merge while first transaction still held configuration locks")
	case <-time.After(40 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("first transaction failed: %v", err)
	}
	select {
	case <-secondEntered:
	case <-time.After(time.Second):
		t.Fatal("second transaction did not proceed after first released locks")
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second transaction failed: %v", err)
	}
	if mergeCalls != 2 {
		t.Fatalf("expected two serialized merge calls, got %d", mergeCalls)
	}
}


func TestWriteTransactionBackupPreservingPriorRestoresPreviousSidecarAfterPostRenameFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json.previous")
	previous := []byte("previous recovery point")
	candidate := []byte("new snapshot")
	if err := os.WriteFile(path, previous, 0600); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected directory fsync failure after rename")
	err := writeTransactionBackupPreservingPrior(path, candidate, func(path string, data []byte, mode os.FileMode) error {
		if err := atomicWriteFile(path, data, mode); err != nil {
			return err
		}
		return injected
	})
	if !errors.Is(err, injected) {
		t.Fatalf("expected injected post-rename failure, got %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read restored prior sidecar: %v", readErr)
	}
	if !bytes.Equal(got, previous) {
		t.Fatalf("prior sidecar was not restored: got %q want %q", got, previous)
	}
}

func TestWriteTransactionBackupPreservingPriorRemovesNewSidecarAfterFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "first-install.previous")
	injected := errors.New("injected post-rename failure")
	err := writeTransactionBackupPreservingPrior(path, []byte("candidate"), func(path string, data []byte, mode os.FileMode) error {
		if err := atomicWriteFile(path, data, mode); err != nil {
			return err
		}
		return injected
	})
	if !errors.Is(err, injected) {
		t.Fatalf("expected injected post-rename failure, got %v", err)
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		t.Fatalf("new sidecar must be removed after failed snapshot, stat error=%v", statErr)
	}
}
