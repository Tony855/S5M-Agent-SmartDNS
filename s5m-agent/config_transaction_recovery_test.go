package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
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
	old := configTransactionRecoveryRecord{
		Version: 1, Phase: "prepared",
		SmartDNS: transactionRecoveryFile{Data: []byte("old-smartdns"), Existed: true},
		Mihomo: transactionRecoveryFile{Data: []byte("old-mihomo"), Existed: true},
		ManagedRoutes: transactionRecoveryFile{Data: []byte("[\\"192.0.2.10/32\\"]"), Existed: true},
		Controller: transactionRecoveryFile{Data: []byte("old-controller-hash"), Existed: true},
	}
	for name, data := range map[string][]byte{
		"smartdns.conf": []byte("candidate-smartdns"),
		"config.yaml": []byte("candidate-mihomo"),
		"controller-route-cidrs.json": []byte("[\\"198.51.100.20/32\\"]"),
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
		"controller-route-cidrs.json": []byte("[\\"192.0.2.10/32\\"]"),
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
		ManagedRoutes: transactionRecoveryFile{Data: []byte("[\\"192.0.2.10/32\\"]"), Existed: true},
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
		ManagedRoutes: transactionRecoveryFile{Data: []byte("[\\"192.0.2.10/32\\"]"), Existed: true},
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
	oldHome := os.Getenv("MIHOMO_HOME")
	t.Setenv("MIHOMO_HOME", dir)
	target := filepath.Join(dir, "operator-state")
	writeRecoveryFixtureFile(t, target, []byte("{\\"version\\":1,\\"phase\\":\\"prepared\\"}"))
	if err := os.Symlink(target, configTransactionRecoveryPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigTransactionRecoveryRecord(); err == nil {
		t.Fatal("symlink recovery journal must be rejected")
	}
	_ = oldHome
}
