package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupSmartDNSConfigWithoutLiveFileRemovesStaleBackup(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "smartdns.conf")
	backup := live + ".previous"
	if err := os.WriteFile(backup, []byte("stale rollback data"), 0600); err != nil {
		t.Fatal(err)
	}

	old, hadOld, err := backupSmartDNSConfig(live, backup)
	if err != nil {
		t.Fatalf("backup absent live config: %v", err)
	}
	if hadOld || old != nil {
		t.Fatalf("expected no previous live config, got hadOld=%v data=%q", hadOld, old)
	}
	if _, err := os.Lstat(backup); !os.IsNotExist(err) {
		t.Fatalf("stale backup must be removed, Lstat error=%v", err)
	}
}

func TestBackupSmartDNSConfigFailurePreservesLiveConfig(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "smartdns.conf")
	want := []byte("bind 127.0.0.1:6053\n")
	if err := os.WriteFile(live, want, 0600); err != nil {
		t.Fatal(err)
	}
	// A directory at the backup destination forces the atomic rename to fail.
	backup := filepath.Join(dir, "backup-destination")
	if err := os.Mkdir(backup, 0700); err != nil {
		t.Fatal(err)
	}

	if _, _, err := backupSmartDNSConfig(live, backup); err == nil {
		t.Fatal("expected backup failure")
	}
	got, err := readSmartDNSFileNoFollow(live, 8<<10)
	if err != nil {
		t.Fatalf("live config became unreadable: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("live config changed after backup failure: got %q want %q", got, want)
	}
}

func TestWriteSmartDNSFileAtomicallyFailurePreservesDestination(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "destination-directory")
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(destination, "marker")
	if err := os.WriteFile(marker, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := writeSmartDNSFileAtomically(destination, []byte("replacement"), 0600); err == nil {
		t.Fatal("expected atomic replacement of a directory to fail")
	}
	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("destination directory was damaged: %v", err)
	}
	if string(got) != "keep" {
		t.Fatalf("destination marker changed: %q", got)
	}
}

func TestRestoreSmartDNSConfigRemovesNewFileWhenNoPreviousConfig(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "smartdns.conf")
	if err := os.WriteFile(live, []byte("new config"), 0600); err != nil {
		t.Fatal(err)
	}

	restored, err := restoreSmartDNSConfigVerified(live, nil, false)
	if err != nil {
		t.Fatalf("restore first-install state: %v", err)
	}
	if !restored {
		t.Fatal("expected first-install rollback to be verified")
	}
	if _, err := os.Lstat(live); !os.IsNotExist(err) {
		t.Fatalf("new config must be removed after rollback, Lstat error=%v", err)
	}
}

func TestRestoreSmartDNSConfigRestoresExactPreviousBytes(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "smartdns.conf")
	old := []byte("bind 127.0.0.1:6053\n# preserve exact bytes\n")
	if err := os.WriteFile(live, []byte("candidate config"), 0600); err != nil {
		t.Fatal(err)
	}

	restored, err := restoreSmartDNSConfigVerified(live, old, true)
	if err != nil {
		t.Fatalf("restore previous config: %v", err)
	}
	if !restored {
		t.Fatal("expected previous config restoration to be verified")
	}
	got, err := readSmartDNSFileNoFollow(live, 8<<10)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, old) {
		t.Fatalf("rollback bytes differ: got %q want %q", got, old)
	}
}
