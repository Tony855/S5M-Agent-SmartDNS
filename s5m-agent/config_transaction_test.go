package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
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
