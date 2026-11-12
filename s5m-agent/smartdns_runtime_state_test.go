package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestPersistSmartDNSDisabledIsIdempotentAndDurable(t *testing.T) {
	dir := t.TempDir()
	original := smartDNSDisabledPath
	smartDNSDisabledPath = filepath.Join(dir, "state", "smartdns.disabled")
	t.Cleanup(func() { smartDNSDisabledPath = original })

	if err := persistSmartDNSDisabled(true); err != nil {
		t.Fatalf("persist disabled state: %v", err)
	}
	first, err := os.ReadFile(smartDNSDisabledPath)
	if err != nil {
		t.Fatalf("read disabled marker: %v", err)
	}
	if string(first) != "disabled\n" {
		t.Fatalf("disabled marker = %q", first)
	}
	info, err := os.Stat(smartDNSDisabledPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("disabled marker permissions = %o, want 0600", info.Mode().Perm())
	}
	if smartDNSRuntimeEnabled() {
		t.Fatal("runtime reports enabled after persisting disabled marker")
	}

	// Repeating the same transition must be safe and leave the marker intact.
	if err := persistSmartDNSDisabled(true); err != nil {
		t.Fatalf("repeat disable transition: %v", err)
	}
	second, err := os.ReadFile(smartDNSDisabledPath)
	if err != nil || string(second) != string(first) {
		t.Fatalf("repeated disable changed marker: data=%q err=%v", second, err)
	}

	if err := persistSmartDNSDisabled(false); err != nil {
		t.Fatalf("persist enabled state: %v", err)
	}
	if !smartDNSRuntimeEnabled() {
		t.Fatal("runtime still reports disabled after marker removal")
	}
	if _, err := os.Lstat(smartDNSDisabledPath); !os.IsNotExist(err) {
		t.Fatalf("disabled marker remains after enable transition: %v", err)
	}

	// Enabling an already-enabled node is also idempotent.
	if err := persistSmartDNSDisabled(false); err != nil {
		t.Fatalf("repeat enable transition: %v", err)
	}
}

func TestPersistSmartDNSDisabledDoesNotFollowMarkerSymlink(t *testing.T) {
	dir := t.TempDir()
	original := smartDNSDisabledPath
	smartDNSDisabledPath = filepath.Join(dir, "smartdns.disabled")
	t.Cleanup(func() { smartDNSDisabledPath = original })

	target := filepath.Join(dir, "operator-owned-state")
	if err := os.WriteFile(target, []byte("keep-me\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, smartDNSDisabledPath); err != nil {
		t.Fatal(err)
	}

	if err := persistSmartDNSDisabled(true); err != nil {
		t.Fatalf("replace disabled marker symlink atomically: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep-me\n" {
		t.Fatalf("symlink target was modified: %q", got)
	}
	markerInfo, err := os.Lstat(smartDNSDisabledPath)
	if err != nil {
		t.Fatal(err)
	}
	if markerInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatal("disabled marker remains a symlink after atomic replacement")
	}
	marker, err := os.ReadFile(smartDNSDisabledPath)
	if err != nil || string(marker) != "disabled\n" {
		t.Fatalf("replacement marker = %q, err=%v", marker, err)
	}
}

