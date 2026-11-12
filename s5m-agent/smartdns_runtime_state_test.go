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

func TestSmartDNSRestartGateEnforcesCooldownAndAllowsRetry(t *testing.T) {
	var gate smartDNSRestartGate
	start := time.Unix(1_800_000_000, 0)
	if ok, remaining := gate.TryAcquire(start, 30*time.Second); !ok || remaining != 0 {
		t.Fatalf("first acquire = (%v, %v), want (true, 0)", ok, remaining)
	}
	if ok, remaining := gate.TryAcquire(start.Add(10*time.Second), 30*time.Second); ok || remaining != 20*time.Second {
		t.Fatalf("early retry = (%v, %v), want (false, 20s)", ok, remaining)
	}
	if ok, remaining := gate.TryAcquire(start.Add(30*time.Second), 30*time.Second); !ok || remaining != 0 {
		t.Fatalf("retry at cooldown boundary = (%v, %v), want (true, 0)", ok, remaining)
	}
}

func TestSmartDNSRestartGateSerializesConcurrentRestarts(t *testing.T) {
	var gate smartDNSRestartGate
	now := time.Unix(1_800_000_000, 0)
	const contenders = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	granted := 0
	wg.Add(contenders)
	for i := 0; i < contenders; i++ {
		go func() {
			defer wg.Done()
			if ok, _ := gate.TryAcquire(now, 30*time.Second); ok {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if granted != 1 {
		t.Fatalf("concurrent restart gate granted %d callers, want exactly one", granted)
	}
}
