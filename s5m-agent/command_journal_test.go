package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecuteAgentCommandWithJournalReplaysCompletedResult(t *testing.T) {
	t.Setenv("MIHOMO_HOME", t.TempDir())
	enabled := false
	cmd := agentCommand{ID: "cmd-1", Type: "set_smartdns_enabled", Enabled: &enabled}
	executions := 0
	run := func() (string, string, error) {
		executions++
		return "disabled", "", nil
	}
	status, message, _, err := executeAgentCommandWithJournal(cmd, run)
	if err != nil || status != "success" || message != "disabled" {
		t.Fatalf("first execution: status=%q message=%q err=%v", status, message, err)
	}
	status, message, _, err = executeAgentCommandWithJournal(cmd, run)
	if err != nil || status != "success" || message != "disabled" {
		t.Fatalf("replay: status=%q message=%q err=%v", status, message, err)
	}
	if executions != 1 {
		t.Fatalf("completed command executed %d times; want exactly once in this process", executions)
	}
	info, err := os.Stat(agentCommandJournalPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("journal permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestExecuteAgentCommandWithJournalRejectsIDPayloadReuse(t *testing.T) {
	t.Setenv("MIHOMO_HOME", t.TempDir())
	first := agentCommand{ID: "cmd-2", Type: "set_smartdns_enabled"}
	_, _, _, err := executeAgentCommandWithJournal(first, func() (string, string, error) {
		return "done", "", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	reused := agentCommand{ID: "cmd-2", Type: "set_smartdns_enabled", Enabled: &enabled}
	executions := 0
	status, _, _, err := executeAgentCommandWithJournal(reused, func() (string, string, error) {
		executions++
		return "unexpected", "", nil
	})
	if err == nil || status != "failed" || executions != 0 {
		t.Fatalf("reused ID must be rejected without execution: status=%q executions=%d err=%v", status, executions, err)
	}
}

func TestExecuteAgentCommandWithJournalReconcilesInterruptedCommand(t *testing.T) {
	home := t.TempDir()
	t.Setenv("MIHOMO_HOME", home)
	cmd := agentCommand{ID: "cmd-3", Type: "configure_smartdns", Config: "server: 127.0.0.1"}
	payload, err := json.Marshal(cmd)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	entry := agentCommandJournalEntry{ID: cmd.ID, PayloadHash: hex.EncodeToString(sum[:]), State: "running"}
	if err := writeAgentCommandJournal(entry); err != nil {
		t.Fatal(err)
	}
	executions := 0
	status, message, _, err := executeAgentCommandWithJournal(cmd, func() (string, string, error) {
		executions++
		return "reconciled", "", nil
	})
	if err != nil || status != "success" || message != "reconciled" || executions != 1 {
		t.Fatalf("interrupted command reconciliation: status=%q message=%q executions=%d err=%v", status, message, executions, err)
	}
	if _, err := os.Stat(filepath.Join(home, "agent-command-journal.json")); err != nil {
		t.Fatalf("journal not persisted: %v", err)
	}
}

func TestReadAgentCommandJournalRejectsSymlink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("MIHOMO_HOME", home)
	target := filepath.Join(home, "target.json")
	entry := agentCommandJournalEntry{ID: "valid", PayloadHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", State: "running"}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, agentCommandJournalPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentCommandJournal(); err == nil {
		t.Fatal("journal symlink was followed")
	}
}

func TestReadAgentCommandJournalRejectsOversizedFileBeforeRead(t *testing.T) {
	home := t.TempDir()
	t.Setenv("MIHOMO_HOME", home)
	if err := os.WriteFile(agentCommandJournalPath(), make([]byte, agentCommandJournalMaxBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentCommandJournal(); err == nil {
		t.Fatal("oversized journal was accepted")
	}
}

func TestReadAgentCommandJournalRejectsPermissiveMode(t *testing.T) {
	t.Setenv("MIHOMO_HOME", t.TempDir())
	entry := agentCommandJournalEntry{ID: "valid", PayloadHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", State: "running"}
	if err := writeAgentCommandJournal(entry); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(agentCommandJournalPath(), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentCommandJournal(); err == nil {
		t.Fatal("world-readable journal was accepted")
	}
}

func TestExecuteAgentCommandWithJournalRejectsInvalidCommand(t *testing.T) {
	t.Setenv("MIHOMO_HOME", t.TempDir())
	executions := 0
	status, _, _, err := executeAgentCommandWithJournal(agentCommand{Type: "configure_smartdns"}, func() (string, string, error) {
		executions++
		return "unexpected", "", nil
	})
	if err == nil || status != "failed" || executions != 0 {
		t.Fatalf("invalid command must not execute: status=%q executions=%d err=%v", status, executions, err)
	}
}


func TestReadAgentCommandJournalRejectsCorruptAndInvalidEntries(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "malformed JSON", data: `{"id":`},
		{name: "invalid hash", data: `{"id":"cmd","payload_hash":"not-a-hash","state":"running"}`},
		{name: "unknown state", data: `{"id":"cmd","payload_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"pending"}`},
		{name: "completed without status", data: `{"id":"cmd","payload_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"completed"}`},
		{name: "oversized message", data: `{"id":"cmd","payload_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"completed","status":"success","message":"` + strings.Repeat("x", 2049) + `"}`},
		{name: "oversized config", data: `{"id":"cmd","payload_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"completed","status":"success","config":"` + strings.Repeat("x", (8<<10)+1) + `"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MIHOMO_HOME", t.TempDir())
			if err := os.WriteFile(agentCommandJournalPath(), []byte(tt.data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readAgentCommandJournal(); err == nil {
				t.Fatalf("invalid journal entry %q was accepted", tt.name)
			}
		})
	}
}

func TestReadAgentCommandJournalAcceptsValidRunningEntry(t *testing.T) {
	t.Setenv("MIHOMO_HOME", t.TempDir())
	entry := agentCommandJournalEntry{
		ID: "cmd-valid",
		PayloadHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		State: "running",
	}
	if err := writeAgentCommandJournal(entry); err != nil {
		t.Fatal(err)
	}
	got, err := readAgentCommandJournal()
	if err != nil {
		t.Fatalf("valid running journal rejected: %v", err)
	}
	if got.ID != entry.ID || got.PayloadHash != entry.PayloadHash || got.State != entry.State {
		t.Fatalf("journal mismatch: got %+v want %+v", got, entry)
	}
}


func TestExecuteAgentCommandWithJournalDoesNotRunWhenJournalIsUnavailable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("MIHOMO_HOME", home)
	// A directory at the journal path makes the no-follow reader reject the
	// journal before the command's side-effect callback can run.
	if err := os.Mkdir(agentCommandJournalPath(), 0700); err != nil {
		t.Fatal(err)
	}
	executions := 0
	status, _, _, err := executeAgentCommandWithJournal(agentCommand{
		ID: "cmd-journal-unavailable", Type: "set_smartdns_enabled",
	}, func() (string, string, error) {
		executions++
		return "unexpected", "", nil
	})
	if err == nil || status != "failed" || executions != 0 {
		t.Fatalf("unavailable journal must prevent execution: status=%q executions=%d err=%v", status, executions, err)
	}
}
