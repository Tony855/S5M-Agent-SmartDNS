package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
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
