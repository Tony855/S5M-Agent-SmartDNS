package app

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestAckAgentCommandRejectsOldIDWhenReplacementIsPending(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "ack-replacement.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const machineCode = "ack_node"
	const oldResult = `{"id":"cmd-old","type":"update_mihomo","status":"success"}`
	const replacement = `{"id":"cmd-new","type":"update_mihomo","version":"v1.2.3"}`
	if err := store.UpdateSettings(map[string]string{
		"agent_command_result_" + machineCode: oldResult,
		"agent_command_" + machineCode:        replacement,
	}); err != nil {
		t.Fatalf("seed command state: %v", err)
	}

	duplicate, matched, err := store.AckAgentCommand(machineCode, "cmd-old", "success", "stale retry", 100)
	if err != nil {
		t.Fatalf("AckAgentCommand: %v", err)
	}
	if duplicate || matched {
		t.Fatalf("stale ACK = duplicate %v, matched %v; want both false while replacement is pending", duplicate, matched)
	}

	settings, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_command_"+machineCode] != replacement {
		t.Fatalf("replacement command changed: %q", settings["agent_command_"+machineCode])
	}
	if settings["agent_command_result_"+machineCode] != oldResult {
		t.Fatalf("previous result changed: %q", settings["agent_command_result_"+machineCode])
	}
}

func TestAckAgentCommandTreatsSameCompletedIDAsDuplicateOnlyWithoutPendingCommand(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "ack-duplicate.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const machineCode = "ack_node"
	const result = `{"id":"cmd-done","type":"update_mihomo","status":"success"}`
	if err := store.UpdateSettings(map[string]string{
		"agent_command_result_" + machineCode: result,
	}); err != nil {
		t.Fatalf("seed command result: %v", err)
	}

	duplicate, matched, err := store.AckAgentCommand(machineCode, "cmd-done", "success", "retry", 200)
	if err != nil {
		t.Fatalf("AckAgentCommand duplicate retry: %v", err)
	}
	if !duplicate || !matched {
		t.Fatalf("duplicate retry = duplicate %v, matched %v; want both true", duplicate, matched)
	}

	settings, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_command_result_"+machineCode] != result {
		t.Fatalf("duplicate retry should not rewrite original result: %q", settings["agent_command_result_"+machineCode])
	}
}

func TestAckAgentCommandDoesNotAcceptDuplicateWhenPendingRecordIsMalformed(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "ack-malformed-pending.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const machineCode = "ack_node"
	const malformed = `{"id":`
	const oldResult = `{"id":"cmd-done","status":"success"}`
	if err := store.UpdateSettings(map[string]string{
		"agent_command_" + machineCode:        malformed,
		"agent_command_result_" + machineCode: oldResult,
	}); err != nil {
		t.Fatalf("seed command state: %v", err)
	}

	duplicate, matched, err := store.AckAgentCommand(machineCode, "cmd-done", "success", "retry", 300)
	if err != nil {
		t.Fatalf("AckAgentCommand: %v", err)
	}
	if duplicate || matched {
		t.Fatalf("ACK with malformed pending record = duplicate %v, matched %v; want both false", duplicate, matched)
	}
}


func TestPendingAgentCommandSurvivesStoreRestartAndACKCommitsDesiredState(t *testing.T) {
	tests := []struct {
		name       string
		status     string
		wantState  string
		wantResult string
	}{
		{name: "successful desired state", status: "success", wantState: "true", wantResult: "success"},
		{name: "failed desired state", status: "failed", wantState: "false", wantResult: "failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "restart-command.db")
			store, err := OpenStore(path)
			if err != nil {
				t.Fatalf("OpenStore before restart: %v", err)
			}
			const machineCode = "restart_node"
			const commandID = "cmd-restart-smartdns"
			pending := `{"id":"cmd-restart-smartdns","type":"set_smartdns_enabled","enabled":true}`
			if err := store.UpdateSettings(map[string]string{
				"agent_command_" + machineCode: pending,
				"smartdns_enabled_" + machineCode: "false",
			}); err != nil {
				t.Fatalf("persist pending command: %v", err)
			}
			if err := store.db.Close(); err != nil {
				t.Fatalf("close store to simulate master restart: %v", err)
			}

			restarted, err := OpenStore(path)
			if err != nil {
				t.Fatalf("OpenStore after restart: %v", err)
			}
			defer restarted.db.Close()

			duplicate, matched, err := restarted.AckAgentCommandWithConfig(machineCode, commandID, tt.status, "result after restart", "", 1234)
			if err != nil {
				t.Fatalf("ACK after restart: %v", err)
			}
			if duplicate || !matched {
				t.Fatalf("ACK after restart = duplicate %v, matched %v; want false, true", duplicate, matched)
			}

			settings, err := restarted.GetSettings()
			if err != nil {
				t.Fatalf("read settings after restart ACK: %v", err)
			}
			if _, exists := settings["agent_command_"+machineCode]; exists {
				t.Fatal("pending command remained after successful ACK transaction")
			}
			if got := settings["smartdns_enabled_"+machineCode]; got != tt.wantState {
				t.Fatalf("SmartDNS desired state = %q, want %q", got, tt.wantState)
			}
			var result map[string]any
			if err := json.Unmarshal([]byte(settings["agent_command_result_"+machineCode]), &result); err != nil {
				t.Fatalf("decode persisted ACK result: %v", err)
			}
			if result["id"] != commandID || result["status"] != tt.wantResult {
				t.Fatalf("persisted ACK result = %#v", result)
			}
		})
	}
}
