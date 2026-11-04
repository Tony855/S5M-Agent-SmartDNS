package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// HTTP ACKs must share the store's atomic pending-command check. A delayed ACK
// for an old command must not clear a replacement or overwrite its result.
func TestHTTPAgentCommandAckRejectsStaleIDWhenReplacementIsPending(t *testing.T) {
	app, code, token := websocketTestApp(t)

	pending := map[string]string{"id": "replacement-id", "type": "update_mihomo", "version": "v1.19.33"}
	pendingJSON, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	oldResult := map[string]any{
		"id": "old-command-id", "type": "update_mihomo", "status": "success",
		"message": "previous result", "updated_at": time.Now().Unix() - 60,
	}
	oldResultJSON, err := json.Marshal(oldResult)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.store.UpdateSettings(map[string]string{
		"agent_command_" + code:        string(pendingJSON),
		"agent_command_result_" + code: string(oldResultJSON),
	}); err != nil {
		t.Fatalf("seed command state: %v", err)
	}

	body := `{"id":"old-command-id","status":"success","message":"late ACK"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/command/ack", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.handleAgentCommandAck(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("read command state after stale ACK: %v", err)
	}
	if settings["agent_command_"+code] != string(pendingJSON) {
		t.Fatalf("replacement pending command changed: got %q, want %q", settings["agent_command_"+code], string(pendingJSON))
	}
	if settings["agent_command_result_"+code] != string(oldResultJSON) {
		t.Fatalf("previous command result changed: got %q, want %q", settings["agent_command_result_"+code], string(oldResultJSON))
	}
}


func TestHTTPAgentCommandAckRedactsSensitiveDiagnostics(t *testing.T) {
	app, code, token := websocketTestApp(t)
	if err := app.store.UpdateSettings(map[string]string{
		"agent_command_" + code: `{"id":"redact-ack","type":"update_mihomo"}`,
	}); err != nil {
		t.Fatalf("seed pending command: %v", err)
	}

	body := `{"id":"redact-ack","status":"failed","message":"password=supersecret /etc/s5m/agent.conf"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/command/ack", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.handleAgentCommandAck(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	stored, err := app.store.GetSetting("agent_command_result_" + code)
	if err != nil {
		t.Fatalf("read command result: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(stored), &result); err != nil {
		t.Fatalf("decode command result: %v", err)
	}
	message, _ := result["message"].(string)
	if strings.Contains(message, "supersecret") || strings.Contains(message, "/etc/s5m/agent.conf") {
		t.Fatalf("sensitive diagnostic was persisted: %q", message)
	}
	if !strings.Contains(message, "[已隐藏]") || !strings.Contains(message, "[路径已隐藏]") {
		t.Fatalf("expected credential and path redaction, got %q", message)
	}
}
