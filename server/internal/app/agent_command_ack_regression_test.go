package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postAgentCommandAck(app *App, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/command/ack", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.handleAgentCommandAck(rec, req)
	return rec
}

func TestAgentCommandAckCompletesMatchingPendingCommand(t *testing.T) {
	app, code, token := websocketTestApp(t)
	if err := app.store.UpdateSettings(map[string]string{
		"agent_command_" + code: `{"id":"cmd-100","type":"update_mihomo","version":"v1.2.3"}`,
	}); err != nil {
		t.Fatalf("seed pending command: %v", err)
	}

	rec := postAgentCommandAck(app, token, `{"id":"cmd-100","status":"success","message":"updated"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_command_"+code] != "" {
		t.Fatalf("pending command remains after ACK: %q", settings["agent_command_"+code])
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(settings["agent_command_result_"+code]), &result); err != nil {
		t.Fatalf("decode command result: %v", err)
	}
	if result["id"] != "cmd-100" || result["type"] != "update_mihomo" ||
		result["status"] != "success" || result["message"] != "updated" {
		t.Fatalf("unexpected persisted command result: %#v", result)
	}
}

func TestAgentCommandAckRetryIsIdempotentForSameCommandID(t *testing.T) {
	app, code, token := websocketTestApp(t)
	if err := app.store.UpdateSettings(map[string]string{
		"agent_command_result_" + code: `{"id":"cmd-101","type":"update_mihomo","status":"success"}`,
	}); err != nil {
		t.Fatalf("seed previous command result: %v", err)
	}

	rec := postAgentCommandAck(app, token, `{"id":"cmd-101","status":"success","message":"retry"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode retry response: %v", err)
	}
	if response["ok"] != true || response["duplicate"] != true {
		t.Fatalf("retry response = %#v, want duplicate ACK", response)
	}
}

func TestAgentCommandAckRejectsMismatchedIDWithoutMutatingCommand(t *testing.T) {
	app, code, token := websocketTestApp(t)
	const pending = `{"id":"cmd-102","type":"update_mihomo","version":"v1.2.3"}`
	const previous = `{"id":"cmd-old","status":"failed"}`
	if err := app.store.UpdateSettings(map[string]string{
		"agent_command_" + code:        pending,
		"agent_command_result_" + code: previous,
	}); err != nil {
		t.Fatalf("seed command state: %v", err)
	}

	rec := postAgentCommandAck(app, token, `{"id":"cmd-not-current","status":"success"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_command_"+code] != pending {
		t.Fatalf("pending command mutated: got %q, want %q", settings["agent_command_"+code], pending)
	}
	if settings["agent_command_result_"+code] != previous {
		t.Fatalf("previous result mutated: got %q, want %q", settings["agent_command_result_"+code], previous)
	}
}

func TestAgentCommandAckRejectsInvalidStatusWithoutMutatingCommand(t *testing.T) {
	app, code, token := websocketTestApp(t)
	const pending = `{"id":"cmd-103","type":"update_mihomo"}`
	if err := app.store.UpdateSettings(map[string]string{
		"agent_command_" + code: pending,
	}); err != nil {
		t.Fatalf("seed pending command: %v", err)
	}

	rec := postAgentCommandAck(app, token, `{"id":"cmd-103","status":"running"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_command_"+code] != pending {
		t.Fatalf("invalid ACK mutated pending command: got %q, want %q", settings["agent_command_"+code], pending)
	}
}
