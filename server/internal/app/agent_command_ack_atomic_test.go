package app

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"
)

func TestAgentCommandAckDoesNotDeleteReplacementCommand(t *testing.T) {
	app, code, token := websocketTestApp(t)
	const pending = `{"id":"cmd-new","type":"restart"}`
	if err := app.store.UpdateSettings(map[string]string{
		"agent_command_" + code:        pending,
		"agent_command_result_" + code: `{"id":"cmd-old","status":"success"}`,
	}); err != nil {
		t.Fatalf("seed command state: %v", err)
	}

	rec := postAgentCommandAck(app, token, `{"id":"cmd-old","status":"success"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale ACK status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_command_"+code] != pending {
		t.Fatalf("replacement command was changed: got %q, want %q", settings["agent_command_"+code], pending)
	}
	if settings["agent_command_result_"+code] != `{"id":"cmd-old","status":"success"}` {
		t.Fatalf("stale ACK overwrote result: %q", settings["agent_command_result_"+code])
	}
}

func TestAgentCommandAckConcurrentHTTPAndWebSocketAreIdempotent(t *testing.T) {
	app, code, token := websocketTestApp(t)
	if err := app.store.UpdateSettings(map[string]string{
		"agent_command_" + code: `{"id":"cmd-race","type":"update_mihomo"}`,
	}); err != nil {
		t.Fatalf("seed pending command: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	httpStatus := 0
	var wsErr error
	go func() {
		defer wg.Done()
		rec := postAgentCommandAck(app, token, `{"id":"cmd-race","status":"success","message":"http"}`)
		httpStatus = rec.Code
	}()
	go func() {
		defer wg.Done()
		wsErr = app.ackAgentWSCommand(code, "cmd-race", "success", "websocket", "")
	}()
	wg.Wait()

	if httpStatus != http.StatusOK {
		t.Fatalf("HTTP ACK status = %d, want 200", httpStatus)
	}
	if wsErr != nil {
		t.Fatalf("WebSocket duplicate ACK should be idempotent, got %v", wsErr)
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_command_"+code] != "" {
		t.Fatalf("pending command remains after concurrent ACKs: %q", settings["agent_command_"+code])
	}
	var result struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(settings["agent_command_result_"+code]), &result); err != nil {
		t.Fatalf("decode persisted command result: %v", err)
	}
	if result.ID != "cmd-race" || result.Status != "success" {
		t.Fatalf("persisted command result = %+v, want ID cmd-race and status success", result)
	}
}
