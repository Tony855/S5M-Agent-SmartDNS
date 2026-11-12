package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// A command that was delivered but not ACKed must remain available to a newly
// authenticated socket after a transport disconnect.
func TestAgentWebSocketReconnectRedeliversUnackedCommand(t *testing.T) {
	app, machineCode, token := websocketTestApp(t)
	const commandID = "reconnect-command-001"
	payload, err := json.Marshal(map[string]any{
		"id": commandID, "type": "set_smartdns_enabled", "enabled": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.store.QueueAuthorizedAgentCommand(machineCode, string(payload)); err != nil {
		t.Fatalf("queue command: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()
	header := http.Header{"Authorization": []string{"Bearer " + token}}
	dial := func() *websocket.Conn {
		t.Helper()
		conn, response, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
		if err != nil {
			if response != nil {
				t.Fatalf("dial Agent WebSocket: %v (HTTP %d)", err, response.StatusCode)
			}
			t.Fatalf("dial Agent WebSocket: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var welcome map[string]any
		if err := conn.ReadJSON(&welcome); err != nil {
			_ = conn.Close()
			t.Fatalf("read welcome: %v", err)
		}
		if welcome["type"] != "welcome" {
			_ = conn.Close()
			t.Fatalf("welcome type = %#v", welcome["type"])
		}
		return conn
	}
	requestCommand := func(conn *websocket.Conn, requestID string) map[string]any {
		t.Helper()
		if err := conn.WriteJSON(map[string]any{"type": "command.request", "id": requestID}); err != nil {
			t.Fatalf("request command %s: %v", requestID, err)
		}
		var response map[string]any
		if err := conn.ReadJSON(&response); err != nil {
			t.Fatalf("read command delivery %s: %v", requestID, err)
		}
		if response["type"] != "command.deliver" || response["id"] != requestID {
			t.Fatalf("unexpected command delivery: %#v", response)
		}
		command, ok := response["command"].(map[string]any)
		if !ok || command["id"] != commandID {
			t.Fatalf("re-delivered command mismatch: %#v", response["command"])
		}
		return command
	}

	first := dial()
	requestCommand(first, "poll-before-disconnect")
	// Simulate the network disappearing after delivery but before command.ack.
	_ = first.Close()

	second := dial()
	defer second.Close()
	requestCommand(second, "poll-after-reconnect")
	if err := second.WriteJSON(map[string]any{
		"type": "command.ack", "id": commandID,
		"command_status": "success", "message": "replayed after reconnect",
	}); err != nil {
		t.Fatalf("send command ACK after reconnect: %v", err)
	}
	var ack map[string]any
	if err := second.ReadJSON(&ack); err != nil {
		t.Fatalf("read command ACK confirmation: %v", err)
	}
	if ack["type"] != "command.acknowledged" || ack["id"] != commandID || ack["ok"] != true {
		t.Fatalf("unexpected command ACK confirmation: %#v", ack)
	}

	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings["agent_command_"+machineCode] != "" {
		t.Fatalf("pending command was not cleared after ACK: %q", settings["agent_command_"+machineCode])
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(settings["agent_command_result_"+machineCode]), &result); err != nil {
		t.Fatalf("decode command result: %v", err)
	}
	if result["id"] != commandID || result["status"] != "success" {
		t.Fatalf("persisted command result mismatch: %#v", result)
	}
}
