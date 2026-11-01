package app

import (
	"encoding/json"
	"strings"
	"testing"
	"net/http"
	"net/http/httptest"

	"github.com/gorilla/websocket"
	"time"
)

func validAgentTelemetry() map[string]any {
	return map[string]any{
		"upload_speed": float64(1024),
		"download_speed": float64(2048),
		"upload_total": float64(10000),
		"download_total": float64(20000),
		"connections": float64(7),
		"traffic_error": "",
		"connections_error": "",
	}
}

func TestValidateAgentWSTelemetryRejectsMalformedMetrics(t *testing.T) {
	if err := validateAgentWSTelemetry(validAgentTelemetry()); err != nil {
		t.Fatalf("valid telemetry rejected: %v", err)
	}
	cases := []struct {
		name string
		change func(map[string]any)
	}{
		{"negative speed", func(v map[string]any) { v["upload_speed"] = float64(-1) }},
		{"fractional connections", func(v map[string]any) { v["connections"] = float64(1.5) }},
		{"string counter", func(v map[string]any) { v["download_total"] = "200" }},
		{"oversized diagnostic", func(v map[string]any) { v["traffic_error"] = strings.Repeat("x", 513) }},
		{"missing field", func(v map[string]any) { delete(v, "connections") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value := validAgentTelemetry()
			tc.change(value)
			if err := validateAgentWSTelemetry(value); err == nil {
				t.Fatal("malformed telemetry unexpectedly accepted")
			}
		})
	}
}

func TestAgentWebSocketPersistsThrottledTelemetrySnapshot(t *testing.T) {
	app, code, token := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil { t.Fatalf("dial Agent WebSocket: %v", err) }
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil { t.Fatalf("read welcome: %v", err) }

	if err := conn.WriteJSON(map[string]any{"type": "telemetry", "status": validAgentTelemetry()}); err != nil {
		t.Fatalf("send telemetry: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		settings, readErr := app.store.GetSettings()
		if readErr != nil { t.Fatalf("read settings: %v", readErr) }
		var saved map[string]any
		_ = json.Unmarshal([]byte(settings["agent_status_"+code]), &saved)
		if saved["upload_speed"] == float64(1024) && saved["connections"] == float64(7) {
			if saved["telemetry_received_at_ms"] == nil { t.Fatal("telemetry timestamp was not persisted") }
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("telemetry snapshot was not persisted")
}
