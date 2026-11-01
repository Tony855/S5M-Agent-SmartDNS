package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

func websocketTestApp(t *testing.T) (*App, string, string) {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "agent-ws.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.db.Close() })

	const code = "ws_node_01"
	const secret = "ws-dedicated-secret"
	app := &App{store: store, jwtKey: []byte("test-ws-signing-key")}
	if err := store.UpdateSettings(map[string]string{
		"agent_token":           "global-secret",
		"agent_machine_" + code: secret,
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	sum := sha256.Sum256([]byte(secret))
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": code, "role": "agent", "ver": hex.EncodeToString(sum[:]),
	}).SignedString(app.jwtKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return app, code, token
}

// floatMap converts JSON-number-like test payloads to float64 values, matching
// encoding/json's decoding behavior on the server.
func floatMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		switch number := value.(type) {
		case int:
			out[key] = float64(number)
		case int64:
			out[key] = float64(number)
		default:
			out[key] = value
		}
	}
	return out
}

func TestAgentWebSocketRejectsUnauthorizedHandshake(t *testing.T) {
	app, _, _ := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	_, response, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], nil)
	if err == nil {
		t.Fatal("unauthorized WebSocket handshake unexpectedly succeeded")
	}
	if response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("handshake response = %#v, want HTTP 401", response)
	}
}

func TestAgentWebSocketAcceptsHeartbeatAndPersistsStatus(t *testing.T) {
	app, code, token := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatalf("dial authenticated WebSocket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	if welcome["type"] != "welcome" {
		t.Fatalf("welcome type = %#v", welcome["type"])
	}

	status := map[string]any{
		"mihomo_version": "v1.19.3",
		"mihomo_healthy": true,
		"upload_total":   12,
		"download_total": 34,
		"upload_speed":   1,
		"download_speed": 2,
		"connections":    3,
		"config_sha256":  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"last_error":     "",
	}
	if err := conn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-1", "status": floatMap(status)}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}
	var ack map[string]any
	if err := conn.ReadJSON(&ack); err != nil {
		t.Fatalf("read heartbeat ACK: %v", err)
	}
	if ack["type"] != "heartbeat.ack" || ack["id"] != "hb-1" || ack["ok"] != true {
		t.Fatalf("unexpected ACK: %#v", ack)
	}

	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	var saved map[string]any
	if err := json.Unmarshal([]byte(settings["agent_status_"+code]), &saved); err != nil {
		t.Fatalf("decode persisted status: %v", err)
	}
	if saved["mihomo_version"] != "v1.19.3" || saved["received_at"] == nil {
		t.Fatalf("unexpected persisted status: %#v", saved)
	}
	if settings["agent_lastseen_"+code] == "" {
		t.Fatal("heartbeat did not persist last-seen timestamp")
	}
}

func TestAgentWebSocketSupersededConnectionCannotOverwriteStatus(t *testing.T) {
	app, code, token := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	dial := func() *websocket.Conn {
		t.Helper()
		conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
		if err != nil {
			t.Fatalf("dial authenticated WebSocket: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var welcome map[string]any
		if err := conn.ReadJSON(&welcome); err != nil {
			conn.Close()
			t.Fatalf("read welcome: %v", err)
		}
		if welcome["type"] != "welcome" {
			conn.Close()
			t.Fatalf("welcome type = %#v", welcome["type"])
		}
		return conn
	}

	oldConn := dial()
	defer oldConn.Close()
	newConn := dial()
	defer newConn.Close()

	status := map[string]any{
		"mihomo_version": "stale-connection",
		"mihomo_healthy": true,
		"upload_total":   float64(12),
		"download_total": float64(34),
		"upload_speed":   float64(1),
		"download_speed": float64(2),
		"connections":    float64(3),
		"config_sha256":  strings.Repeat("a", 64),
		"last_error":     "",
	}
	if err := oldConn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-old", "status": floatMap(status)}); err != nil {
		t.Fatalf("send heartbeat on superseded connection: %v", err)
	}
	if _, _, err := oldConn.ReadMessage(); !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		t.Fatalf("superseded connection should close cleanly, got %v", err)
	}

	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_status_"+code] != "" || settings["agent_lastseen_"+code] != "" {
		t.Fatalf("superseded connection persisted status: %#v", settings)
	}

	freshStatus := map[string]any{}
	for k, v := range status {
		freshStatus[k] = v
	}
	freshStatus["mihomo_version"] = "current-connection"
	if err := newConn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-new", "status": floatMap(freshStatus)}); err != nil {
		t.Fatalf("send heartbeat on current connection: %v", err)
	}
	var response map[string]any
	if err := newConn.ReadJSON(&response); err != nil {
		t.Fatalf("read current connection ACK: %v", err)
	}
	if response["type"] != "heartbeat.ack" || response["id"] != "hb-new" {
		t.Fatalf("unexpected current connection response: %#v", response)
	}
	settings, err = app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings after current heartbeat: %v", err)
	}
	var saved map[string]any
	if err := json.Unmarshal([]byte(settings["agent_status_"+code]), &saved); err != nil {
		t.Fatalf("decode current status: %v", err)
	}
	if saved["mihomo_version"] != "current-connection" {
		t.Fatalf("status overwritten by stale connection: %#v", saved)
	}
}

func TestAgentWebSocketGenerationDoesNotResetAfterDisconnect(t *testing.T) {
	app, _, token := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	dial := func() *websocket.Conn {
		t.Helper()
		conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
		if err != nil {
			t.Fatalf("dial authenticated WebSocket: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var welcome map[string]any
		if err := conn.ReadJSON(&welcome); err != nil {
			conn.Close()
			t.Fatalf("read welcome: %v", err)
		}
		return conn
	}

	oldConn := dial()
	defer oldConn.Close()
	middleConn := dial()
	middleConn.Close()
	latestConn := dial()
	defer latestConn.Close()

	status := map[string]any{
		"mihomo_version": "stale-connection",
		"mihomo_healthy": true,
		"upload_total":   float64(12),
		"download_total": float64(34),
		"upload_speed":   float64(1),
		"download_speed": float64(2),
		"connections":    float64(3),
		"config_sha256":  strings.Repeat("a", 64),
		"last_error":     "",
	}
	if err := oldConn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-aba", "status": floatMap(status)}); err != nil {
		t.Fatalf("send heartbeat on stale connection: %v", err)
	}
	if _, _, err := oldConn.ReadMessage(); !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		t.Fatalf("stale connection should close cleanly, got %v", err)
	}
}

func TestHTTPAgentHeartbeatRejectsInvalidTelemetry(t *testing.T) {
	app, code, token := websocketTestApp(t)
	status := map[string]any{
		"mihomo_version": "v1.19.3",
		"mihomo_healthy": true,
		"upload_total":   float64(-1),
		"download_total": float64(34),
		"upload_speed":   float64(1),
		"download_speed": float64(2),
		"connections":    float64(3),
		"config_sha256":  strings.Repeat("a", 64),
		"last_error":     "",
	}
	body, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	app.handleAgentHeartbeat(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_status_"+code] != "" || settings["agent_lastseen_"+code] != "" {
		t.Fatal("invalid HTTP heartbeat must not be persisted")
	}
}

func TestAgentWebSocketHeartbeatRecoversAfterControllerStateReset(t *testing.T) {
	app, code, token := websocketTestApp(t)
	oldStatus := `{"mihomo_version":"old","mihomo_healthy":true,"upload_total":1,"download_total":2,"upload_speed":0,"download_speed":0,"connections":0,"config_sha256":"","last_error":"","received_at":1}`
	if err := app.store.UpdateSettings(map[string]string{
		"agent_status_" + code:   oldStatus,
		"agent_lastseen_" + code: "1",
	}); err != nil {
		t.Fatalf("seed persisted status: %v", err)
	}

	// Simulate a controller restart: persisted settings survive, but in-memory
	// connection generations and heartbeat ordering timestamps do not.
	app.agentHeartbeatAt = nil
	app.agentWSGeneration = nil
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatalf("dial authenticated WebSocket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatalf("read welcome: %v", err)
	}

	status := map[string]any{
		"mihomo_version": "v1.19.3",
		"mihomo_healthy": true,
		"upload_total":   float64(12),
		"download_total": float64(34),
		"upload_speed":   float64(1),
		"download_speed": float64(2),
		"connections":    float64(3),
		"config_sha256":  strings.Repeat("a", 64),
		"last_error":     "",
	}
	if err := conn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-recovery", "status": floatMap(status)}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}
	var ack map[string]any
	if err := conn.ReadJSON(&ack); err != nil {
		t.Fatalf("read heartbeat ack: %v", err)
	}
	if ack["type"] != "heartbeat.ack" || ack["id"] != "hb-recovery" || ack["ok"] != true {
		t.Fatalf("unexpected heartbeat ack: %#v", ack)
	}

	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	var persisted map[string]any
	if err := json.Unmarshal([]byte(settings["agent_status_"+code]), &persisted); err != nil {
		t.Fatalf("decode persisted status: %v", err)
	}
	if persisted["mihomo_version"] != "v1.19.3" {
		t.Fatalf("persisted status was not recovered after state reset: %#v", persisted)
	}
	lastSeen, err := strconv.ParseInt(settings["agent_lastseen_"+code], 10, 64)
	if err != nil || lastSeen <= 1 {
		t.Fatalf("lastseen = %q, want fresh timestamp; err=%v", settings["agent_lastseen_"+code], err)
	}
}

func TestHTTPAgentHeartbeatAcceptsAfterControllerStateReset(t *testing.T) {
	app, code, token := websocketTestApp(t)
	oldStatus := `{"mihomo_version":"old","mihomo_healthy":true,"upload_total":1,"download_total":2,"upload_speed":0,"download_speed":0,"connections":0,"config_sha256":"","last_error":"","received_at":1}`
	if err := app.store.UpdateSettings(map[string]string{
		"agent_status_" + code:   oldStatus,
		"agent_lastseen_" + code: "1",
	}); err != nil {
		t.Fatalf("seed persisted status: %v", err)
	}

	// A controller restart clears in-memory heartbeat ordering state while the
	// persisted node status remains. The first valid heartbeat must recover it.
	app.agentHeartbeatAt = nil
	app.agentWSGeneration = nil
	status := map[string]any{
		"mihomo_version": "v1.19.3",
		"mihomo_healthy": true,
		"upload_total":   float64(12),
		"download_total": float64(34),
		"upload_speed":   float64(1),
		"download_speed": float64(2),
		"connections":    float64(3),
		"config_sha256":  strings.Repeat("a", 64),
		"last_error":     "",
	}
	body, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	app.handleAgentHeartbeat(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	var persisted map[string]any
	if err := json.Unmarshal([]byte(settings["agent_status_"+code]), &persisted); err != nil {
		t.Fatalf("decode persisted status: %v", err)
	}
	if persisted["mihomo_version"] != "v1.19.3" {
		t.Fatalf("persisted status was not recovered after state reset: %#v", persisted)
	}
	lastSeen, err := strconv.ParseInt(settings["agent_lastseen_"+code], 10, 64)
	if err != nil || lastSeen <= 1 {
		t.Fatalf("lastseen = %q, want fresh timestamp; err=%v", settings["agent_lastseen_"+code], err)
	}
}

func TestHTTPAgentHeartbeatDoesNotOverwriteNewerHeartbeat(t *testing.T) {
	app, code, token := websocketTestApp(t)
	newerStatus := `{"mihomo_version":"newer","mihomo_healthy":true,"upload_total":12,"download_total":34,"upload_speed":1,"download_speed":2,"connections":3,"config_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","last_error":"","received_at":123}`
	if err := app.store.UpdateSettings(map[string]string{
		"agent_status_" + code:   newerStatus,
		"agent_lastseen_" + code: "123",
	}); err != nil {
		t.Fatalf("seed newer status: %v", err)
	}
	app.agentHeartbeatAt = map[string]int64{code: time.Now().Add(time.Minute).UnixNano()}

	status := map[string]any{
		"mihomo_version": "older",
		"mihomo_healthy": true,
		"upload_total":   float64(1),
		"download_total": float64(2),
		"upload_speed":   float64(3),
		"download_speed": float64(4),
		"connections":    float64(1),
		"config_sha256":  strings.Repeat("b", 64),
		"last_error":     "",
	}
	body, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	app.handleAgentHeartbeat(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_status_"+code] != newerStatus || settings["agent_lastseen_"+code] != "123" {
		t.Fatalf("stale heartbeat overwrote newer status: %#v", settings)
	}
}

func TestAgentWebSocketRejectsHeartbeatMissingRequiredFields(t *testing.T) {
	app, _, token := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatalf("dial authenticated WebSocket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	if err := conn.WriteJSON(map[string]any{
		"type": "heartbeat", "id": "hb-bad", "status": map[string]any{"mihomo_version": "v1.0.0"},
	}); err != nil {
		t.Fatalf("send invalid heartbeat: %v", err)
	}
	var response map[string]any
	if err := conn.ReadJSON(&response); err != nil {
		t.Fatalf("read validation response: %v", err)
	}
	if response["type"] != "error" || response["id"] != "hb-bad" {
		t.Fatalf("unexpected validation response: %#v", response)
	}
}

func TestValidateAgentWSStatusRejectsInvalidValues(t *testing.T) {
	valid := func() map[string]any {
		return map[string]any{
			"mihomo_version": "v1.19.3",
			"mihomo_healthy": true,
			"upload_total":   float64(12),
			"download_total": float64(34),
			"upload_speed":   float64(1),
			"download_speed": float64(2),
			"connections":    float64(3),
			"config_sha256":  strings.Repeat("a", 64),
			"last_error":     "",
		}
	}
	tests := []struct {
		name    string
		mutate  func(map[string]any)
		wantErr bool
	}{
		{name: "valid", mutate: func(map[string]any) {}},
		{name: "empty hash allowed", mutate: func(s map[string]any) { s["config_sha256"] = "" }},
		{name: "healthy without version", mutate: func(s map[string]any) { s["mihomo_version"] = "" }, wantErr: true},
		{name: "wrong healthy type", mutate: func(s map[string]any) { s["mihomo_healthy"] = "true" }, wantErr: true},
		{name: "negative counter", mutate: func(s map[string]any) { s["upload_total"] = float64(-1) }, wantErr: true},
		{name: "fractional counter", mutate: func(s map[string]any) { s["download_total"] = float64(1.5) }, wantErr: true},
		{name: "wrong connections type", mutate: func(s map[string]any) { s["connections"] = "many" }, wantErr: true},
		{name: "invalid hash", mutate: func(s map[string]any) { s["config_sha256"] = "abc" }, wantErr: true},
		{name: "oversized error", mutate: func(s map[string]any) { s["last_error"] = strings.Repeat("x", agentWSMaxErrorBytes+1) }, wantErr: true},
		{name: "missing field", mutate: func(s map[string]any) { delete(s, "connections") }, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := valid()
			tt.mutate(status)
			err := validateAgentWSStatus(status)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateAgentWSStatus() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAgentWebSocketDoesNotPersistInvalidStatus(t *testing.T) {
	app, code, token := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatalf("dial authenticated WebSocket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	status := map[string]any{
		"mihomo_version": "v1.19.3",
		"mihomo_healthy": true,
		"upload_total":   float64(12),
		"download_total": float64(34),
		"upload_speed":   float64(1),
		"download_speed": float64(2),
		"connections":    "many",
		"config_sha256":  strings.Repeat("a", 64),
		"last_error":     "",
	}
	if err := conn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-invalid", "status": status}); err != nil {
		t.Fatalf("send invalid heartbeat: %v", err)
	}
	var response map[string]any
	if err := conn.ReadJSON(&response); err != nil {
		t.Fatalf("read validation response: %v", err)
	}
	if response["type"] != "error" || response["id"] != "hb-invalid" {
		t.Fatalf("unexpected validation response: %#v", response)
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_status_"+code] != "" || settings["agent_lastseen_"+code] != "" {
		t.Fatal("invalid heartbeat must not be persisted")
	}
}

func TestHTTPAgentHeartbeatRejectsMissingRequiredFields(t *testing.T) {
	app, code, token := websocketTestApp(t)
	body := strings.NewReader(`{"mihomo_version":"v1.19.3","mihomo_healthy":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	app.handleAgentHeartbeat(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "心跳缺少必需字段") {
		t.Fatalf("response should explain missing heartbeat field, got %s", rec.Body.String())
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_status_"+code] != "" || settings["agent_lastseen_"+code] != "" {
		t.Fatal("invalid HTTP heartbeat must not be persisted")
	}
}

func TestHTTPAgentHeartbeatAcceptsCompleteTelemetry(t *testing.T) {
	app, code, token := websocketTestApp(t)
	status := map[string]any{
		"hostname":       "edge-node-01",
		"os":             "linux",
		"arch":           "amd64",
		"mihomo_version": "v1.19.3",
		"mihomo_healthy": true,
		"upload_total":   float64(12),
		"download_total": float64(34),
		"upload_speed":   float64(1),
		"download_speed": float64(2),
		"connections":    float64(3),
		"config_sha256":  strings.Repeat("a", 64),
		"last_error":     "",
	}
	body, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	app.handleAgentHeartbeat(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	var persisted map[string]any
	if err := json.Unmarshal([]byte(settings["agent_status_"+code]), &persisted); err != nil {
		t.Fatalf("decode persisted status: %v", err)
	}
	if persisted["received_at"] == nil || persisted["mihomo_version"] != "v1.19.3" {
		t.Fatalf("complete heartbeat not persisted correctly: %#v", persisted)
	}
}

// TestAgentWebSocketCannotPersistHeartbeatAfterAuthorizationRevocation verifies
// that deleting an Agent binding invalidates its already-open WebSocket session.
func TestAgentWebSocketCannotPersistHeartbeatAfterAuthorizationRevocation(t *testing.T) {
	app, code, token := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatalf("dial authenticated WebSocket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatalf("read welcome: %v", err)
	}

	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/agents?code="+code, nil)
	revokeRec := httptest.NewRecorder()
	app.handleDeleteAgent(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200; body=%s", revokeRec.Code, revokeRec.Body.String())
	}

	status := map[string]any{
		"mihomo_version": "v1.19.3",
		"mihomo_healthy": true,
		"upload_total":   float64(12),
		"download_total": float64(34),
		"upload_speed":   float64(1),
		"download_speed": float64(2),
		"connections":    float64(3),
		"config_sha256":  strings.Repeat("a", 64),
		"last_error":     "",
	}
	if err := conn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-revoked", "status": status}); err != nil {
		t.Fatalf("send heartbeat after revocation: %v", err)
	}
	if _, _, err := conn.ReadMessage(); !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		t.Fatalf("revoked WebSocket should close cleanly, got %v", err)
	}

	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_status_"+code] != "" || settings["agent_lastseen_"+code] != "" {
		t.Fatalf("revoked Agent heartbeat was persisted: %#v", settings)
	}
}

// TestHTTPAgentHeartbeatRejectsRevokedAuthorization verifies that a previously
// issued token cannot continue writing telemetry after its machine binding is removed.
func TestHTTPAgentHeartbeatRejectsRevokedAuthorization(t *testing.T) {
	app, code, token := websocketTestApp(t)
	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/agents?code="+code, nil)
	revokeRec := httptest.NewRecorder()
	app.handleDeleteAgent(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200; body=%s", revokeRec.Code, revokeRec.Body.String())
	}

	status := map[string]any{
		"mihomo_version": "v1.19.3",
		"mihomo_healthy": true,
		"upload_total":   float64(12),
		"download_total": float64(34),
		"upload_speed":   float64(1),
		"download_speed": float64(2),
		"connections":    float64(3),
		"config_sha256":  strings.Repeat("a", 64),
		"last_error":     "",
	}
	body, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	app.handleAgentHeartbeat(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("heartbeat status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_status_"+code] != "" || settings["agent_lastseen_"+code] != "" {
		t.Fatalf("revoked HTTP heartbeat was persisted: %#v", settings)
	}
}

func TestAgentWebSocketCommandRequestReturnsNoneWhenQueueEmpty(t *testing.T) {
	app, _, token := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatalf("dial authenticated WebSocket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	if err := conn.WriteJSON(map[string]any{"type": "command.request", "id": "cmd-poll-1"}); err != nil {
		t.Fatalf("request command: %v", err)
	}
	var response map[string]any
	if err := conn.ReadJSON(&response); err != nil {
		t.Fatalf("read command response: %v", err)
	}
	if response["type"] != "command.none" || response["id"] != "cmd-poll-1" {
		t.Fatalf("unexpected command response: %#v", response)
	}
}

func TestAgentWebSocketDeliversAndAcknowledgesPendingCommand(t *testing.T) {
	app, code, token := websocketTestApp(t)
	pending := map[string]string{
		"id":   "cmd-test-1",
		"type": "update_mihomo",
	}
	raw, err := json.Marshal(pending)
	if err != nil {
		t.Fatalf("marshal pending command: %v", err)
	}
	if err := app.store.UpdateSettings(map[string]string{"agent_command_" + code: string(raw)}); err != nil {
		t.Fatalf("queue pending command: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatalf("dial authenticated WebSocket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	if err := conn.WriteJSON(map[string]any{"type": "command.request", "id": "poll-1"}); err != nil {
		t.Fatalf("request command: %v", err)
	}
	var delivered map[string]any
	if err := conn.ReadJSON(&delivered); err != nil {
		t.Fatalf("read delivered command: %v", err)
	}
	if delivered["type"] != "command.deliver" || delivered["id"] != "poll-1" {
		t.Fatalf("unexpected command envelope: %#v", delivered)
	}
	command, ok := delivered["command"].(map[string]any)
	if !ok || command["id"] != "cmd-test-1" || command["type"] != "update_mihomo" {
		t.Fatalf("unexpected delivered command: %#v", delivered["command"])
	}

	if err := conn.WriteJSON(map[string]any{
		"type": "command.ack", "id": "cmd-test-1",
		"command_status": "success", "message": "test completed",
	}); err != nil {
		t.Fatalf("send command ACK: %v", err)
	}
	var ack map[string]any
	if err := conn.ReadJSON(&ack); err != nil {
		t.Fatalf("read ACK confirmation: %v", err)
	}
	if ack["type"] != "command.acknowledged" || ack["id"] != "cmd-test-1" || ack["ok"] != true {
		t.Fatalf("unexpected ACK confirmation: %#v", ack)
	}

	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("read persisted command result: %v", err)
	}
	if settings["agent_command_"+code] != "" {
		t.Fatalf("acknowledged command remains queued: %s", settings["agent_command_"+code])
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(settings["agent_command_result_"+code]), &result); err != nil {
		t.Fatalf("decode persisted command result: %v", err)
	}
	if result["id"] != "cmd-test-1" || result["status"] != "success" || result["message"] != "test completed" {
		t.Fatalf("unexpected persisted command result: %#v", result)
	}
}

func TestAgentWebSocketConfigSyncAndUnchangedHash(t *testing.T) {
	app, code, token := websocketTestApp(t)
	configYAML := strings.TrimSpace("allow-lan: true\nmixed-port: 7890\nsecret: test-secret\ntun:\n  enable: true\ndns:\n  enable: true\n")
	if err := app.store.SaveNodeConfig(code, configYAML); err != nil {
		t.Fatalf("save node config: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatalf("dial authenticated WebSocket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	if welcome["type"] != "welcome" {
		t.Fatalf("welcome type = %#v, want welcome", welcome["type"])
	}

	requestID := "config-request-1"
	if err := conn.WriteJSON(map[string]any{
		"type": "config.request", "id": requestID, "config_sha256": "",
	}); err != nil {
		t.Fatalf("request initial config: %v", err)
	}
	var first map[string]any
	if err := conn.ReadJSON(&first); err != nil {
		t.Fatalf("read initial config response: %v", err)
	}
	expectedYAML, err := normalizeAgentProxyConfig(configYAML)
	if err != nil {
		t.Fatalf("normalize expected Agent config: %v", err)
	}
	sum := sha256.Sum256([]byte(expectedYAML))
	expectedHash := hex.EncodeToString(sum[:])
	if first["type"] != "config.sync" || first["id"] != requestID ||
		first["sha256"] != expectedHash || first["yaml"] != expectedYAML {
		t.Fatalf("unexpected initial config response: %#v", first)
	}

	if err := conn.WriteJSON(map[string]any{
		"type": "config.request", "id": "config-request-2", "config_sha256": expectedHash,
	}); err != nil {
		t.Fatalf("request unchanged config: %v", err)
	}
	var second map[string]any
	if err := conn.ReadJSON(&second); err != nil {
		t.Fatalf("read unchanged config response: %v", err)
	}
	if second["type"] != "config.unchanged" || second["id"] != "config-request-2" ||
		second["sha256"] != expectedHash {
		t.Fatalf("unexpected unchanged config response: %#v", second)
	}

	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if settings["agent_lastseen_"+code] == "" {
		t.Fatal("config request did not update Agent last-seen timestamp")
	}
}

func TestAgentWebSocketCannotReadConfigAfterAuthorizationRevocation(t *testing.T) {
	app, code, token := websocketTestApp(t)
	const configYAML = "mixed-port: 7890\nsecret: retained-secret\n"
	if err := app.store.SaveNodeConfig(code, configYAML); err != nil {
		t.Fatalf("save node config: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatalf("dial authenticated WebSocket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatalf("read welcome: %v", err)
	}

	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/agents?code="+code, nil)
	revokeRec := httptest.NewRecorder()
	app.handleDeleteAgent(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200; body=%s", revokeRec.Code, revokeRec.Body.String())
	}

	if err := conn.WriteJSON(map[string]any{"type": "config.request", "id": "cfg-after-revoke"}); err != nil {
		t.Fatalf("send config request after revocation: %v", err)
	}
	if _, _, err := conn.ReadMessage(); !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		t.Fatalf("revoked Agent connection should close before config delivery, got %v", err)
	}
}

func TestAgentWebSocketSupersededConnectionCannotReadPendingCommand(t *testing.T) {
	app, code, token := websocketTestApp(t)
	pending := `{"id":"cmd-current","type":"update_mihomo"}`
	if err := app.store.UpdateSettings(map[string]string{"agent_command_" + code: pending}); err != nil {
		t.Fatalf("seed pending command: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	dial := func() *websocket.Conn {
		t.Helper()
		conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
		if err != nil {
			t.Fatalf("dial authenticated WebSocket: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var welcome map[string]any
		if err := conn.ReadJSON(&welcome); err != nil {
			conn.Close()
			t.Fatalf("read welcome: %v", err)
		}
		return conn
	}
	oldConn := dial()
	defer oldConn.Close()
	newConn := dial()
	defer newConn.Close()

	if err := oldConn.WriteJSON(map[string]any{"type": "command.request", "id": "old-connection"}); err != nil {
		t.Fatalf("send command request on superseded connection: %v", err)
	}
	if _, _, err := oldConn.ReadMessage(); !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		t.Fatalf("superseded connection should close before command delivery, got %v", err)
	}
}

// TestAgentWebSocketHeartbeatRevalidatesAuthorizationAfterBindingRemoval covers
// the in-flight handshake/revocation window: the socket generation still matches,
// but the Agent binding has already been removed.
func TestAgentWebSocketHeartbeatRevalidatesAuthorizationAfterBindingRemoval(t *testing.T) {
	app, code, token := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatalf("dial authenticated WebSocket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatalf("read welcome: %v", err)
	}

	// SmartDNS configuration is private node state and must be removed with the credential.
	if err := app.store.UpdateSettings(map[string]string{"smartdns_config_" + code: "private resolver config"}); err != nil {
		t.Fatalf("seed SmartDNS config: %v", err)
	}
	// Simulate binding removal after handshake authentication but before the
	// connection-generation invalidation becomes visible to this socket.
	if err := app.store.DeleteAgentBinding(code); err != nil {
		t.Fatalf("DeleteAgentBinding: %v", err)
	}
	status := map[string]any{
		"mihomo_version": "v1.19.3",
		"mihomo_healthy": true,
		"upload_total":   float64(12),
		"download_total": float64(34),
		"upload_speed":   float64(1),
		"download_speed": float64(2),
		"connections":    float64(3),
		"config_sha256":  strings.Repeat("a", 64),
		"last_error":     "",
	}
	if err := conn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-revocation-race", "status": status}); err != nil {
		t.Fatalf("send heartbeat after binding removal: %v", err)
	}
	var response map[string]any
	if err := conn.ReadJSON(&response); err != nil {
		t.Fatalf("read response after binding removal: %v", err)
	}
	if response["type"] != "error" || !strings.Contains(response["message"].(string), "授权") {
		t.Fatalf("revoked WebSocket heartbeat should fail authorization, got %#v", response)
	}

	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_status_"+code] != "" || settings["agent_lastseen_"+code] != "" {
		t.Fatalf("heartbeat after binding removal was persisted: %#v", settings)
	}
	if settings["smartdns_config_"+code] != "" {
		t.Fatalf("SmartDNS config survived Agent binding revocation: %#v", settings)
	}
}

func TestLegacyHTTPAgentEndpointsRejectRevokedBinding(t *testing.T) {
	app, code, token := websocketTestApp(t)
	if err := app.store.UpdateSettings(map[string]string{
		"agent_command_" + code: `{"id":"cmd-after-revoke","type":"update_mihomo"}`,
	}); err != nil {
		t.Fatalf("seed pending command: %v", err)
	}

	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/agents?code="+code, nil)
	revokeRec := httptest.NewRecorder()
	app.handleDeleteAgent(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200; body=%s", revokeRec.Code, revokeRec.Body.String())
	}

	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{name: "config", handler: app.handleAgentConfig},
		{name: "command", handler: app.handleAgentCommand},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/"+tc.name, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			tc.handler(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
			}
		})
	}

	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings["agent_lastseen_"+code] != "" || settings["agent_command_"+code] != "" {
		t.Fatalf("revoked Agent state was recreated or command remained: %#v", settings)
	}
}

// TestAgentWebSocketSupportsMultipleRuntimeOperationsOnOneSession protects the
// persistent-session contract: heartbeat, config sync, command delivery, and ACK
// must work sequentially without opening a replacement connection.
func TestAgentWebSocketSupportsMultipleRuntimeOperationsOnOneSession(t *testing.T) {
	app, code, token := websocketTestApp(t)
	configYAML := strings.TrimSpace("allow-lan: true\nmixed-port: 7890\nsecret: test-secret\ntun:\n  enable: true\ndns:\n  enable: true\n")
	if err := app.store.SaveNodeConfig(code, configYAML); err != nil {
		t.Fatalf("save node config: %v", err)
	}
	pending, err := json.Marshal(map[string]string{"id": "cmd-session-1", "type": "update_mihomo"})
	if err != nil {
		t.Fatalf("marshal pending command: %v", err)
	}
	if err := app.store.UpdateSettings(map[string]string{"agent_command_" + code: string(pending)}); err != nil {
		t.Fatalf("queue pending command: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatalf("dial authenticated WebSocket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil || welcome["type"] != "welcome" {
		t.Fatalf("read welcome: payload=%#v err=%v", welcome, err)
	}

	status := map[string]any{
		"mihomo_version": "v1.19.3", "mihomo_healthy": true,
		"upload_total": float64(12), "download_total": float64(34),
		"upload_speed": float64(1), "download_speed": float64(2),
		"connections": float64(3), "config_sha256": strings.Repeat("a", 64),
		"last_error": "",
	}
	if err := conn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-session-1", "status": status}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}
	var heartbeatAck map[string]any
	if err := conn.ReadJSON(&heartbeatAck); err != nil {
		t.Fatalf("read heartbeat ACK: %v", err)
	}
	if heartbeatAck["type"] != "heartbeat.ack" || heartbeatAck["id"] != "hb-session-1" {
		t.Fatalf("unexpected heartbeat ACK: %#v", heartbeatAck)
	}

	if err := conn.WriteJSON(map[string]any{"type": "config.request", "id": "cfg-session-1", "config_sha256": ""}); err != nil {
		t.Fatalf("request config: %v", err)
	}
	var configResponse map[string]any
	if err := conn.ReadJSON(&configResponse); err != nil {
		t.Fatalf("read config response: %v", err)
	}
	expectedYAML, err := normalizeAgentProxyConfig(configYAML)
	if err != nil {
		t.Fatalf("normalize expected Agent config: %v", err)
	}
	if configResponse["type"] != "config.sync" || configResponse["id"] != "cfg-session-1" || configResponse["yaml"] != expectedYAML {
		t.Fatalf("unexpected config response: %#v", configResponse)
	}

	if err := conn.WriteJSON(map[string]any{"type": "command.request", "id": "poll-session-1"}); err != nil {
		t.Fatalf("request command: %v", err)
	}
	var commandResponse map[string]any
	if err := conn.ReadJSON(&commandResponse); err != nil {
		t.Fatalf("read command response: %v", err)
	}
	command, ok := commandResponse["command"].(map[string]any)
	if commandResponse["type"] != "command.deliver" || commandResponse["id"] != "poll-session-1" ||
		!ok || command["id"] != "cmd-session-1" {
		t.Fatalf("unexpected command response: %#v", commandResponse)
	}

	if err := conn.WriteJSON(map[string]any{
		"type": "command.ack", "id": "cmd-session-1",
		"command_status": "success", "message": "session test passed",
	}); err != nil {
		t.Fatalf("send command ACK: %v", err)
	}
	var commandAck map[string]any
	if err := conn.ReadJSON(&commandAck); err != nil {
		t.Fatalf("read command ACK confirmation: %v", err)
	}
	if commandAck["type"] != "command.acknowledged" || commandAck["id"] != "cmd-session-1" || commandAck["ok"] != true {
		t.Fatalf("unexpected command ACK confirmation: %#v", commandAck)
	}

	// The same socket must remain valid after all operations, not be superseded.
	if err := conn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-session-2", "status": status}); err != nil {
		t.Fatalf("send second heartbeat on same session: %v", err)
	}
	var secondAck map[string]any
	if err := conn.ReadJSON(&secondAck); err != nil {
		t.Fatalf("read second heartbeat ACK: %v", err)
	}
	if secondAck["type"] != "heartbeat.ack" || secondAck["id"] != "hb-session-2" {
		t.Fatalf("unexpected second heartbeat ACK: %#v", secondAck)
	}
}

func TestQueueAgentMihomoUpdateValidatesAndPersistsCommand(t *testing.T) {
	app, _, _ := websocketTestApp(t)
	sha := strings.Repeat("a", 64)
	if err := app.queueAgentMihomoUpdate("ws_node_01", "v1.19.33", sha); err != nil {
		t.Fatalf("queueAgentMihomoUpdate: %v", err)
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	var command map[string]string
	if err := json.Unmarshal([]byte(settings["agent_command_ws_node_01"]), &command); err != nil {
		t.Fatalf("decode persisted command: %v", err)
	}
	if command["type"] != "update_mihomo" || command["version"] != "v1.19.33" || command["sha256"] != sha || command["id"] == "" {
		t.Fatalf("unexpected persisted command: %#v", command)
	}
	if err := app.queueAgentMihomoUpdate("ws_node_01", "v1.19.33", sha); err == nil || !strings.Contains(err.Error(), "已有待执行命令") {
		t.Fatalf("expected duplicate pending command rejection, got %v", err)
	}
}

func TestQueueAgentMihomoUpdateRejectsInvalidInputAndUnknownAgent(t *testing.T) {
	app, _, _ := websocketTestApp(t)
	cases := []struct {
		name, machineCode, version, sha string
	}{
		{name: "bad machine code", machineCode: "bad code", version: "v1.19.33", sha: strings.Repeat("a", 64)},
		{name: "bad version", machineCode: "ws_node_01", version: "latest", sha: strings.Repeat("a", 64)},
		{name: "bad sha", machineCode: "ws_node_01", version: "v1.19.33", sha: "deadbeef"},
		{name: "unknown agent", machineCode: "unknown", version: "v1.19.33", sha: strings.Repeat("a", 64)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := app.queueAgentMihomoUpdate(tc.machineCode, tc.version, tc.sha); err == nil {
				t.Fatal("expected invalid command to be rejected")
			}
		})
	}
}

// TestAgentWebSocketHeartbeatTTLAllowsLongKernelUpdate guards against the server
// closing an Agent session while a bounded Mihomo download/restart/health check is
// still running and the Agent cannot send another heartbeat until it finishes.
func TestSafeAgentWebSocketErrorRedactsSensitiveDetails(t *testing.T) {
	err := fmt.Errorf("open /opt/s5m-agent/data/config.yaml failed: token=abc123 secret: xyz789: YAML syntax error")
	got := safeAgentWebSocketError("读取节点配置", err)
	if !strings.Contains(got, "读取节点配置失败") || !strings.Contains(got, "YAML syntax error") {
		t.Fatalf("diagnostic lost useful error details: %q", got)
	}
	for _, secret := range []string{"abc123", "xyz789", "/opt/s5m-agent"} {
		if strings.Contains(got, secret) {
			t.Fatalf("diagnostic leaked sensitive value %q: %q", secret, got)
		}
	}
}

func TestSafeAgentWebSocketErrorHandlesEmptyErrorAndBoundsLength(t *testing.T) {
	if got := safeAgentWebSocketError("读取节点配置", nil); got != "读取节点配置失败: 未知错误" {
		t.Fatalf("empty error diagnostic = %q", got)
	}
	got := safeAgentWebSocketError("读取节点配置", fmt.Errorf("%s", strings.Repeat("x", 1000)))
	if len(got) > 650 {
		t.Fatalf("diagnostic exceeds safe bound: %d bytes", len(got))
	}
}

func TestAgentWebSocketHeartbeatTTLAllowsLongKernelUpdate(t *testing.T) {
	if agentWSHeartbeatTTL < 5*time.Minute {
		t.Fatalf("agent WebSocket heartbeat TTL = %s; want at least 5 minutes for kernel updates", agentWSHeartbeatTTL)
	}
}

func TestAckAgentWSCommandRedactsSensitiveResultBeforePersisting(t *testing.T) {
	app, code, _ := websocketTestApp(t)
	pending := `{"id":"cmd-redact","type":"update_mihomo"}`
	if err := app.store.UpdateSettings(map[string]string{"agent_command_" + code: pending}); err != nil {
		t.Fatalf("queue pending command: %v", err)
	}
	message := "token=super-secret failed at /tmp/private/config.yaml"
	if err := app.ackAgentWSCommand(code, "cmd-redact", "failed", message, ""); err != nil {
		t.Fatalf("ack command: %v", err)
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("read command result: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(settings["agent_command_result_"+code]), &result); err != nil {
		t.Fatalf("decode command result: %v", err)
	}
	got, _ := result["message"].(string)
	if strings.Contains(got, "super-secret") || strings.Contains(got, "/tmp/private/config.yaml") {
		t.Fatalf("sensitive command result was persisted unredacted: %q", got)
	}
	if !strings.Contains(got, "[已隐藏]") || !strings.Contains(got, "[路径已隐藏]") {
		t.Fatalf("command result lost redaction markers: %q", got)
	}
}

func TestSanitizeAgentWebSocketTextRedactsJSONCredentialsAndBearerTokens(t *testing.T) {
	input := `{"token":"json-secret","api_key":"key-secret"} Authorization: Bearer bearer-secret`
	got := sanitizeAgentWebSocketText(input)
	for _, secret := range []string{"json-secret", "key-secret", "bearer-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("sensitive value %q remained in sanitized text: %q", secret, got)
		}
	}
	if strings.Count(got, "[已隐藏]") < 3 {
		t.Fatalf("expected JSON credentials and bearer token to be redacted: %q", got)
	}
}

func TestSanitizeAgentWebSocketTextRedactsQuotedCredentialsWithSpacesAndEscapes(t *testing.T) {
	input := `{"token":"secret with spaces","password":"value with \"quote\"","api_key": "key with spaces"} token='plain value with spaces' Authorization: Bearer bearer-secret`
	got := sanitizeAgentWebSocketText(input)
	for _, secret := range []string{"secret with spaces", "value with", "quote", "key with spaces", "plain value with spaces", "bearer-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("sensitive value %q remained in sanitized text: %q", secret, got)
		}
	}
	if strings.Count(got, "[已隐藏]") < 4 {
		t.Fatalf("expected quoted JSON credentials and bearer token to be redacted: %q", got)
	}
}

func TestAgentWebSocketPersistsConfigSyncErrorInHeartbeat(t *testing.T) {
	app, code, token := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatalf("dial authenticated WebSocket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	if welcome["type"] != "welcome" {
		t.Fatalf("unexpected welcome: %#v", welcome)
	}

	const reportedError = "Agent 配置同步失败: Mihomo reload rejected config"
	status := map[string]any{
		"mihomo_version": "v1.19.33", "mihomo_healthy": true,
		"upload_total": float64(12), "download_total": float64(34),
		"upload_speed": float64(1), "download_speed": float64(2),
		"connections": float64(3), "config_sha256": strings.Repeat("a", 64),
		"last_error": reportedError,
	}
	if err := conn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-config-error", "status": status}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}
	var ack map[string]any
	if err := conn.ReadJSON(&ack); err != nil {
		t.Fatalf("read heartbeat ACK: %v", err)
	}
	if ack["type"] != "heartbeat.ack" || ack["id"] != "hb-config-error" || ack["ok"] != true {
		t.Fatalf("unexpected heartbeat ACK: %#v", ack)
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("read persisted Agent settings: %v", err)
	}
	var persisted map[string]any
	if err := json.Unmarshal([]byte(settings["agent_status_"+code]), &persisted); err != nil {
		t.Fatalf("decode persisted Agent status: %v", err)
	}
	if got, _ := persisted["last_error"].(string); got != reportedError {
		t.Fatalf("persisted last_error = %q, want %q", got, reportedError)
	}
	if settings["agent_lastseen_"+code] == "" {
		t.Fatal("heartbeat timestamp was not persisted with error status")
	}

	// A later healthy heartbeat must replace the stale error, not leave the
	// previous failure visible indefinitely in the console.
	recoveredStatus := map[string]any{
		"mihomo_version": "v1.19.33", "mihomo_healthy": true,
		"upload_total": float64(15), "download_total": float64(40),
		"upload_speed": float64(2), "download_speed": float64(3),
		"connections": float64(2), "config_sha256": strings.Repeat("b", 64),
		"last_error": "",
	}
	if err := conn.WriteJSON(map[string]any{"type": "heartbeat", "id": "hb-config-recovered", "status": recoveredStatus}); err != nil {
		t.Fatalf("send recovered heartbeat: %v", err)
	}
	ack = nil
	if err := conn.ReadJSON(&ack); err != nil {
		t.Fatalf("read recovered heartbeat ACK: %v", err)
	}
	if ack["type"] != "heartbeat.ack" || ack["id"] != "hb-config-recovered" || ack["ok"] != true {
		t.Fatalf("unexpected recovered heartbeat ACK: %#v", ack)
	}
	settings, err = app.store.GetSettings()
	if err != nil {
		t.Fatalf("read recovered Agent settings: %v", err)
	}
	if err := json.Unmarshal([]byte(settings["agent_status_"+code]), &persisted); err != nil {
		t.Fatalf("decode recovered Agent status: %v", err)
	}
	if got, _ := persisted["last_error"].(string); got != "" {
		t.Fatalf("stale last_error remained after recovery: %q", got)
	}
}

func TestAgentWebSocketIsClosedImmediatelyAfterAuthorizationRevocation(t *testing.T) {
	app, code, token := websocketTestApp(t)
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatalf("dial authenticated WebSocket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatalf("read welcome: %v", err)
	}

	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/agents?code="+code, nil)
	revokeRec := httptest.NewRecorder()
	app.handleDeleteAgent(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200; body=%s", revokeRec.Code, revokeRec.Body.String())
	}

	// No heartbeat or further request is sent: revocation itself must close
	// the idle socket rather than waiting for the next message/TTL timeout.
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatal("revoked idle WebSocket remained open")
	}
	if websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
		t.Fatalf("unexpected WebSocket close error: %v", err)
	}
}


func TestSmartDNSControllerCopyChangesOnlyAfterSuccessfulApply(t *testing.T) {
	app, code, _ := websocketTestApp(t)
	const previous = "bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nserver 8.8.8.8"
	const candidate = "bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nserver 1.1.1.1"
	if err := app.store.UpdateSettings(map[string]string{"smartdns_config_" + code: previous}); err != nil {
		t.Fatalf("seed previous config: %v", err)
	}
	failedPayload, err := json.Marshal(map[string]string{"id": "smartdns-failed-apply", "type": "configure_smartdns", "config": candidate})
	if err != nil { t.Fatalf("marshal failed command: %v", err) }
	if err := app.store.QueueAgentSmartDNSCommand(code, string(failedPayload)); err != nil {
		t.Fatalf("queue failed apply: %v", err)
	}
	if _, matched, err := app.store.AckAgentCommandWithConfig(code, "smartdns-failed-apply", "failed", "validation failed", "", time.Now().Unix()); err != nil || !matched {
		t.Fatalf("ack failed apply: matched=%v err=%v", matched, err)
	}
	got, err := app.store.GetSetting("smartdns_config_" + code)
	if err != nil || got != previous {
		t.Fatalf("failed apply replaced last-known-good config: got=%q err=%v", got, err)
	}

	successPayload, err := json.Marshal(map[string]string{"id": "smartdns-success-apply", "type": "configure_smartdns", "config": candidate})
	if err != nil { t.Fatalf("marshal successful command: %v", err) }
	if err := app.store.QueueAgentSmartDNSCommand(code, string(successPayload)); err != nil {
		t.Fatalf("queue successful apply: %v", err)
	}
	if _, matched, err := app.store.AckAgentCommandWithConfig(code, "smartdns-success-apply", "success", "applied", "", time.Now().Unix()); err != nil || !matched {
		t.Fatalf("ack successful apply: matched=%v err=%v", matched, err)
	}
	got, err = app.store.GetSetting("smartdns_config_" + code)
	if err != nil || got != candidate {
		t.Fatalf("successful apply did not update controller config: got=%q err=%v", got, err)
	}
}


func TestSmartDNSCommandsCannotQueueAfterAgentBindingRevocation(t *testing.T) {
	app, code, _ := websocketTestApp(t)
	if err := app.store.DeleteAgentBinding(code); err != nil {
		t.Fatalf("revoke Agent binding: %v", err)
	}
	if err := app.store.QueueAgentSmartDNSReadCommand(code, `{"id":"read-after-revoke","type":"read_smartdns_config"}`); err == nil {
		t.Fatal("SmartDNS read command queued after Agent binding revocation")
	}
	if err := app.store.QueueAgentSmartDNSCommand(code, `{"id":"apply-after-revoke","type":"configure_smartdns","config":"candidate"}`); err == nil {
		t.Fatal("SmartDNS apply command queued after Agent binding revocation")
	}
	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if settings["agent_command_"+code] != "" {
		t.Fatalf("revoked Agent received a pending command: %#v", settings)
	}
}


func TestNewAgentCommandIDUsesUniqueHexadecimalIdentifiers(t *testing.T) {
	seen := make(map[string]struct{}, 256)
	for i := 0; i < 256; i++ {
		id, err := newAgentCommandID()
		if err != nil {
			t.Fatalf("newAgentCommandID: %v", err)
		}
		if len(id) != 32 {
			t.Fatalf("command ID length = %d, want 32", len(id))
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Fatalf("command ID is not hexadecimal: %q: %v", id, err)
		}
		if _, exists := seen[id]; exists {
			t.Fatalf("duplicate command ID generated: %q", id)
		}
		seen[id] = struct{}{}
	}
}


func TestAgentWebSocketSmartDNSHealthTransitionResyncsWithoutPersistingRuntimeDNS(t *testing.T) {
	app, code, token := websocketTestApp(t)
	persisted, err := app.BuildConfigForMachine(code)
	if err != nil { t.Fatalf("build baseline node config: %v", err) }
	if err := app.store.SaveNodeConfig(code, persisted); err != nil { t.Fatalf("save node config: %v", err) }
	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil { t.Fatalf("dial authenticated WebSocket: %v", err) }
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil { t.Fatalf("read welcome: %v", err) }
	setHealth := func(healthy bool, id string) {
		t.Helper()
		status := map[string]any{
			"mihomo_version": "v1.19.33",
			"mihomo_healthy": true,
			"upload_total": float64(12),
			"download_total": float64(34),
			"upload_speed": float64(1),
			"download_speed": float64(2),
			"connections": float64(3),
			"config_sha256": strings.Repeat("a", 64),
			"last_error": "",
			"smartdns_available": true,
			"smartdns_running": healthy,
			"smartdns_dns_healthy": healthy,
		}
		if err := conn.WriteJSON(map[string]any{"type":"heartbeat", "id":id, "status":status}); err != nil { t.Fatalf("send SmartDNS health heartbeat: %v", err) }
		var ack map[string]any
		if err := conn.ReadJSON(&ack); err != nil { t.Fatalf("read SmartDNS heartbeat ACK: %v", err) }
		if ack["type"] != "heartbeat.ack" || ack["id"] != id || ack["ok"] != true { t.Fatalf("invalid SmartDNS heartbeat ACK: %#v", ack) }
	}

	setHealth(true, "smartdns-health-initial")
	if err := conn.WriteJSON(map[string]any{"type":"config.request", "id":"smartdns-healthy", "config_sha256":""}); err != nil { t.Fatal(err) }
	var healthy map[string]any
	if err := conn.ReadJSON(&healthy); err != nil { t.Fatalf("read healthy config: %v", err) }
	if healthy["type"] != "config.sync" || !strings.Contains(healthy["yaml"].(string), "127.0.0.1:6053") { t.Fatalf("healthy SmartDNS config was not routed locally: %#v", healthy) }
	healthyHash, ok := healthy["sha256"].(string)
	if !ok || healthyHash == "" { t.Fatalf("missing healthy config hash: %#v", healthy) }

	stored, err := app.store.GetNodeConfig(code)
	if err != nil { t.Fatal(err) }
	if stored == nil || stored.YAML != persisted { t.Fatalf("runtime DNS leaked into persisted node config: %#v", stored) }

	setHealth(false, "smartdns-health-lost")
	if err := conn.WriteJSON(map[string]any{"type":"config.request", "id":"smartdns-unhealthy", "config_sha256":healthyHash}); err != nil { t.Fatal(err) }
	var fallback map[string]any
	if err := conn.ReadJSON(&fallback); err != nil { t.Fatalf("read fallback config: %v", err) }
	fallbackYAML, _ := fallback["yaml"].(string)
	if fallback["type"] != "config.sync" || !strings.Contains(fallbackYAML, "223.5.5.5") || !strings.Contains(fallbackYAML, "119.29.29.29") || strings.Contains(fallbackYAML, "127.0.0.1:6053") {
		t.Fatalf("SmartDNS health loss did not trigger independent upstream fallback: %#v", fallback)
	}
	if fallback["sha256"] == healthyHash { t.Fatal("SmartDNS health transition did not change config hash") }
	stored, err = app.store.GetNodeConfig(code)
	if err != nil { t.Fatal(err) }
	if stored == nil || stored.YAML != persisted { t.Fatalf("fallback sync mutated persisted node config: %#v", stored) }

	// When SmartDNS recovers, the next regular config request must switch the
	// runtime DNS back to localhost without persisting that runtime overlay.
	fallbackHash, ok := fallback["sha256"].(string)
	if !ok || fallbackHash == "" { t.Fatalf("missing fallback config hash: %#v", fallback) }
	setHealth(true, "smartdns-health-recovered")
	if err := conn.WriteJSON(map[string]any{"type":"config.request", "id":"smartdns-recovered", "config_sha256":fallbackHash}); err != nil { t.Fatal(err) }
	var recovered map[string]any
	if err := conn.ReadJSON(&recovered); err != nil { t.Fatalf("read recovered config: %v", err) }
	recoveredYAML, _ := recovered["yaml"].(string)
	if recovered["type"] != "config.sync" || !strings.Contains(recoveredYAML, "127.0.0.1:6053") {
		t.Fatalf("SmartDNS recovery did not restore local DNS routing: %#v", recovered)
	}
	if recovered["sha256"] == fallbackHash { t.Fatal("SmartDNS recovery did not change config hash") }
	stored, err = app.store.GetNodeConfig(code)
	if err != nil { t.Fatal(err) }
	if stored == nil || stored.YAML != persisted { t.Fatalf("recovery sync mutated persisted node config: %#v", stored) }
}
