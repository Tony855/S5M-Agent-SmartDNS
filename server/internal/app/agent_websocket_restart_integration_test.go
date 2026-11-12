package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

// This integration test joins the two previously separate guarantees:
// durable Master command storage across a process restart and WebSocket
// redelivery when an Agent disconnects before acknowledging the command.
func TestAgentCommandSurvivesMasterRestartAndWebSocketDisconnect(t *testing.T) {
	const (
		machineCode = "restart_ws_node"
		machineSecret = "restart-ws-dedicated-secret"
		commandID = "cmd-restart-ws-001"
	)
	dbPath := filepath.Join(t.TempDir(), "master-restart.db")
	jwtKey := []byte("restart-ws-test-signing-key")

	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("open initial store: %v", err)
	}
	if err := store.UpdateSettings(map[string]string{
		"agent_token": "global-test-token",
		"agent_machine_" + machineCode: machineSecret,
		"agent_command_" + machineCode: `{"id":"cmd-restart-ws-001","type":"set_smartdns_enabled","enabled":true}`,
	}); err != nil {
		_ = store.db.Close()
		t.Fatalf("persist pending command: %v", err)
	}
	if err := store.db.Close(); err != nil {
		t.Fatalf("close initial store: %v", err)
	}

	sum := sha256.Sum256([]byte(machineSecret))
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": machineCode,
		"role": "agent",
		"ver": hex.EncodeToString(sum[:]),
	}).SignedString(jwtKey)
	if err != nil {
		t.Fatalf("sign Agent token: %v", err)
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)

	openServer := func(t *testing.T) (*App, *httptest.Server, *websocket.Conn) {
		t.Helper()
		restartedStore, openErr := OpenStore(dbPath)
		if openErr != nil {
			t.Fatalf("reopen Master store: %v", openErr)
		}
		app := &App{store: restartedStore, jwtKey: jwtKey}
		server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
		conn, _, dialErr := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
		if dialErr != nil {
			server.Close()
			_ = restartedStore.db.Close()
			t.Fatalf("dial Agent WebSocket: %v", dialErr)
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var welcome map[string]any
		if readErr := conn.ReadJSON(&welcome); readErr != nil {
			conn.Close()
			server.Close()
			_ = restartedStore.db.Close()
			t.Fatalf("read WebSocket welcome: %v", readErr)
		}
		if welcome["type"] != "welcome" {
			conn.Close()
			server.Close()
			_ = restartedStore.db.Close()
			t.Fatalf("welcome type = %#v, want welcome", welcome["type"])
		}
		return app, server, conn
	}

	// First Master process: the command is delivered, but the Agent disconnects
	// before ACK. The command must remain pending in durable storage.
	firstApp, firstServer, firstConn := openServer(t)
	if err := firstConn.WriteJSON(map[string]any{"type": "command.request", "id": "poll-before-restart"}); err != nil {
		t.Fatalf("request command before restart: %v", err)
	}
	var firstDelivery map[string]any
	if err := firstConn.ReadJSON(&firstDelivery); err != nil {
		t.Fatalf("read first command delivery: %v", err)
	}
	firstCommand, ok := firstDelivery["command"].(map[string]any)
	if firstDelivery["type"] != "command.deliver" || !ok || firstCommand["id"] != commandID {
		t.Fatalf("unexpected first delivery: %#v", firstDelivery)
	}
	_ = firstConn.Close()
	firstServer.Close()
	if err := firstApp.store.db.Close(); err != nil {
		t.Fatalf("close Master after unacknowledged delivery: %v", err)
	}

	// Second Master process: reconnect and require the exact same command ID
	// and payload to be delivered again, then ACK it successfully.
	secondApp, secondServer, secondConn := openServer(t)
	defer secondServer.Close()
	defer secondConn.Close()
	defer secondApp.store.db.Close()

	if err := secondConn.WriteJSON(map[string]any{"type": "command.request", "id": "poll-after-restart"}); err != nil {
		t.Fatalf("request command after restart: %v", err)
	}
	var redelivery map[string]any
	if err := secondConn.ReadJSON(&redelivery); err != nil {
		t.Fatalf("read redelivered command: %v", err)
	}
	replayedCommand, ok := redelivery["command"].(map[string]any)
	if redelivery["type"] != "command.deliver" || !ok {
		t.Fatalf("unexpected redelivery envelope: %#v", redelivery)
	}
	if replayedCommand["id"] != commandID || replayedCommand["type"] != "set_smartdns_enabled" || replayedCommand["enabled"] != true {
		t.Fatalf("redelivered command changed across restart: %#v", replayedCommand)
	}

	if err := secondConn.WriteJSON(map[string]any{
		"type": "command.ack",
		"id": commandID,
		"command_status": "success",
		"message": "SmartDNS enabled after Master restart",
	}); err != nil {
		t.Fatalf("send command ACK after restart: %v", err)
	}
	var ack map[string]any
	if err := secondConn.ReadJSON(&ack); err != nil {
		t.Fatalf("read command ACK confirmation: %v", err)
	}
	if ack["type"] != "command.acknowledged" || ack["id"] != commandID || ack["ok"] != true {
		t.Fatalf("unexpected ACK confirmation: %#v", ack)
	}

	settings, err := secondApp.store.GetSettings()
	if err != nil {
		t.Fatalf("read final durable command state: %v", err)
	}
	if settings["agent_command_"+machineCode] != "" {
		t.Fatalf("ACKed command remains pending: %s", settings["agent_command_"+machineCode])
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(settings["agent_command_result_"+machineCode]), &result); err != nil {
		t.Fatalf("decode final command result: %v", err)
	}
	if result["id"] != commandID || result["status"] != "success" {
		t.Fatalf("final durable ACK result = %#v", result)
	}
	if got := settings["smartdns_enabled_"+machineCode]; got != "true" {
		t.Fatalf("persisted SmartDNS desired state = %q, want true", got)
	}
}
