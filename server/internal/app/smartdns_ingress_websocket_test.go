package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestAgentWebSocketRejectsPerClientConfigWithoutFreshIngressAttestation(t *testing.T) {
	app, code, token := websocketTestApp(t)
	if err := app.store.SaveNodeConfig(code, "mixed-port: 7890\n"); err != nil {
		t.Fatalf("SaveNodeConfig: %v", err)
	}
	if err := app.store.UpdateSettings(map[string]string{
		"smartdns_routing_config": `{"mode":"per_client","clients":[{"client_cidr":"192.168.50.0/24","proxy_name":"proxy-a"}]}`,
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
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
		t.Fatalf("read welcome: %#v, err=%v", welcome, err)
	}
	if err := conn.WriteJSON(map[string]string{
		"type": "config.request", "id": "missing-ingress-attestation",
		"config_sha256": "", "smartdns_config_sha256": "",
	}); err != nil {
		t.Fatalf("request config: %v", err)
	}
	var response map[string]any
	if err := conn.ReadJSON(&response); err != nil {
		t.Fatalf("read rejected config response: %v", err)
	}
	if response["type"] != "error" || !strings.Contains(response["message"].(string), "DNS ingress") {
		t.Fatalf("per-client config must fail closed without ingress attestation: %#v", response)
	}
}
