package app

import (
	"encoding/json"
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


func TestQueueAgentSmartDNSConfigAlsoRequiresIngressReadinessForPerClientMode(t *testing.T) {
	app, code, _ := websocketTestApp(t)
	if err := app.store.UpdateSettings(map[string]string{
		"smartdns_routing_config": `{"mode":"per_client","clients":[{"client_cidr":"192.168.50.0/24","proxy_name":"proxy-a"}]}`,
	}); err != nil {
		t.Fatalf("set per-client routing mode: %v", err)
	}
	if err := app.queueAgentSmartDNSConfig(code, "bind 127.0.0.1:6053\\nbind-tcp 127.0.0.1:6053"); err == nil ||
		!strings.Contains(err.Error(), "DNS ingress") {
		t.Fatalf("direct SmartDNS apply must fail closed without fresh ingress attestation, got %v", err)
	}
}


func TestAgentWebSocketRecoversPerClientConfigWhenSmartDNSRuntimeIsUnhealthy(t *testing.T) {
	app, code, token := websocketTestApp(t)
	if err := app.store.SaveNodeConfig(code, "mode: rule\nproxies:\n  - name: proxy-a\n    type: socks5\n    server: 192.0.2.10\n    port: 1080\nrules:\n  - MATCH,DIRECT\n"); err != nil {
		t.Fatalf("SaveNodeConfig: %v", err)
	}
	proxy := &Proxy{
		Name: "proxy-a", Type: "socks5", Server: "192.0.2.10", Port: 1080,
		MachineCode: code, Enabled: true, Extra: map[string]any{},
	}
	if err := app.store.CreateProxy(proxy); err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}
	now := time.Now()
	status := map[string]any{
		"dns_ingress_contract_version": float64(smartDNSIngressReadinessContractVersion),
		"dns_ingress_ready": false,
		"dns_ingress_source_ip_preserved": true,
		"dns_ingress_firewall_ready": true,
		"dns_ingress_firewall_persistent": true,
		"dns_ingress_udp_ready": true,
		"dns_ingress_tcp_ready": true,
		"dns_ingress_interface": "eth0",
		"dns_ingress_client_cidrs": []string{"192.168.50.0/24"},
		"dns_ingress_ipv4_ready": true,
		"dns_ingress_ipv4_address": "172.31.0.10",
		"dns_ingress_ipv6_ready": false,
		"dns_ingress_ipv6_address": "",
		"dns_ingress_smartdns_ipv4_bound": false,
		"dns_ingress_smartdns_ipv4_bind_address": "",
		"dns_ingress_smartdns_listener_ready": false,
		"smartdns_available": true,
		"smartdns_running": true,
		"smartdns_dns_healthy": false,
		"received_at": float64(now.Unix()),
	}
	statusJSON, err := json.Marshal(status)
	if err != nil { t.Fatal(err) }
	if err := app.store.UpdateSettings(map[string]string{
		"smartdns_routing_config": `{"mode":"per_client","clients":[{"client_cidr":"192.168.50.0/24","proxy_name":"proxy-a","listen_port":16000}]}`,
		"smartdns_enabled_" + code: "true",
		"agent_lastseen_" + code: strconv.FormatInt(now.Unix(), 10),
		"agent_status_" + code: string(statusJSON),
	}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(app.handleAgentWebSocket))
	defer server.Close()
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil { t.Fatalf("dial authenticated WebSocket: %v", err) }
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var welcome map[string]any
	if err := conn.ReadJSON(&welcome); err != nil || welcome["type"] != "welcome" {
		t.Fatalf("read welcome: %#v, err=%v", welcome, err)
	}
	if err := conn.WriteJSON(map[string]string{
		"type": "config.request", "id": "recover-per-client",
		"config_sha256": "", "smartdns_config_sha256": "",
	}); err != nil { t.Fatalf("request recovery config: %v", err) }
	var response map[string]any
	if err := conn.ReadJSON(&response); err != nil { t.Fatalf("read recovery config: %v", err) }
	if response["type"] != "config.sync" {
		t.Fatalf("unhealthy SmartDNS must receive a contract-bound recovery sync, got %#v", response)
	}
	contract, ok := response["ingress_contract"].(map[string]any)
	if !ok || contract["ready"] != true || contract["ipv4_address"] != "172.31.0.10" {
		t.Fatalf("recovery sync is missing the host-provisioned ingress contract: %#v", response["ingress_contract"])
	}
	mappings, ok := contract["mappings"].([]any)
	if !ok || len(mappings) != 1 {
		t.Fatalf("recovery contract must preserve the exact client-to-listener mapping: %#v", contract["mappings"])
	}
	smartDNSYAML, _ := response["smartdns_yaml"].(string)
	if !strings.Contains(smartDNSYAML, "bind 172.31.0.10:6055") ||
		!strings.Contains(smartDNSYAML, "group-match -client-ip 192.168.50.0/24") {
		t.Fatalf("recovery sync did not include the exact attested SmartDNS runtime: %s", smartDNSYAML)
	}
}
