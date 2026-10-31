package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentRegisterTokenAuthenticatesAndIsRevokedAfterRotation(t *testing.T) {
	app, code, _ := websocketTestApp(t)
	const dedicatedSecret = "ws-dedicated-secret"

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register",
		strings.NewReader(`{"machine_code":"ws_node_01","secret":"ws-dedicated-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.handleAgentRegister(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("registration status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode registration response: %v", err)
	}
	if strings.TrimSpace(response.Token) == "" {
		t.Fatal("registration succeeded without returning an Agent token")
	}

	authReq := httptest.NewRequest(http.MethodGet, "/api/v1/agent/config", nil)
	authReq.Header.Set("Authorization", "Bearer "+response.Token)
	gotCode, err := app.agentMachineFromRequest(authReq)
	if err != nil || gotCode != code {
		t.Fatalf("registered token authorization = %q, %v; want %q, nil", gotCode, err, code)
	}

	if err := app.store.UpdateSettings(map[string]string{
		"agent_machine_" + code: dedicatedSecret + "-rotated",
	}); err != nil {
		t.Fatalf("rotate dedicated token: %v", err)
	}
	if _, err := app.agentMachineFromRequest(authReq); err == nil {
		t.Fatal("registration token remained valid after dedicated credential rotation")
	}
}
