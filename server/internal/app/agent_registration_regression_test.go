package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentRegisterRejectsWhitespaceOnlyDedicatedToken(t *testing.T) {
	app, code, _ := websocketTestApp(t)
	if err := app.store.UpdateSettings(map[string]string{
		"agent_machine_" + code: " \t\n ",
	}); err != nil {
		t.Fatalf("set whitespace-only dedicated token: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register",
		strings.NewReader(`{"machine_code":"ws_node_01","secret":"placeholder-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.handleAgentRegister(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("registration returned a token for a whitespace-only credential: %s", rec.Body.String())
	}
}

func TestAgentRegisterRejectsGlobalTokenAsDedicatedCredential(t *testing.T) {
	app, _, _ := websocketTestApp(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register",
		strings.NewReader(`{"machine_code":"ws_node_01","secret":"global-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.handleAgentRegister(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("registration returned a token for the global credential: %s", rec.Body.String())
	}
}

func TestAgentRegisterRejectsOversizedUnauthenticatedRequest(t *testing.T) {
	app, _, _ := websocketTestApp(t)
	body := `{"machine_code":"ws_node_01","secret":"` + strings.Repeat("x", 9<<10) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.handleAgentRegister(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}
}


func TestAgentRegisterRateLimitsRepeatedRequestsPerClient(t *testing.T) {
	app, _, _ := websocketTestApp(t)
	for i := 0; i < loginAttemptLimit; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register",
			strings.NewReader(`{"machine_code":"ws_node_01","secret":"wrong-secret"}`))
		req.RemoteAddr = "198.51.100.77:12345"
		rec := httptest.NewRecorder()
		app.handleAgentRegister(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("attempt %d status = %d, want %d; body=%s", i+1, rec.Code, http.StatusForbidden, rec.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/register",
		strings.NewReader(`{"machine_code":"ws_node_01","secret":"wrong-secret"}`))
	req.RemoteAddr = "198.51.100.77:12345"
	rec := httptest.NewRecorder()
	app.handleAgentRegister(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt after limit status = %d, want %d; body=%s", rec.Code, http.StatusTooManyRequests, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("rate-limited response omitted Retry-After")
	}
}
