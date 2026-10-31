package app

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestAgentMachineFromRequestRejectsWhitespaceOnlyDedicatedToken(t *testing.T) {
	app, code, _ := websocketTestApp(t)
	const blankToken = " \t\n "
	if err := app.store.UpdateSettings(map[string]string{
		"agent_machine_" + code: blankToken,
	}); err != nil {
		t.Fatalf("set blank dedicated token: %v", err)
	}

	version := fmt.Sprintf("%x", sha256.Sum256([]byte(blankToken)))
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": code, "role": "agent", "ver": version,
	}).SignedString(app.jwtKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/config", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	if _, err := app.agentMachineFromRequest(req); err == nil {
		t.Fatal("whitespace-only dedicated token must not authorize an Agent")
	}
}
