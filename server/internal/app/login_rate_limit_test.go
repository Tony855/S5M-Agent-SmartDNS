package app

import (
	"fmt"
	"net/http"
	"strings"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestLoginAttemptLimiterBoundsAttemptsAndResets(t *testing.T) {
	var limiter loginAttemptLimiter
	now := time.Now()
	for i := 0; i < loginAttemptLimit; i++ {
		if ok, _ := limiter.allow("192.0.2.10", now); !ok {
			t.Fatalf("attempt %d unexpectedly rate-limited", i+1)
		}
	}
	if ok, retry := limiter.allow("192.0.2.10", now); ok || retry <= 0 {
		t.Fatalf("attempt beyond limit allowed=%v retry=%v", ok, retry)
	}
	if ok, _ := limiter.allow("192.0.2.11", now); !ok {
		t.Fatal("one client's attempts must not block another client")
	}
	limiter.reset("192.0.2.10")
	if ok, _ := limiter.allow("192.0.2.10", now); !ok {
		t.Fatal("successful authentication reset should clear the client's window")
	}
}

func TestLoginAttemptLimiterExpiresWindowAndBoundsKeys(t *testing.T) {
	var limiter loginAttemptLimiter
	now := time.Now()
	for i := 0; i < loginAttemptLimit; i++ { limiter.allow("198.51.100.1", now) }
	if ok, _ := limiter.allow("198.51.100.1", now.Add(loginAttemptWindow)); !ok {
		t.Fatal("expired login window was not reset")
	}
	for i := 0; i < loginAttemptMaxKeys+20; i++ {
		limiter.allow(fmt.Sprintf("192.0.2.%d", i), now)
	}
	if len(limiter.entries) > loginAttemptMaxKeys {
		t.Fatalf("limiter retained %d keys, max %d", len(limiter.entries), loginAttemptMaxKeys)
	}
}

func TestLoginClientKeyTrustsForwardedIPOnlyFromLoopbackProxy(t *testing.T) {
	req := httptest.NewRequest("POST", "/login", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Real-IP", "203.0.113.9")
	if got := loginClientKey(req); got != "203.0.113.9" {
		t.Fatalf("trusted proxy client key = %q", got)
	}
	req.RemoteAddr = "198.51.100.7:54321"
	req.Header.Set("X-Real-IP", "203.0.113.9")
	if got := loginClientKey(req); got != "198.51.100.7" {
		t.Fatalf("untrusted forwarded header overrode direct peer: %q", got)
	}
}


func TestDummyLoginPasswordHashIsValid(t *testing.T) {
	if len(dummyLoginPasswordHash) == 0 {
		t.Fatal("dummy bcrypt hash is empty")
	}
	if err := bcrypt.CompareHashAndPassword(dummyLoginPasswordHash, []byte("s5m-invalid-login-dummy-password")); err != nil {
		t.Fatalf("dummy bcrypt hash is invalid: %v", err)
	}
}


func TestLoginRejectsOversizedRequestBody(t *testing.T) {
	app := &App{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(strings.Repeat("x", (8<<10)+1)))
	req.RemoteAddr = "192.0.2.99:12345"
	rec := httptest.NewRecorder()
	app.handleLogin(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}
}
