package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// BenchmarkHTTPAgentHeartbeatHandler measures the complete HTTP heartbeat handler
// for concurrent requests from one authenticated Agent. Unlike the persistence-only
// benchmark, this includes JSON decoding, token and machine-binding validation,
// the global heartbeat lock, and SQLite persistence. It is not a multi-Agent fleet
// benchmark; the persistence benchmark remains responsible for varying fleet size.
func BenchmarkHTTPAgentHeartbeatHandler(b *testing.B) {
	store, err := OpenStore(filepath.Join(b.TempDir(), "http-heartbeat-benchmark.db"))
	if err != nil {
		b.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const code = "bench_http_node"
	const secret = "bench-http-dedicated-secret"
	app := &App{store: store, jwtKey: []byte("benchmark-signing-key")}
	if err := store.UpdateSettings(map[string]string{
		"agent_token":           "global-secret",
		"agent_machine_" + code: secret,
	}); err != nil {
		b.Fatalf("seed Agent binding: %v", err)
	}
	sum := sha256.Sum256([]byte(secret))
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  code,
		"role": "agent",
		"ver":  hex.EncodeToString(sum[:]),
	}).SignedString(app.jwtKey)
	if err != nil {
		b.Fatalf("sign benchmark token: %v", err)
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
		b.Fatalf("marshal heartbeat: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat", strings.NewReader(string(body)))
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			app.handleAgentHeartbeat(rec, req)
			if rec.Code != http.StatusOK {
				b.Errorf("heartbeat status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
				return
			}
		}
	})
}
