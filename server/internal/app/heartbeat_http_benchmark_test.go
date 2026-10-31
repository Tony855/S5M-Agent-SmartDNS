package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// BenchmarkAgentHTTPHeartbeatEndToEnd measures the complete HTTP heartbeat
// handler path, including request construction, JSON decoding, authentication,
// the shared heartbeat mutex, and SQLite persistence. It is intentionally
// separate from BenchmarkAgentHeartbeatPersistence so the two measurements
// are not mistaken for equivalent workloads.
func BenchmarkAgentHTTPHeartbeatEndToEnd(b *testing.B) {
	for _, fleetSize := range []int{100, 300, 500} {
		b.Run(fmt.Sprintf("nodes_%d", fleetSize), func(b *testing.B) {
			store, err := OpenStore(filepath.Join(b.TempDir(), "heartbeat-http-benchmark.db"))
			if err != nil {
				b.Fatalf("OpenStore: %v", err)
			}
			defer store.db.Close()

			const jwtKey = "heartbeat-benchmark-signing-key"
			const globalToken = "heartbeat-benchmark-global-token"
			app := &App{store: store, jwtKey: []byte(jwtKey)}
			codes := make([]string, fleetSize)
			settings := map[string]string{"agent_token": globalToken}
			tokens := make([]string, fleetSize)
			for i := range codes {
				code := fmt.Sprintf("bench_node_%03d", i)
				secret := fmt.Sprintf("dedicated-secret-%03d", i)
				codes[i] = code
				settings["agent_machine_"+code] = secret
				sum := sha256.Sum256([]byte(secret))
				token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"sub": code, "role": "agent", "ver": hex.EncodeToString(sum[:]),
				}).SignedString(app.jwtKey)
				if err != nil {
					b.Fatalf("sign token for %s: %v", code, err)
				}
				tokens[i] = token
			}
			if err := store.UpdateSettings(settings); err != nil {
				b.Fatalf("seed agent bindings: %v", err)
			}

			status, err := json.Marshal(map[string]any{
				"mihomo_version": "benchmark", "mihomo_healthy": true,
				"upload_total": 12, "download_total": 34,
				"upload_speed": 1, "download_speed": 2,
				"connections":   3,
				"config_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"last_error":    "",
			})
			if err != nil {
				b.Fatalf("marshal heartbeat: %v", err)
			}
			var next atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					idx := next.Add(1) - 1
					node := int(idx % uint64(len(codes)))
					req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat", bytes.NewReader(status))
					req.Header.Set("Authorization", "Bearer "+tokens[node])
					rec := httptest.NewRecorder()
					app.handleAgentHeartbeat(rec, req)
					if rec.Code != http.StatusOK && rec.Code != http.StatusConflict {
						b.Errorf("heartbeat handler status = %d, want 200 or 409; body=%s", rec.Code, rec.Body.String())
						return
					}
				}
			})
		})
	}
}
