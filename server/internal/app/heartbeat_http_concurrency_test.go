package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestHTTPAgentHeartbeatConcurrentRequests exercises concurrent authenticated
// heartbeats for one node. Requests may be rejected with 409 when their
// timestamps arrive out of order, but no other status is valid and the final
// persisted record must remain valid JSON.
func TestHTTPAgentHeartbeatConcurrentRequests(t *testing.T) {
	app, code, token := websocketTestApp(t)

	body, err := json.Marshal(map[string]any{
		"mihomo_version": "concurrency-test",
		"mihomo_healthy": true,
		"upload_total":   12,
		"download_total": 34,
		"upload_speed":   1,
		"download_speed": 2,
		"connections":    3,
		"config_sha256":  strings.Repeat("a", 64),
		"last_error":     "",
	})
	if err != nil {
		t.Fatalf("marshal heartbeat: %v", err)
	}

	const requests = 64
	var wg sync.WaitGroup
	errs := make(chan error, requests)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/heartbeat", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			app.handleAgentHeartbeat(rec, req)
			if rec.Code != http.StatusOK && rec.Code != http.StatusConflict {
				errs <- fmt.Errorf("heartbeat status = %d; body=%s", rec.Code, rec.Body.String())
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	settings, err := app.store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	raw := settings["agent_status_"+code]
	if raw == "" {
		t.Fatal("concurrent heartbeats did not persist a status")
	}
	var persisted map[string]any
	if err := json.Unmarshal([]byte(raw), &persisted); err != nil {
		t.Fatalf("persisted heartbeat is invalid JSON: %v", err)
	}
	if persisted["mihomo_version"] != "concurrency-test" {
		t.Fatalf("unexpected persisted heartbeat: %#v", persisted)
	}
	if settings["agent_lastseen_"+code] == "" {
		t.Fatal("concurrent heartbeats did not persist last-seen timestamp")
	}
}
