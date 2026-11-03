package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestMihomoTelemetryStateSnapshotIsConsistent(t *testing.T) {
	state := &mihomoTelemetryState{}
	state.update(func(value *mihomoTelemetrySnapshot) {
		value.UploadSpeed = 1200
		value.DownloadSpeed = 3400
		value.Connections = 9
		value.UploadTotal = 10000
		value.DownloadTotal = 20000
	})
	got := state.snapshot()
	if got.UploadSpeed != 1200 || got.DownloadSpeed != 3400 || got.Connections != 9 {
		t.Fatalf("unexpected telemetry snapshot: %+v", got)
	}
	if got.UpdatedAt.IsZero() || time.Since(got.UpdatedAt) > time.Second {
		t.Fatalf("telemetry snapshot timestamp is missing or stale: %v", got.UpdatedAt)
	}
}

func TestTelemetryIntervalsStayWithinInteractiveDefaults(t *testing.T) {
	if defaultTelemetryPushInterval != 200*time.Millisecond {
		t.Fatalf("push interval = %v, want 200ms", defaultTelemetryPushInterval)
	}
	if defaultConnectionsInterval != 500*time.Millisecond {
		t.Fatalf("connections interval = %v, want 500ms", defaultConnectionsInterval)
	}
}

func TestTelemetryPublisherSendsSupportedHighFrequencyFrames(t *testing.T) {
	t.Setenv("MIHOMO_HOME", t.TempDir())

	previousState := agentMihomoTelemetry
	state := &mihomoTelemetryState{}
	sampledAt := time.Now()
	state.update(func(value *mihomoTelemetrySnapshot) {
		value.UploadSpeed = 1234
		value.DownloadSpeed = 5678
		value.Connections = 4
		value.UploadTotal = 10000
		value.DownloadTotal = 20000
		value.SampledAt = sampledAt
	})
	agentMihomoTelemetry = state
	defer func() { agentMihomoTelemetry = previousState }()

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	received := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var payload map[string]any
		if err := conn.ReadJSON(&payload); err == nil {
			received <- payload
		}
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runAgentTelemetryPublisher(ctx, conn)
	}()

	select {
	case payload := <-received:
		if payload["type"] != "telemetry" {
			t.Fatalf("frame type = %#v, want telemetry", payload["type"])
		}
		status, ok := payload["status"].(map[string]any)
		if !ok {
			t.Fatalf("telemetry status has unexpected type: %#v", payload["status"])
		}
		if status["upload_speed"] != float64(1234) || status["download_speed"] != float64(5678) {
			t.Fatalf("telemetry speeds were not sent: %#v", status)
		}
		if status["connections"] != float64(4) || status["upload_total"] != float64(10000) || status["download_total"] != float64(20000) {
			t.Fatalf("telemetry counters were not sent: %#v", status)
		}
		if status["telemetry_stale"] != false || status["telemetry_sampled_at_ms"] != float64(sampledAt.UnixMilli()) {
			t.Fatalf("telemetry freshness metadata was not sent: %#v", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("publisher did not send a telemetry frame")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("telemetry publisher did not stop after context cancellation")
	}
}

func TestCalculateCounterRateUsesElapsedSampleInterval(t *testing.T) {
	got := calculateCounterRate(6000, 1000, 500*time.Millisecond)
	if got != 10000 {
		t.Fatalf("counter rate = %v, want 10000 B/s", got)
	}
}

func TestCalculateCounterRateHandlesResetAndInvalidIntervals(t *testing.T) {
	if got := calculateCounterRate(100, 200, 500*time.Millisecond); got != 0 {
		t.Fatalf("counter reset rate = %v, want 0", got)
	}
	if got := calculateCounterRate(200, 100, 0); got != 0 {
		t.Fatalf("zero interval rate = %v, want 0", got)
	}
}

func TestTelemetryErrorPreservesLastSuccessfulSample(t *testing.T) {
	state := &mihomoTelemetryState{}
	sampledAt := time.Now().Add(-time.Second)
	state.update(func(value *mihomoTelemetrySnapshot) {
		value.UploadSpeed = 1250
		value.DownloadSpeed = 2500
		value.Connections = 7
		value.UploadTotal = 10000
		value.DownloadTotal = 20000
		value.SampledAt = sampledAt
	})

	recordMihomoTelemetryError(state, "Mihomo /connections 请求失败: connection refused")
	got := state.snapshot()
	if got.UploadSpeed != 1250 || got.DownloadSpeed != 2500 || got.Connections != 7 {
		t.Fatalf("temporary API failure erased last successful metrics: %+v", got)
	}
	if got.UploadTotal != 10000 || got.DownloadTotal != 20000 {
		t.Fatalf("temporary API failure erased cumulative counters: %+v", got)
	}
	if got.SampledAt != sampledAt {
		t.Fatalf("temporary API failure changed sample time: got %v want %v", got.SampledAt, sampledAt)
	}
	if got.ConnectionsError == "" || got.TrafficError == "" {
		t.Fatalf("expected both telemetry diagnostics to be populated: %+v", got)
	}
}

func TestMihomoTelemetryStaleThreshold(t *testing.T) {
	now := time.Now()
	if !mihomoTelemetryIsStale(time.Time{}, now) {
		t.Fatal("missing telemetry sample must be stale")
	}
	if mihomoTelemetryIsStale(now.Add(-time.Second), now) {
		t.Fatal("recent telemetry sample must not be stale")
	}
	if !mihomoTelemetryIsStale(now.Add(-2*time.Second), now) {
		t.Fatal("sample older than the stale threshold must be stale")
	}
}

func TestMihomoAPISecretOrLoadRetriesAfterFailureAndCachesSuccess(t *testing.T) {
	attempts := 0
	load := func() (string, error) {
		attempts++
		if attempts == 1 {
			return "", fmt.Errorf("config not ready")
		}
		return "rotated-secret", nil
	}

	if _, err := mihomoAPISecretOrLoad("", load); err == nil {
		t.Fatal("first secret load should fail while config is unavailable")
	}
	secret, err := mihomoAPISecretOrLoad("", load)
	if err != nil {
		t.Fatalf("second secret load should recover: %v", err)
	}
	if secret != "rotated-secret" {
		t.Fatalf("loaded secret = %q, want rotated-secret", secret)
	}
	secret, err = mihomoAPISecretOrLoad(secret, load)
	if err != nil {
		t.Fatalf("cached secret should be reused: %v", err)
	}
	if secret != "rotated-secret" || attempts != 2 {
		t.Fatalf("secret=%q attempts=%d, want cached secret and exactly 2 loads", secret, attempts)
	}
}

func TestMihomoAPISecretValidationFailsClosed(t *testing.T) {
	if _, err := mihomoAPISecretFromConfig(map[string]any{}); err == nil {
		t.Fatal("missing Mihomo API secret must be rejected")
	}
	secret, err := mihomoAPISecretFromConfig(map[string]any{"secret": "  local-secret  "})
	if err != nil {
		t.Fatalf("valid Mihomo API secret was rejected: %v", err)
	}
	if secret != "local-secret" {
		t.Fatalf("secret was not normalized: got %q", secret)
	}
}

func TestApplyMihomoTelemetrySnapshotKeepsCachedValuesAndFreshness(t *testing.T) {
	now := time.Now()
	sampledAt := now.Add(-time.Second)
	status := map[string]any{}
	snapshot := mihomoTelemetrySnapshot{
		UploadSpeed: 100,
		DownloadSpeed: 200,
		Connections: 3,
		UploadTotal: 400,
		DownloadTotal: 500,
		SampledAt: sampledAt,
	}
	applyMihomoTelemetrySnapshot(status, snapshot, now)
	if status["upload_speed"] != float64(100) || status["connections"] != 3 {
		t.Fatalf("cached metrics were not copied to heartbeat status: %#v", status)
	}
	if status["telemetry_stale"] != false {
		t.Fatalf("recent sample marked stale: %#v", status["telemetry_stale"])
	}
	if status["telemetry_sampled_at_ms"] != sampledAt.UnixMilli() {
		t.Fatalf("sample timestamp mismatch: %#v", status["telemetry_sampled_at_ms"])
	}
	applyMihomoTelemetrySnapshot(status, snapshot, now.Add(2*time.Second))
	if status["telemetry_stale"] != true {
		t.Fatalf("expired sample not marked stale: %#v", status["telemetry_stale"])
	}
}


func TestMihomoTelemetryStatusIsSharedByHeartbeatAndPublisher(t *testing.T) {
	now := time.Now()
	sampledAt := now.Add(-250 * time.Millisecond)
	snapshot := mihomoTelemetrySnapshot{
		UploadSpeed: 11, DownloadSpeed: 22, Connections: 3,
		UploadTotal: 44, DownloadTotal: 55,
		TrafficError: "traffic warning", ConnectionsError: "connection warning",
		SampledAt: sampledAt,
	}
	streamStatus := mihomoTelemetryStatus(snapshot, now)
	heartbeatStatus := map[string]any{}
	applyMihomoTelemetrySnapshot(heartbeatStatus, snapshot, now)
	for key, want := range streamStatus {
		if got := heartbeatStatus[key]; got != want {
			t.Fatalf("heartbeat field %q = %#v, stream field = %#v", key, got, want)
		}
	}
	if len(heartbeatStatus) != len(streamStatus) {
		t.Fatalf("heartbeat schema has %d fields, stream schema has %d", len(heartbeatStatus), len(streamStatus))
	}
}
