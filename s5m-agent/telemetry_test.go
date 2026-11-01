package main

import (
	"testing"
	"time"
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
