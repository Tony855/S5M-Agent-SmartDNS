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
