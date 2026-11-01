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
