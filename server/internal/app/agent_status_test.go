package app

import (
	"testing"
	"time"
)

func TestAgentStatusIsOnlineBoundaries(t *testing.T) {
	now := time.Date(2026, time.October, 24, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		updatedAt string
		want      bool
	}{
		{name: "fresh heartbeat", updatedAt: now.Add(-30 * time.Second).Format(time.RFC3339), want: true},
		{name: "at freshness limit", updatedAt: now.Add(-90 * time.Second).Format(time.RFC3339), want: true},
		{name: "stale heartbeat", updatedAt: now.Add(-91 * time.Second).Format(time.RFC3339), want: false},
		{name: "future timestamp within tolerance", updatedAt: now.Add(30 * time.Second).Format(time.RFC3339), want: true},
		{name: "future timestamp beyond tolerance", updatedAt: now.Add(31 * time.Second).Format(time.RFC3339), want: false},
		{name: "invalid timestamp", updatedAt: "not-a-time", want: false},
		{name: "empty timestamp", updatedAt: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := agentStatusIsOnline(tt.updatedAt, now); got != tt.want {
				t.Fatalf("agentStatusIsOnline(%q) = %v, want %v", tt.updatedAt, got, tt.want)
			}
		})
	}
}
