package app

import "time"

// agentStatusIsOnline determines liveness from the authenticated Agent heartbeat.
// It is intentionally independent of container-runtime telemetry.
func agentStatusIsOnline(updatedAt string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, updatedAt)
	if err != nil || t.After(now.Add(30*time.Second)) {
		return false
	}
	return now.Sub(t) <= 90*time.Second
}
