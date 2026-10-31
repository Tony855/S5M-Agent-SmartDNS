package app

import (
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// BenchmarkAgentHeartbeatPersistence measures the SQLite persistence portion of
// Agent heartbeat handling for different fleet sizes. It intentionally does not
// include HTTP authentication, JSON decoding, or agentWSMu contention; use it as
// a baseline before changing synchronization in the live handlers.
func BenchmarkAgentHeartbeatPersistence(b *testing.B) {
	for _, fleetSize := range []int{100, 300, 500} {
		b.Run(fmt.Sprintf("nodes_%d", fleetSize), func(b *testing.B) {
			store, err := OpenStore(filepath.Join(b.TempDir(), "heartbeat-benchmark.db"))
			if err != nil {
				b.Fatalf("OpenStore: %v", err)
			}
			defer store.db.Close()

			codes := make([]string, fleetSize)
			initial := make(map[string]string, fleetSize*2)
			for i := range codes {
				codes[i] = fmt.Sprintf("bench_node_%03d", i)
				initial["agent_lastseen_"+codes[i]] = "0"
				initial["agent_status_"+codes[i]] = "{}"
			}
			if err := store.UpdateSettings(initial); err != nil {
				b.Fatalf("seed heartbeat settings: %v", err)
			}

			var next atomic.Uint64
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					idx := next.Add(1) % uint64(len(codes))
					code := codes[idx]
					n := next.Load()
					err := store.UpdateSettings(map[string]string{
						"agent_lastseen_" + code: fmt.Sprintf("%d", n),
						"agent_status_" + code:   fmt.Sprintf("{\"seq\":%d}", n),
					})
					if err != nil {
						b.Errorf("persist heartbeat: %v", err)
						return
					}
				}
			})
		})
	}
}
