package app

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Repeatedly exercise the per-node command lock under a bursty 500-node fleet.
// Each round has multiple duplicate deliveries per node and verifies that
// unrelated nodes can progress while same-node operations remain serialized.
func TestAgentWSCommandLocksSustained500NodeBurstSoak(t *testing.T) {
	const (
		nodes = 500
		rounds = 8
		duplicatesPerNode = 4
	)
	app := &App{}
	var violations atomic.Int64
	var completed atomic.Int64

	for round := 0; round < rounds; round++ {
		var active [nodes]atomic.Int32
		start := make(chan struct{})
		var wg sync.WaitGroup
		for node := 0; node < nodes; node++ {
			for duplicate := 0; duplicate < duplicatesPerNode; duplicate++ {
				wg.Add(1)
				go func(node, duplicate int) {
					defer wg.Done()
					<-start
					unlock := app.lockAgentWSCommand(fmt.Sprintf("soak-%d", node))
					defer unlock()
					if active[node].Add(1) != 1 {
						violations.Add(1)
					}
					// Vary the critical-section duration to expose waiter/refcount races.
					time.Sleep(time.Duration((node+duplicate+round)%4+1) * time.Millisecond)
					active[node].Add(-1)
					completed.Add(1)
				}(node, duplicate)
			}
		}
		close(start)
		wg.Wait()
		app.agentWSCommandMu.Lock()
		retained := len(app.agentWSCommandLocks)
		app.agentWSCommandMu.Unlock()
		if retained != 0 {
			t.Fatalf("round %d retained %d idle per-node locks", round+1, retained)
		}
	}
	want := int64(nodes * rounds * duplicatesPerNode)
	if got := completed.Load(); got != want {
		t.Fatalf("completed operations = %d, want %d", got, want)
	}
	if got := violations.Load(); got != 0 {
		t.Fatalf("same-node command overlap violations = %d", got)
	}
}
