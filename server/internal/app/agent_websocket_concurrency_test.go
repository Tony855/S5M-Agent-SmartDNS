package app

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAgentWSCommandLocksArePerMachine(t *testing.T) {
	app := &App{}

	unlockA := app.lockAgentWSCommand("node-a")
	nodeBAcquired := make(chan struct{})
	go func() {
		unlock := app.lockAgentWSCommand("node-b")
		close(nodeBAcquired)
		unlock()
	}()
	select {
	case <-nodeBAcquired:
		// A different node must not wait for node-a's command.
	case <-time.After(time.Second):
		unlockA()
		t.Fatal("node-b command was blocked by node-a")
	}

	nodeASecondAcquired := make(chan struct{})
	go func() {
		unlock := app.lockAgentWSCommand("node-a")
		close(nodeASecondAcquired)
		unlock()
	}()
	select {
	case <-nodeASecondAcquired:
		unlockA()
		t.Fatal("two commands for the same node ran concurrently")
	case <-time.After(30 * time.Millisecond):
		// Same-node serialization is expected.
	}

	unlockA()
	select {
	case <-nodeASecondAcquired:
	case <-time.After(time.Second):
		t.Fatal("queued same-node command did not proceed after lock release")
	}
}

func TestAgentWSCommandLocksScaleAcrossNodes(t *testing.T) {
	app := &App{}
	for _, count := range []int{100, 300, 500} {
		acquired := make(chan func(), count)
		for i := 0; i < count; i++ {
			machineCode := fmt.Sprintf("node-%d-%d", count, i)
			go func(code string) {
				acquired <- app.lockAgentWSCommand(code)
			}(machineCode)
		}
		unlocks := make([]func(), 0, count)
		deadline := time.After(5 * time.Second)
		for len(unlocks) < count {
			select {
			case unlock := <-acquired:
				unlocks = append(unlocks, unlock)
			case <-deadline:
				for _, unlock := range unlocks {
					unlock()
				}
				t.Fatalf("%d distinct node locks did not acquire concurrently; acquired %d", count, len(unlocks))
			}
		}
		for _, unlock := range unlocks {
			unlock()
		}
	}
}


func TestAgentWSCommandLocksAreEvictedAfterUse(t *testing.T) {
	app := &App{}
	for i := 0; i < 1000; i++ {
		code := fmt.Sprintf("transient-node-%d", i)
		unlock := app.lockAgentWSCommand(code)
		unlock()
	}
	app.agentWSCommandMu.Lock()
	defer app.agentWSCommandMu.Unlock()
	if got := len(app.agentWSCommandLocks); got != 0 {
		t.Fatalf("idle per-agent lock map retained %d entries after 1000 distinct nodes; want 0", got)
	}
}

func TestAgentWSCommandLockWaitersKeepSharedLockUntilReleased(t *testing.T) {
	app := &App{}
	unlockFirst := app.lockAgentWSCommand("same-node")
	waiting := make(chan func(), 1)
	go func() { waiting <- app.lockAgentWSCommand("same-node") }()
	deadline := time.Now().Add(time.Second)
	for {
		app.agentWSCommandMu.Lock()
		lock := app.agentWSCommandLocks["same-node"]
		refs := 0
		if lock != nil { refs = lock.refs }
		app.agentWSCommandMu.Unlock()
		if refs == 2 { break }
		if time.Now().After(deadline) {
			unlockFirst()
			t.Fatal("waiting command did not register its lock reference")
		}
		time.Sleep(time.Millisecond)
	}
	unlockFirst()
	unlockSecond := <-waiting
	unlockSecond()
	app.agentWSCommandMu.Lock()
	defer app.agentWSCommandMu.Unlock()
	if _, ok := app.agentWSCommandLocks["same-node"]; ok {
		t.Fatal("lock entry remained after holder and waiter released it")
	}
}


func TestAgentWSCommandLocksPreservePerNodeIsolationAt500Nodes(t *testing.T) {
	const nodes = 500
	app := &App{}
	var active [nodes]atomic.Int32
	var violations atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for node := 0; node < nodes; node++ {
		for duplicate := 0; duplicate < 2; duplicate++ {
			wg.Add(1)
			go func(node int) {
				defer wg.Done()
				<-start
				unlock := app.lockAgentWSCommand(fmt.Sprintf("soak-node-%d", node))
				defer unlock()
				if active[node].Add(1) != 1 {
					violations.Add(1)
				}
				time.Sleep(time.Millisecond)
				active[node].Add(-1)
			}(node)
		}
	}
	close(start)
	wg.Wait()
	if got := violations.Load(); got != 0 {
		t.Fatalf("same-node commands overlapped %d times across %d nodes", got, nodes)
	}
	app.agentWSCommandMu.Lock()
	defer app.agentWSCommandMu.Unlock()
	if got := len(app.agentWSCommandLocks); got != 0 {
		t.Fatalf("500-node command soak retained %d idle locks", got)
	}
}
