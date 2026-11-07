package app

import (
	"fmt"
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
