package app

import (
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
