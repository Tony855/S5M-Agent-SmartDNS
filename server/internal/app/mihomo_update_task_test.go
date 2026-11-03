package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestMihomoUpdateTaskStatusCanBeRecoveredAfterReconnect(t *testing.T) {
	task := &mihomoUpdateTask{ID: "mihomo-test-1", Status: "completed", ResultStatus: "updated", Version: "v1.20.0", Message: "updated", StartedAt: 100, FinishedAt: 110}
	app := &App{mihomoUpdateTask: task, mihomoUpdateTasks: map[string]*mihomoUpdateTask{task.ID: task}, mihomoUpdateOrder: []string{task.ID}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := browserEventsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		app.handleMihomoUpdateTaskStatus(&browserEventClient{conn: conn, username: "admin"}, "rpc-1", "mihomo-test-1")
	}))
	defer server.Close()
	header := http.Header{}
	header.Set("Origin", server.URL)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var reply map[string]any
	if err := conn.ReadJSON(&reply); err != nil {
		t.Fatal(err)
	}
	if reply["type"] != "request.result" || reply["request_id"] != "rpc-1" || reply["ok"] != true {
		t.Fatalf("unexpected reply: %#v", reply)
	}
	data, ok := reply["data"].(map[string]any)
	if !ok {
		t.Fatalf("missing task data: %#v", reply)
	}
	if data["task_id"] != "mihomo-test-1" || data["status"] != "completed" || data["version"] != "v1.20.0" {
		t.Fatalf("task recovery data mismatch: %#v", data)
	}
}

func TestMihomoUpdateTaskStatusRejectsUnknownTask(t *testing.T) {
	app := &App{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := browserEventsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		app.handleMihomoUpdateTaskStatus(&browserEventClient{conn: conn, username: "admin"}, "rpc-2", "missing")
	}))
	defer server.Close()
	header := http.Header{}
	header.Set("Origin", server.URL)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+server.URL[len("http"):], header)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var reply map[string]any
	if err := conn.ReadJSON(&reply); err != nil {
		t.Fatal(err)
	}
	if reply["ok"] != false || reply["error"] != "更新任务不存在或已过期" {
		t.Fatalf("unexpected unknown-task response: %#v", reply)
	}
}

func TestMihomoUpdateTaskSnapshotIncludesTerminalMetadata(t *testing.T) {
	task := mihomoUpdateTask{ID: "task-1", Status: "failed", Error: "rollback completed", StartedAt: 1, FinishedAt: 2}
	got := task.snapshot()
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["status"] != "failed" || decoded["error"] != "rollback completed" || decoded["finished_at"] != float64(2) {
		t.Fatalf("snapshot lost terminal metadata: %#v", decoded)
	}
}

func TestMihomoUpdateTaskHistoryKeepsLatestTen(t *testing.T) {
	app := &App{}
	app.mihomoUpdateMu.Lock()
	for i := 0; i < 12; i++ {
		id := fmt.Sprintf("task-%d", i)
		app.rememberMihomoUpdateTaskLocked(&mihomoUpdateTask{ID: id, Status: "completed"})
	}
	app.mihomoUpdateMu.Unlock()

	if len(app.mihomoUpdateTasks) != 10 || app.mihomoUpdateTasks["task-0"] != nil || app.mihomoUpdateTasks["task-11"] == nil {
		t.Fatalf("unexpected bounded task history: %#v", app.mihomoUpdateOrder)
	}
}
