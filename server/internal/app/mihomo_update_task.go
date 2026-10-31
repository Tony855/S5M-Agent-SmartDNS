package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

type mihomoUpdateTask struct {
	ID           string
	Status       string
	ResultStatus string
	Version      string
	Message      string
	Error        string
	StartedAt    int64
	FinishedAt   int64
}

func (t mihomoUpdateTask) snapshot() map[string]any {
	return map[string]any{
		"task_id": t.ID, "status": t.Status, "result_status": t.ResultStatus,
		"version": t.Version, "message": t.Message, "error": t.Error,
		"started_at": t.StartedAt, "finished_at": t.FinishedAt,
	}
}

// rememberMihomoUpdateTaskLocked records a task and bounds in-memory history.
// The caller must hold mihomoUpdateMu.
func (a *App) rememberMihomoUpdateTaskLocked(task *mihomoUpdateTask) {
	if a.mihomoUpdateTasks == nil {
		a.mihomoUpdateTasks = make(map[string]*mihomoUpdateTask)
	}
	a.mihomoUpdateTasks[task.ID] = task
	a.mihomoUpdateOrder = append(a.mihomoUpdateOrder, task.ID)
	for len(a.mihomoUpdateOrder) > 10 {
		oldest := a.mihomoUpdateOrder[0]
		a.mihomoUpdateOrder = a.mihomoUpdateOrder[1:]
		delete(a.mihomoUpdateTasks, oldest)
	}
}

// startMihomoUpdateTask acknowledges quickly; the update itself is detached from
// the browser socket and survives browser disconnects for the lifetime of S5M.
func (a *App) startMihomoUpdateTask(client *browserEventClient, requestID string) {
	a.mihomoUpdateMu.Lock()
	if current := a.mihomoUpdateTask; current != nil && (current.Status == "queued" || current.Status == "running") {
		snapshot := current.snapshot()
		a.mihomoUpdateMu.Unlock()
		_ = client.writeJSON(map[string]any{"type": "request.result", "request_id": requestID, "ok": true, "data": snapshot})
		return
	}
	id := fmt.Sprintf("mihomo-%x", time.Now().UnixNano())
	task := &mihomoUpdateTask{ID: id, Status: "running", StartedAt: time.Now().Unix()}
	a.mihomoUpdateTask = task
	if a.mihomoUpdateTasks == nil {
		a.mihomoUpdateTasks = make(map[string]*mihomoUpdateTask)
	}
	a.rememberMihomoUpdateTaskLocked(task)
	startedSnapshot := task.snapshot()
	a.mihomoUpdateMu.Unlock()
	if err := client.writeJSON(map[string]any{"type": "request.result", "request_id": requestID, "ok": true, "data": startedSnapshot}); err != nil {
		fmt.Printf("browser_ws: mihomo update start ACK failed task_id=%q: %v\n", id, err)
	}
	a.publishBrowserEvent(map[string]any{"type": "mihomo.update.started", "task_id": id, "at": task.StartedAt})
	go func() {
		rec := httptest.NewRecorder()
		a.handleUpdateMihomo(rec, httptest.NewRequest(http.MethodPost, "/api/v1/mihomo/update", nil))
		var payload map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			payload = map[string]any{"error": "更新程序返回了无效 JSON"}
		}
		a.mihomoUpdateMu.Lock()
		if a.mihomoUpdateTask == nil || a.mihomoUpdateTask.ID != id {
			a.mihomoUpdateMu.Unlock()
			return
		}
		current := a.mihomoUpdateTask
		current.FinishedAt = time.Now().Unix()
		if rec.Code >= 200 && rec.Code < 300 {
			current.Status = "completed"
			current.ResultStatus, _ = payload["status"].(string)
			current.Version, _ = payload["version"].(string)
			current.Message, _ = payload["message"].(string)
		} else {
			current.Status = "failed"
			current.Error, _ = payload["error"].(string)
			if strings.TrimSpace(current.Error) == "" {
				current.Error = "主控 Mihomo 更新失败"
			}
		}
		snapshot := current.snapshot()
		status := current.Status
		a.mihomoUpdateMu.Unlock()
		eventType := "mihomo.update.completed"
		if status == "failed" {
			eventType = "mihomo.update.failed"
		}
		snapshot["type"] = eventType
		a.publishBrowserEvent(snapshot)
	}()
}

func (a *App) handleMihomoUpdateTaskStatus(client *browserEventClient, requestID, taskID string) {
	taskID = strings.TrimSpace(taskID)
	a.mihomoUpdateMu.Lock()
	task := a.mihomoUpdateTasks[taskID]
	if task == nil || taskID == "" {
		a.mihomoUpdateMu.Unlock()
		_ = client.writeJSON(map[string]any{"type": "request.result", "request_id": requestID, "ok": false, "error": "更新任务不存在或已过期"})
		return
	}
	snapshot := task.snapshot()
	a.mihomoUpdateMu.Unlock()
	_ = client.writeJSON(map[string]any{"type": "request.result", "request_id": requestID, "ok": true, "data": snapshot})
}

func (a *App) handleLatestMihomoUpdateTaskStatus(client *browserEventClient, requestID string) {
	a.mihomoUpdateMu.Lock()
	if len(a.mihomoUpdateOrder) == 0 {
		a.mihomoUpdateMu.Unlock()
		_ = client.writeJSON(map[string]any{"type": "request.result", "request_id": requestID, "ok": true, "data": nil})
		return
	}
	id := a.mihomoUpdateOrder[len(a.mihomoUpdateOrder)-1]
	task := a.mihomoUpdateTasks[id]
	if task == nil {
		a.mihomoUpdateMu.Unlock()
		_ = client.writeJSON(map[string]any{"type": "request.result", "request_id": requestID, "ok": false, "error": "最近更新任务记录不可用"})
		return
	}
	snapshot := task.snapshot()
	a.mihomoUpdateMu.Unlock()
	_ = client.writeJSON(map[string]any{"type": "request.result", "request_id": requestID, "ok": true, "data": snapshot})
}
