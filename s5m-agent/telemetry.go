package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

const (
	defaultTelemetryPushInterval = 200 * time.Millisecond
	defaultConnectionsInterval   = 500 * time.Millisecond
)

type mihomoTelemetrySnapshot struct {
	UploadSpeed      float64   `json:"upload_speed"`
	DownloadSpeed    float64   `json:"download_speed"`
	Connections      int       `json:"connections"`
	UploadTotal      uint64    `json:"upload_total"`
	DownloadTotal    uint64    `json:"download_total"`
	TrafficError     string    `json:"traffic_error"`
	ConnectionsError string    `json:"connections_error"`
	UpdatedAt        time.Time `json:"-"`
}

type mihomoTelemetryState struct {
	mu    sync.RWMutex
	value mihomoTelemetrySnapshot
}

func (s *mihomoTelemetryState) update(fn func(*mihomoTelemetrySnapshot)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.value)
	s.value.UpdatedAt = time.Now()
}

func (s *mihomoTelemetryState) snapshot() mihomoTelemetrySnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.value
}

func mihomoControllerSecret() (string, error) {
	data, err := os.ReadFile(mihomoConfigPath())
	if err != nil {
		return "", fmt.Errorf("读取 Mihomo 配置失败: %w", err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("解析 Mihomo 配置失败: %w", err)
	}
	secret, _ := cfg["secret"].(string)
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return "", fmt.Errorf("Mihomo 配置缺少 API secret，拒绝发起未鉴权统计请求")
	}
	return secret, nil
}

func newMihomoAPIRequest(ctx context.Context, path, secret string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:8088"+path, nil)
	if err != nil {
		return nil, err
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	return req, nil
}

// streamMihomoTraffic consumes Mihomo's streaming /traffic endpoint and reconnects
// with bounded backoff. It never creates one HTTP request per display refresh.
func streamMihomoTraffic(ctx context.Context, state *mihomoTelemetryState, secret string) {
	backoff := time.Second
	client := &http.Client{}
	for ctx.Err() == nil {
		req, err := newMihomoAPIRequest(ctx, "/traffic", secret)
		if err != nil {
			state.update(func(v *mihomoTelemetrySnapshot) { v.UploadSpeed = 0; v.DownloadSpeed = 0; v.TrafficError = safeMihomoValidationDiagnostic([]byte(err.Error())) })
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			state.update(func(v *mihomoTelemetrySnapshot) { v.UploadSpeed = 0; v.DownloadSpeed = 0; v.TrafficError = safeMihomoValidationDiagnostic([]byte("Mihomo /traffic 连接失败: " + err.Error())) })
			if !waitTelemetryBackoff(ctx, backoff) { return }
			backoff = min(backoff*2, 15*time.Second)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			state.update(func(v *mihomoTelemetrySnapshot) { v.UploadSpeed = 0; v.DownloadSpeed = 0; v.TrafficError = fmt.Sprintf("Mihomo /traffic 返回 HTTP %d", resp.StatusCode) })
			if !waitTelemetryBackoff(ctx, backoff) { return }
			backoff = min(backoff*2, 15*time.Second)
			continue
		}
		backoff = time.Second
		decoder := json.NewDecoder(resp.Body)
		for ctx.Err() == nil {
			var sample struct {
				Up   float64 `json:"up"`
				Down float64 `json:"down"`
			}
			if err := decoder.Decode(&sample); err != nil {
				break
			}
			if math.IsNaN(sample.Up) || math.IsNaN(sample.Down) || math.IsInf(sample.Up, 0) || math.IsInf(sample.Down, 0) || sample.Up < 0 || sample.Down < 0 {
				state.update(func(v *mihomoTelemetrySnapshot) { v.UploadSpeed = 0; v.DownloadSpeed = 0; v.TrafficError = "Mihomo /traffic 返回无效速率" })
				continue
			}
			state.update(func(v *mihomoTelemetrySnapshot) {
				v.UploadSpeed = sample.Up
				v.DownloadSpeed = sample.Down
				v.TrafficError = ""
			})
		}
		_ = resp.Body.Close()
		if ctx.Err() != nil { return }
		state.update(func(v *mihomoTelemetrySnapshot) { v.UploadSpeed = 0; v.DownloadSpeed = 0; v.TrafficError = "Mihomo /traffic 流已断开，正在重连" })
		if !waitTelemetryBackoff(ctx, backoff) { return }
		backoff = min(backoff*2, 15*time.Second)
	}
}

func waitTelemetryBackoff(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func pollMihomoConnections(ctx context.Context, state *mihomoTelemetryState, secret string) {
	ticker := time.NewTicker(defaultConnectionsInterval)
	defer ticker.Stop()
	client := &http.Client{Timeout: 2 * time.Second}
	poll := func() {
		req, err := newMihomoAPIRequest(ctx, "/connections", secret)
		if err != nil {
			state.update(func(v *mihomoTelemetrySnapshot) { v.ConnectionsError = safeMihomoValidationDiagnostic([]byte(err.Error())) })
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() == nil {
				state.update(func(v *mihomoTelemetrySnapshot) { v.Connections = 0; v.ConnectionsError = safeMihomoValidationDiagnostic([]byte("Mihomo /connections 请求失败: " + err.Error())) })
			}
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			state.update(func(v *mihomoTelemetrySnapshot) { v.Connections = 0; v.ConnectionsError = fmt.Sprintf("Mihomo /connections 返回 HTTP %d", resp.StatusCode) })
			return
		}
		var payload struct {
			Connections []json.RawMessage `json:"connections"`
			UploadTotal uint64            `json:"uploadTotal"`
			DownloadTotal uint64          `json:"downloadTotal"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			state.update(func(v *mihomoTelemetrySnapshot) { v.Connections = 0; v.ConnectionsError = safeMihomoValidationDiagnostic([]byte("解析 Mihomo /connections 失败: " + err.Error())) })
			return
		}
		state.update(func(v *mihomoTelemetrySnapshot) {
			v.Connections = len(payload.Connections)
			v.UploadTotal = payload.UploadTotal
			v.DownloadTotal = payload.DownloadTotal
			v.ConnectionsError = ""
		})
	}
	poll()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		}
	}
}

var agentWSWriteLocks sync.Map

func lockAgentWSWrite(conn *websocket.Conn) func() {
	value, _ := agentWSWriteLocks.LoadOrStore(conn, &sync.Mutex{})
	mu := value.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func forgetAgentWSWriteLock(conn *websocket.Conn) {
	agentWSWriteLocks.Delete(conn)
}

func runAgentTelemetryPublisher(ctx context.Context, conn *websocket.Conn) {
	secret, err := mihomoControllerSecret()
	state := &mihomoTelemetryState{}
	if err != nil {
		state.update(func(v *mihomoTelemetrySnapshot) { diagnostic := safeMihomoValidationDiagnostic([]byte(err.Error())); v.TrafficError = diagnostic; v.ConnectionsError = diagnostic })
	} else {
		go streamMihomoTraffic(ctx, state, secret)
		go pollMihomoConnections(ctx, state, secret)
	}
	ticker := time.NewTicker(defaultTelemetryPushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			snapshot := state.snapshot()
			payload := map[string]any{
				"type": "telemetry",
				"status": map[string]any{
					"upload_speed": snapshot.UploadSpeed,
					"download_speed": snapshot.DownloadSpeed,
					"connections": snapshot.Connections,
					"upload_total": snapshot.UploadTotal,
					"download_total": snapshot.DownloadTotal,
					"traffic_error": snapshot.TrafficError,
					"connections_error": snapshot.ConnectionsError,
					"telemetry_at_ms": now.UnixMilli(),
				},
			}
			if err := writeAgentWSJSON(conn, payload); err != nil {
				return
			}
		}
	}
}
