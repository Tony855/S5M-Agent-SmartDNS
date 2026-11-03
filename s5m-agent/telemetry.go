package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

const (
	defaultTelemetryPushInterval = 200 * time.Millisecond
	defaultConnectionsInterval  = 500 * time.Millisecond
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
	SampledAt        time.Time `json:"-"`
}

type mihomoTelemetryState struct {
	mu    sync.RWMutex
	value mihomoTelemetrySnapshot
}

// Shared by the heartbeat snapshot and the high-frequency WebSocket publisher.
// The publisher sends snapshots through the controller's supported telemetry frame.
var agentMihomoTelemetry = &mihomoTelemetryState{}

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
	return mihomoAPISecretFromConfig(cfg)
}

func mihomoAPISecretOrLoad(current string, load func() (string, error)) (string, error) {
	if strings.TrimSpace(current) != "" {
		return current, nil
	}
	if load == nil {
		return "", fmt.Errorf("Mihomo API secret loader is unavailable")
	}
	return load()
}

func mihomoAPISecretFromConfig(cfg map[string]any) (string, error) {
	secret, _ := cfg["secret"].(string)
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return "", fmt.Errorf("Mihomo 配置缺少 API secret，拒绝发起未鉴权 API 请求")
	}
	return secret, nil
}

func newMihomoAPIRequest(ctx context.Context, path, secret string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:8088"+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	return req, nil
}

// calculateCounterRate derives bytes/second from Mihomo's monotonic cumulative
// counters. A counter reset or non-positive sample interval produces zero.
func calculateCounterRate(current, previous uint64, elapsed time.Duration) float64 {
	if elapsed <= 0 || current < previous {
		return 0
	}
	return float64(current-previous) / elapsed.Seconds()
}

func mihomoTelemetryIsStale(sampledAt, now time.Time) bool {
	return sampledAt.IsZero() || now.Sub(sampledAt) > 3*defaultConnectionsInterval
}

func applyMihomoTelemetrySnapshot(status map[string]any, snapshot mihomoTelemetrySnapshot, now time.Time) {
	status["upload_speed"] = snapshot.UploadSpeed
	status["download_speed"] = snapshot.DownloadSpeed
	status["upload_total"] = snapshot.UploadTotal
	status["download_total"] = snapshot.DownloadTotal
	status["connections"] = snapshot.Connections
	status["traffic_error"] = snapshot.TrafficError
	status["connections_error"] = snapshot.ConnectionsError
	sampledAtMS := int64(0)
	if !snapshot.SampledAt.IsZero() {
		sampledAtMS = snapshot.SampledAt.UnixMilli()
	}
	status["telemetry_sampled_at_ms"] = sampledAtMS
	status["telemetry_stale"] = mihomoTelemetryIsStale(snapshot.SampledAt, now)
}

func recordMihomoTelemetryError(state *mihomoTelemetryState, message string) {
	message = safeMihomoValidationDiagnostic([]byte(message))
	state.update(func(v *mihomoTelemetrySnapshot) {
		// Keep the last successful counters and connection count. A temporary
		// API/network failure must not be rendered as a real zero-traffic state.
		v.TrafficError = message
		v.ConnectionsError = message
	})
}

func pollMihomoConnections(ctx context.Context, state *mihomoTelemetryState) {
	ticker := time.NewTicker(defaultConnectionsInterval)
	defer ticker.Stop()
	client := &http.Client{Timeout: 2 * time.Second}
	var secret string
	var previousAt time.Time
	var previousUpload, previousDownload uint64

	poll := func() {
		// Read the secret lazily and retry on every polling cycle while it is
		// unavailable. This recovers from startup races where Mihomo config is
		// generated after the Agent WebSocket session has already connected.
		var err error
		secret, err = mihomoAPISecretOrLoad(secret, mihomoControllerSecret)
		if err != nil {
			previousAt = time.Time{}
			recordMihomoTelemetryError(state, "读取 Mihomo API secret 失败: "+err.Error())
			return
		}

		req, err := newMihomoAPIRequest(ctx, "/connections", secret)
		if err != nil {
			previousAt = time.Time{}
			recordMihomoTelemetryError(state, "创建 Mihomo /connections 请求失败: "+err.Error())
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() == nil {
				previousAt = time.Time{}
				recordMihomoTelemetryError(state, "Mihomo /connections 请求失败: "+err.Error())
			}
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			// The Mihomo secret may have changed during a config reload. Drop
			// the cached value so the next poll rereads the current config.
			secret = ""
			previousAt = time.Time{}
			recordMihomoTelemetryError(state, fmt.Sprintf("Mihomo /connections 鉴权失败 HTTP %d，等待重新读取 API secret", resp.StatusCode))
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			previousAt = time.Time{}
			recordMihomoTelemetryError(state, fmt.Sprintf("Mihomo /connections 返回 HTTP %d", resp.StatusCode))
			return
		}
		var payload struct {
			Connections   []json.RawMessage `json:"connections"`
			UploadTotal   uint64            `json:"uploadTotal"`
			DownloadTotal uint64            `json:"downloadTotal"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, (4<<20)+1)).Decode(&payload); err != nil {
			previousAt = time.Time{}
			recordMihomoTelemetryError(state, "解析 Mihomo /connections 失败: "+err.Error())
			return
		}

		now := time.Now()
		upSpeed, downSpeed := float64(0), float64(0)
		if !previousAt.IsZero() {
			elapsed := now.Sub(previousAt)
			upSpeed = calculateCounterRate(payload.UploadTotal, previousUpload, elapsed)
			downSpeed = calculateCounterRate(payload.DownloadTotal, previousDownload, elapsed)
		}
		previousAt = now
		previousUpload = payload.UploadTotal
		previousDownload = payload.DownloadTotal

		state.update(func(v *mihomoTelemetrySnapshot) {
			v.Connections = len(payload.Connections)
			v.UploadTotal = payload.UploadTotal
			v.DownloadTotal = payload.DownloadTotal
			v.UploadSpeed = upSpeed
			v.DownloadSpeed = downSpeed
			v.SampledAt = now
			v.TrafficError = ""
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
	// The controller has a dedicated "telemetry" frame handler. It consumes
	// these frames without replying on the socket and publishes browser events,
	// so this stream does not interfere with synchronous heartbeat/config ACKs.
	go pollMihomoConnections(ctx, agentMihomoTelemetry)

	ticker := time.NewTicker(defaultTelemetryPushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			snapshot := agentMihomoTelemetry.snapshot()
			sampledAtMS := int64(0)
			if !snapshot.SampledAt.IsZero() {
				sampledAtMS = snapshot.SampledAt.UnixMilli()
			}
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
					"telemetry_sampled_at_ms": sampledAtMS,
					"telemetry_stale": mihomoTelemetryIsStale(snapshot.SampledAt, now),
				},
			}
			if err := writeAgentWSJSON(conn, payload); err != nil {
				return
			}
		}
	}
}
