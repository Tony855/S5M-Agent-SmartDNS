package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	maxMihomoAPIResponseBytes      = 64 << 10
	maxMihomoAPIErrorResponseBytes = 4 << 10
)

// readMihomoAPIResponse reads at most maxBytes+1 bytes so oversized responses
// are detected even when the peer omits Content-Length or streams chunked data.
func readMihomoAPIResponse(body io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("Mihomo API 响应大小限制无效")
	}
	data, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("读取 Mihomo API 响应失败: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("Mihomo API 响应超过 %d 字节限制", maxBytes)
	}
	return data, nil
}

func (a *App) mihomoReq(method, path string, body io.Reader) (*http.Response, error) {
	url := strings.TrimRight(a.cfg.MihomoAPI, "/") + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.cfg.MihomoSecret != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.MihomoSecret)
	}
	return (&http.Client{Timeout: 10 * time.Second}).Do(req)
}

func (a *App) ReloadMihomo() error {
	b := fmt.Sprintf(`{"path":%q}`, a.cfg.MihomoConfigPath)
	resp, err := a.mihomoReq(http.MethodPut, "/configs?force=true", strings.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, readErr := readMihomoAPIResponse(resp.Body, maxMihomoAPIErrorResponseBytes)
		if readErr != nil {
			return fmt.Errorf("HTTP %d: %w", resp.StatusCode, readErr)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}

func (a *App) MihomoInfo() map[string]any {
	out := map[string]any{"online": false}
	resp, err := a.mihomoReq(http.MethodGet, "/version", nil)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		out["error"] = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return out
	}
	raw, err := readMihomoAPIResponse(resp.Body, maxMihomoAPIResponseBytes)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		out["error"] = "Mihomo /version 响应格式无效"
		return out
	}
	out["online"] = true
	out["version"] = v
	return out
}

// runningMihomoAPIVersion reads the version reported by the live controller API.
// It deliberately does not infer the running version from the on-disk binary.
func (a *App) runningMihomoAPIVersion() (string, error) {
	resp, err := a.mihomoReq(http.MethodGet, "/version", nil)
	if err != nil {
		return "", fmt.Errorf("连接 Mihomo 控制 API 失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxMihomoAPIErrorResponseBytes))
		return "", fmt.Errorf("Mihomo /version 返回 HTTP %d", resp.StatusCode)
	}
	raw, err := readMihomoAPIResponse(resp.Body, 16<<10)
	if err != nil {
		return "", fmt.Errorf("读取 Mihomo /version 响应失败: %w", err)
	}
	var payload struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &payload); err != nil {
		return "", fmt.Errorf("解析 Mihomo /version 响应失败: %w", err)
	}
	version := strings.TrimPrefix(strings.TrimSpace(payload.Version), "v")
	if version == "" {
		return "", fmt.Errorf("Mihomo /version 未返回有效版本号")
	}
	return "v" + version, nil
}

func (a *App) waitForMihomoAPIVersion(expected string, timeout time.Duration) error {
	expected = strings.TrimPrefix(strings.TrimSpace(expected), "v")
	if expected == "" {
		return fmt.Errorf("目标 Mihomo 版本不能为空")
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		actual, err := a.runningMihomoAPIVersion()
		if err == nil && strings.TrimPrefix(actual, "v") == expected {
			return nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("运行版本不匹配，期望 v%s，实际 %q", expected, actual)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("等待 Mihomo 运行版本确认超时: %w", lastErr)
		}
		pause := 500 * time.Millisecond
		if remaining := time.Until(deadline); remaining < pause {
			pause = remaining
		}
		time.Sleep(pause)
	}
}
