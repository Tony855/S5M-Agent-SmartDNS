package app

import (
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	slog.Error("API 报错", "code", code, "msg", msg)
	writeJSON(w, code, map[string]string{"error": msg})
}

const maxJSONRequestBody = 2 << 20

var errRequestBodyTooLarge = errors.New("请求体超过大小限制")

func decodeLimited(r *http.Request, maxBytes int64, sizeLabel string, v any) error {
	if maxBytes <= 0 {
		return errors.New("请求体大小限制无效")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > maxBytes {
		return fmt.Errorf("%w: %s", errRequestBodyTooLarge, sizeLabel)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return err
	}
	return nil
}

func decode(r *http.Request, v any) error {
	return decodeLimited(r, maxJSONRequestBody, "2 MiB", v)
}

func decodeErrorStatus(err error) int {
	if errors.Is(err, errRequestBodyTooLarge) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func (a *App) handleCreateBrowserEventsTicket(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u == nil || u.Role != "admin" {
		writeErr(w, http.StatusForbidden, "需要管理员权限")
		return
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		writeErr(w, http.StatusInternalServerError, "生成实时通道授权失败")
		return
	}
	ticket := hex.EncodeToString(buf)
	now := time.Now()
	a.browserTicketMu.Lock()
	if a.browserTickets == nil {
		a.browserTickets = make(map[string]browserWSTicket)
	}
	for key, value := range a.browserTickets {
		if !value.ExpiresAt.After(now) {
			delete(a.browserTickets, key)
		}
	}
	a.browserTickets[ticket] = browserWSTicket{Username: u.Username, ExpiresAt: now.Add(30 * time.Second)}
	a.browserTicketMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ticket": ticket, "expires_in": 30})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, "参数错误")
		return
	}
	u, err := a.store.UserByUsername(in.Username)
	if err != nil || !u.Enabled || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Password)) != nil {
		writeErr(w, 401, "账号或密码错误")
		return
	}
	tok, err := a.signToken(u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "生成登录凭证失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "user": u})
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, currentUser(r)) }

func (a *App) handlePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Old string `json:"old"`
		New string `json:"new"`
	}

	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	if len(in.New) < 6 {
		writeErr(w, http.StatusBadRequest, "新密码至少 6 位")
		return
	}

	cu := currentUser(r)
	if cu == nil {
		writeErr(w, http.StatusUnauthorized, "未登录")
		return
	}

	u, err := a.store.UserByUsername(cu.Username)
	if err != nil || u == nil || !u.Enabled {
		writeErr(w, http.StatusUnauthorized, "账号不存在或已禁用，请重新登录")
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Old)) != nil {
		writeErr(w, http.StatusUnauthorized, "原密码错误")
		return
	}

	h, err := bcrypt.GenerateFromPassword([]byte(in.New), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "密码处理失败")
		return
	}

	if err := a.store.UpdatePassword(u.ID, string(h)); err != nil {
		writeErr(w, http.StatusInternalServerError, "密码保存失败")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "密码已更新"})
}

func isInternalSettingKey(key string) bool {
	for _, prefix := range []string{
		"agent_machine_", "agent_mihomo_secret_", "agent_secret_", "agent_command_",
		"agent_command_result_", "smartdns_config_", "agent_lastseen_", "agent_status_", "mihomo_secret_",
	} {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return key == "agent_token"
}

func (a *App) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取设置失败")
		return
	}
	// Do not return credentials, queued commands, or runtime telemetry through the
	// generic settings endpoint. Dedicated Agent endpoints expose only necessary fields.
	publicSettings := make(map[string]string, len(settings))
	for key, value := range settings {
		if !isInternalSettingKey(key) {
			publicSettings[key] = value
		}
	}
	writeJSON(w, http.StatusOK, publicSettings)
}

func (a *App) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var in map[string]string
	if err := decode(r, &in); err != nil || in == nil {
		writeErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	for key := range in {
		if isInternalSettingKey(key) {
			writeErr(w, http.StatusBadRequest, "禁止通过通用设置接口修改内部授权、密钥或 Agent 命令字段")
			return
		}
	}
	if mode, ok := in["proxy_routing_mode"]; ok {
		switch strings.TrimSpace(mode) {
		case "global", "split", "rule", "return", "game":
		default:
			writeErr(w, http.StatusBadRequest, "代理模式必须是 global、split、rule、return 或 game")
			return
		}
	}
	if raw, ok := in["smartdns_routing_config"]; ok {
		var cfg SmartDNSRoutingConfig
		if strings.TrimSpace(raw) == "" {
			// Empty value explicitly removes the opt-in setting and restores legacy behavior.
			in["smartdns_routing_config"] = ""
		} else {
			if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
				writeErr(w, http.StatusBadRequest, "SmartDNS 路由设置必须是有效 JSON: "+err.Error())
				return
			}
			if cfg.Mode == SmartDNSProxyModePerClient {
				writeErr(w, http.StatusBadRequest, "按客户端独立出口尚未完成隔离 DNS 运行时，暂不允许启用")
				return
			}
			if cfg.Mode != SmartDNSProxyModeShared {
				writeErr(w, http.StatusBadRequest, "SmartDNS 模式必须是 shared；留空可恢复旧行为")
				return
			}
			if cfg.Strategy != "" && cfg.Strategy != SmartDNSDefaultStrategy {
				writeErr(w, http.StatusBadRequest, "当前 SmartDNS 统一代理策略仅支持 fallback")
				return
			}
			cfg.Strategy = SmartDNSDefaultStrategy
			normalized, err := json.Marshal(cfg)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "SmartDNS 路由设置无法序列化")
				return
			}
			in["smartdns_routing_config"] = string(normalized)
		}
	}
	if err := a.store.UpdateSettings(in); err != nil {
		writeErr(w, http.StatusInternalServerError, "设置保存失败")
		return
	}
	// Routing and other shared settings affect generated Agent YAML. Refresh
	// every authorized node's cached configuration before reporting success.
	// A failure is explicit: the setting is persisted, but one or more node
	// configurations may still be stale and require a retry.
	if err := a.syncAuthorizedNodeConfigs(); err != nil {
		writeErr(w, http.StatusInternalServerError, "设置已保存，但节点配置同步失败；请重试同步: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "设置已保存，已重新生成并保存已授权节点配置；在线 Agent 将在下次拉取时应用"})
}

func (a *App) handleListInstances(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListInstances()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取实例列表失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
}
func validateInstance(in *Instance) string {
	in.Name = strings.TrimSpace(in.Name)
	in.MachineCode = strings.TrimSpace(in.MachineCode)
	in.APIURL = strings.TrimSpace(in.APIURL)

	if in.Name == "" {
		return "实例名称不能为空"
	}
	if len(in.Name) > 100 {
		return "实例名称不能超过 100 个字符"
	}
	if len(in.MachineCode) > 128 {
		return "机器码不能超过 128 个字符"
	}
	if len(in.APIURL) > 2048 {
		return "API 地址不能超过 2048 个字符"
	}
	if in.APIURL != "" {
		parsed, err := url.ParseRequestURI(in.APIURL)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
			return "API 地址必须是有效的 HTTP 或 HTTPS URL，且不能包含用户名或密码"
		}
	}
	return ""
}

func (a *App) handleCreateInstance(w http.ResponseWriter, r *http.Request) {
	var in Instance
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	if msg := validateInstance(&in); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	if err := a.store.CreateInstance(&in); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, in)
}
func (a *App) handleDeleteInstance(w http.ResponseWriter, r *http.Request) {
	rawID := strings.TrimSpace(r.PathValue("id"))
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "实例 ID 无效")
		return
	}

	if err := a.store.DeleteInstance(id); err != nil {
		writeErr(w, http.StatusInternalServerError, "删除实例失败")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "已删除"})
}

func (a *App) handleListMachineProxyModes(w http.ResponseWriter, r *http.Request) {
	modes, err := a.store.ListMachineProxyModes()
	if err != nil { writeErr(w, http.StatusInternalServerError, "读取机器代理模式列表失败"); return }
	writeJSON(w, http.StatusOK, modes)
}

func (a *App) handleGetMachineProxyMode(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.PathValue("code"))
	if code == "" || code == "__GLOBAL__" { writeErr(w, http.StatusBadRequest, "机器码无效"); return }
	mode, err := a.store.GetMachineProxyMode(code)
	if err != nil { writeErr(w, http.StatusInternalServerError, "读取机器代理模式失败"); return }
	writeJSON(w, http.StatusOK, map[string]string{"machine_code": code, "routing_mode": mode})
}

func (a *App) handleSetMachineProxyMode(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.PathValue("code"))
	if code == "" || code == "__GLOBAL__" { writeErr(w, http.StatusBadRequest, "机器码无效"); return }
	var in struct { RoutingMode string `json:"routing_mode"` }
	if err := decode(r, &in); err != nil { writeErr(w, http.StatusBadRequest, "参数错误"); return }
	if err := a.store.SetMachineProxyMode(code, in.RoutingMode); err != nil { writeErr(w, http.StatusBadRequest, err.Error()); return }
	if err := a.syncAuthorizedNodeConfigs(); err != nil { writeErr(w, http.StatusInternalServerError, "机器模式已保存，但节点配置同步失败: "+err.Error()); return }
	writeJSON(w, http.StatusOK, map[string]string{"machine_code": code, "routing_mode": strings.ToLower(strings.TrimSpace(in.RoutingMode)), "message": "机器代理模式已保存并同步"})
}

func (a *App) handleListProxies(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListProxies()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取代理列表失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *App) validateProxy(p *Proxy) string {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" { return "名称不能为空" }
	p.MachineCode = strings.TrimSpace(p.MachineCode)
	if p.MachineCode != "" && p.MachineCode != "__GLOBAL__" && (len(p.MachineCode) > 64 || !regexp.MustCompile("^[A-Za-z0-9_-]+$").MatchString(p.MachineCode)) {
		return "关联机器码格式错误；留空表示未绑定，或选择全局节点"
	}
	// Per-proxy routing mode is deprecated; routing is configured once per machine.
	p.Mode = "rule"
	p.Type = strings.ToLower(strings.TrimSpace(p.Type))
	p.Server = strings.TrimSpace(p.Server)
	switch p.Type { case "socks5", "http", "ss", "vmess", "vless", "trojan": default: return "代理类型无效，必须是 socks5、http、ss、vmess、vless 或 trojan" }
	if p.Server == "" { return "代理必须填写类型、服务器和端口" }
	if p.Port < 1 || p.Port > 65535 { return "代理端口必须在 1-65535 之间" }
	p.SourceCIDR = strings.TrimSpace(p.SourceCIDR)
	if p.SourceCIDR == "" { p.SourceCIDR = "0.0.0.0/0" }
	if _, _, err := net.ParseCIDR(p.SourceCIDR); err != nil { return "源 IP 必须是合法 CIDR" }
	return ""
}

func (a *App) handleCreateProxy(w http.ResponseWriter, r *http.Request) {
	var p Proxy
	if err := decode(r, &p); err != nil {
		writeErr(w, 400, "参数错误")
		return
	}
	if msg := a.validateProxy(&p); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if p.Extra == nil {
		p.Extra = map[string]any{}
	}
	if err := a.store.CreateProxy(&p); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	if err := a.syncAuthorizedNodeConfigs(); err != nil {
		writeErr(w, http.StatusInternalServerError, "代理已保存，但节点配置同步失败: "+err.Error())
		return
	}
	writeJSON(w, 200, p)
}

func (a *App) handleUpdateProxy(w http.ResponseWriter, r *http.Request) {
	rawID := strings.TrimSpace(r.PathValue("id"))
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "代理 ID 无效")
		return
	}
	var p Proxy
	if err := decode(r, &p); err != nil {
		writeErr(w, 400, "参数错误")
		return
	}
	p.ID = id
	if msg := a.validateProxy(&p); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if p.Extra == nil {
		p.Extra = map[string]any{}
	}
	if err := a.store.UpdateProxy(&p); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	if err := a.syncAuthorizedNodeConfigs(); err != nil {
		writeErr(w, http.StatusInternalServerError, "代理已更新，但节点配置同步失败: "+err.Error())
		return
	}
	writeJSON(w, 200, p)
}

func (a *App) handleDeleteProxy(w http.ResponseWriter, r *http.Request) {
	rawID := strings.TrimSpace(r.PathValue("id"))
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "代理 ID 无效")
		return
	}

	if err := a.store.DeleteProxy(id); err != nil {
		writeErr(w, http.StatusInternalServerError, "删除代理失败")
		return
	}
	if err := a.syncAuthorizedNodeConfigs(); err != nil {
		writeErr(w, http.StatusInternalServerError, "代理已删除，但节点配置同步失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "已删除"})
}

func (a *App) handlePreview(w http.ResponseWriter, r *http.Request) {
	yml, err := a.BuildConfig()
	if err != nil {
		writeErr(w, 500, "生成配置失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"yaml": yml})
}
func (a *App) handlePublish(w http.ResponseWriter, r *http.Request) {
	cv, err := a.Publish()
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "message": err.Error(), "version": cv})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "message": "发布成功", "version": cv})
}
func (a *App) handleVersions(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListVersions(30)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取配置版本失败")
		return
	}
	writeJSON(w, http.StatusOK, list)
}
func (a *App) handleRollback(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Version int `json:"version"`
	}
	if err := decode(r, &in); err != nil || in.Version <= 0 {
		writeErr(w, 400, "无效")
		return
	}
	cv, err := a.Rollback(in.Version)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "message": err.Error(), "version": cv})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "message": "回滚成功", "version": cv})
}
func (a *App) handleOverview(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListProxies()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取代理概览失败")
		return
	}

	enabled := 0
	for _, p := range list {
		if p.Enabled {
			enabled++
		}
	}

	// 先获取内核状态；内核异常时仍返回仪表盘数据。
	mihomo := a.MihomoInfo()

	var downloadTotal uint64
	var uploadTotal uint64
	var connections []any

	resp, monitorErr := a.mihomoReq(http.MethodGet, "/connections", nil)
	if monitorErr == nil {
		defer resp.Body.Close()
		if resp.StatusCode < 300 {
			var data struct {
				DownloadTotal uint64 `json:"downloadTotal"`
				UploadTotal   uint64 `json:"uploadTotal"`
				Connections   []any  `json:"connections"`
			}
			if json.NewDecoder(resp.Body).Decode(&data) == nil {
				downloadTotal = data.DownloadTotal
				uploadTotal = data.UploadTotal
				connections = data.Connections
			}
		}
	}

	if connections == nil {
		connections = []any{}
	}

	// Remote Agent telemetry is stored separately from the controller's own Mihomo
	// overview. Include it explicitly because the dashboard renders remote_nodes.
	remoteNodes := make([]map[string]any, 0)
	settings, settingsErr := a.store.GetSettings()
	if settingsErr == nil {
		now := time.Now().Unix()
		for key := range settings {
			if !strings.HasPrefix(key, "agent_machine_") {
				continue
			}
			code := strings.TrimPrefix(key, "agent_machine_")
			if code == "" {
				continue
			}
			token := settings[key]
			if strings.TrimSpace(token) == "" || token == settings["agent_token"] {
				continue
			}
			lastSeen, _ := strconv.ParseInt(settings["agent_lastseen_"+code], 10, 64)
			status := map[string]any{}
			if raw := settings["agent_status_"+code]; raw != "" {
				_ = json.Unmarshal([]byte(raw), &status)
			}
			if lastSeen <= 0 {
				if receivedAt, ok := status["received_at"].(float64); ok && receivedAt > 0 && receivedAt <= 9.0e15 {
					lastSeen = int64(receivedAt)
				}
			}
			online := lastSeen > 0 && now-lastSeen >= 0 && now-lastSeen < 90
			healthy, _ := status["mihomo_healthy"].(bool)
			apiOnline := healthy
			updatedAt := ""
			if lastSeen > 0 {
				updatedAt = time.Unix(lastSeen, 0).Format(time.RFC3339)
			}
			remoteNodes = append(remoteNodes, map[string]any{
				"machine_code":      code,
				"hostname":          status["hostname"],
				"online":            online,
				"healthy":           online && healthy,
				"mihomo_api_online": online && apiOnline,
				"mihomo_version":    status["mihomo_version"],
				"connections":       status["connections"],
				"downloadSpeed":     status["download_speed"],
				"uploadSpeed":       status["upload_speed"],
				"downloadTotal":     status["download_total"],
				"uploadTotal":       status["upload_total"],
				"last_seen":         lastSeen,
				"updated_at":        updatedAt,
				"last_error":        status["last_error"],
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mihomo":         mihomo,
		"total":          len(list),
		"enabled":        enabled,
		"proxy_total":    len(list),
		"proxy_enabled":  enabled,
		"downloadTotal":  downloadTotal,
		"uploadTotal":    uploadTotal,
		"connections":    connections,
		"remote_nodes":   remoteNodes,
		"agent_total":    len(remoteNodes),
		"agent_online":   countRemoteAgentOnline(remoteNodes),
		"mihomo_healthy": countRemoteMihomoHealthy(remoteNodes),
		// Keep dashboard counter names aligned with the frontend's overview contract.
		"remote_node_total":     len(remoteNodes),
		"remote_online":         countRemoteAgentOnline(remoteNodes),
		"remote_mihomo_healthy": countRemoteMihomoHealthy(remoteNodes),
	})
}

func countRemoteAgentOnline(nodes []map[string]any) int {
	count := 0
	for _, node := range nodes {
		if online, _ := node["online"].(bool); online {
			count++
		}
	}
	return count
}

func countRemoteMihomoHealthy(nodes []map[string]any) int {
	count := 0
	for _, node := range nodes {
		if healthy, _ := node["healthy"].(bool); healthy {
			count++
		}
	}
	return count
}

var trafficMu sync.Mutex
var lastUp, lastDown uint64
var lastTime time.Time

// handleMihomoStatus reports the controller's local Mihomo binary and systemd service state.
// It is read-only: querying status never restarts or updates the kernel.
func (a *App) handleMihomoStatus(w http.ResponseWriter, _ *http.Request) {
	const binaryPath = "/opt/mihomo/mihomo"
	out := map[string]any{
		"binary_path": binaryPath,
		"version":     "未知",
		"service":     "unknown",
		"online":      false,
		"binary_ok":   false,
		"api_online":  false,
		"api_version": "未知",
		"checked_at":  time.Now().Unix(),
	}
	if info, err := os.Stat(binaryPath); err != nil {
		out["binary_error"] = err.Error()
	} else if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		out["binary_error"] = "目标不是可执行的普通文件"
	} else {
		versionOutput, err := exec.Command(binaryPath, "-v").CombinedOutput()
		if err != nil {
			out["binary_error"] = strings.TrimSpace(string(versionOutput))
			if out["binary_error"] == "" {
				out["binary_error"] = err.Error()
			}
		} else {
			version := parseMihomoVersion(versionOutput)
			out["version"] = version
			out["binary_ok"] = version != "unknown"
			if version == "unknown" {
				out["binary_error"] = "版本输出无法识别: " + strings.TrimSpace(string(versionOutput))
			}
		}
	}

	serviceOutput, serviceErr := exec.Command("systemctl", "is-active", "mihomo").CombinedOutput()
	serviceState := strings.TrimSpace(string(serviceOutput))
	if serviceState == "" && serviceErr != nil {
		serviceState = "unknown"
	}
	out["service"] = serviceState
	if serviceErr != nil {
		out["service_error"] = strings.TrimSpace(string(serviceOutput))
		if out["service_error"] == "" {
			out["service_error"] = serviceErr.Error()
		}
	}

	apiVersion, apiErr := a.runningMihomoAPIVersion()
	if apiErr != nil {
		out["api_error"] = apiErr.Error()
	} else {
		out["api_online"] = true
		out["api_version"] = apiVersion
		binaryVersion, _ := out["version"].(string)
		if binaryVersion != "未知" && strings.TrimPrefix(binaryVersion, "v") != strings.TrimPrefix(apiVersion, "v") {
			out["version_mismatch"] = true
			out["api_error"] = fmt.Sprintf("磁盘二进制版本 %s 与运行中的 Mihomo 版本 %s 不一致", binaryVersion, apiVersion)
		}
	}
	out["online"] = out["binary_ok"] == true &&
		serviceState == "active" &&
		out["api_online"] == true &&
		out["version_mismatch"] != true
	writeJSON(w, http.StatusOK, out)
}

func (a *App) handleMonitorTraffic(w http.ResponseWriter, _ *http.Request) {
	resp, err := a.mihomoReq(http.MethodGet, "/connections", nil)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "连接主控 Mihomo API 失败: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		detail := strings.TrimSpace(string(body))
		if detail == "" {
			detail = http.StatusText(resp.StatusCode)
		}
		writeErr(w, http.StatusBadGateway, fmt.Sprintf("主控 Mihomo /connections 返回 HTTP %d: %s", resp.StatusCode, detail))
		return
	}
	var data struct {
		DownloadTotal uint64 `json:"downloadTotal"`
		UploadTotal   uint64 `json:"uploadTotal"`
		Connections   []any  `json:"connections"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&data); err != nil {
		writeErr(w, http.StatusBadGateway, "Mihomo 流量数据格式无效")
		return
	}
	now := time.Now()
	upSpeed, downSpeed := uint64(0), uint64(0)
	trafficMu.Lock()
	if !lastTime.IsZero() {
		diff := now.Sub(lastTime).Seconds()
		if diff > 0 {
			if data.UploadTotal >= lastUp {
				upSpeed = uint64(float64(data.UploadTotal-lastUp) / diff)
			}
			if data.DownloadTotal >= lastDown {
				downSpeed = uint64(float64(data.DownloadTotal-lastDown) / diff)
			}
		}
	}
	lastUp, lastDown, lastTime = data.UploadTotal, data.DownloadTotal, now
	trafficMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"up": upSpeed, "down": downSpeed, "conns": len(data.Connections)})
}

type mihomoReleaseAsset struct {
	Name               string "json:\"name\""
	BrowserDownloadURL string "json:\"browser_download_url\""
}

func parseMihomoVersion(output []byte) string {
	match := regexp.MustCompile("Mihomo Meta (v[0-9]+\\.[0-9]+\\.[0-9]+)").FindSubmatch(output)
	if len(match) < 2 {
		return "unknown"
	}
	return string(match[1])
}

func findMihomoCompatibleAsset(assets []mihomoReleaseAsset) string {
	for _, asset := range assets {
		if strings.Contains(asset.Name, "linux-amd64-compatible") &&
			strings.HasSuffix(asset.Name, ".gz") &&
			!strings.HasSuffix(asset.Name, ".tar.gz") &&
			strings.HasPrefix(asset.BrowserDownloadURL, "https://") {
			return asset.BrowserDownloadURL
		}
	}
	return ""
}

func isGzipHeader(header []byte) bool {
	return len(header) >= 2 && header[0] == 0x1f && header[1] == 0x8b
}

func copyFileAtomic(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(destination), ".mihomo-copy-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, destination)
}

func (a *App) handleUpdateMihomo(w http.ResponseWriter, r *http.Request) {
	const (
		binaryPath = "/opt/mihomo/mihomo"
		backupPath = "/opt/mihomo/mihomo.bak"
		releaseURL = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
	)
	info, statErr := os.Stat(binaryPath)
	if statErr != nil {
		writeErr(w, http.StatusInternalServerError, "读取当前 Mihomo 版本失败：检查二进制路径 "+binaryPath+"："+statErr.Error())
		return
	}
	if !info.Mode().IsRegular() {
		writeErr(w, http.StatusInternalServerError, "读取当前 Mihomo 版本失败：目标不是普通文件："+binaryPath)
		return
	}
	if info.Mode().Perm()&0o111 == 0 {
		writeErr(w, http.StatusInternalServerError, "读取当前 Mihomo 版本失败：二进制没有执行权限："+binaryPath)
		return
	}
	out, err := exec.CommandContext(r.Context(), binaryPath, "-v").CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			detail = err.Error()
		} else {
			detail += " (" + err.Error() + ")"
		}
		writeErr(w, http.StatusInternalServerError, "读取当前 Mihomo 版本失败："+detail)
		return
	}
	currentVersion := parseMihomoVersion(out)
	if currentVersion == "unknown" {
		writeErr(w, http.StatusInternalServerError, "读取当前 Mihomo 版本失败：命令执行成功，但输出无法识别："+strings.TrimSpace(string(out)))
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, releaseURL, nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "创建更新请求失败")
		return
	}
	req.Header.Set("User-Agent", "S5M-Next")
	resp, err := client.Do(req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "检查 Mihomo 更新失败: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeErr(w, http.StatusBadGateway, fmt.Sprintf("GitHub 更新接口返回 HTTP %d", resp.StatusCode))
		return
	}

	var release struct {
		TagName string               "json:\"tag_name\""
		Assets  []mihomoReleaseAsset "json:\"assets\""
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		writeErr(w, http.StatusBadGateway, "解析 Mihomo 发布信息失败")
		return
	}
	if !regexp.MustCompile("^v[0-9]+\\.[0-9]+\\.[0-9]+$").MatchString(release.TagName) {
		writeErr(w, http.StatusBadGateway, "GitHub 返回的 Mihomo 版本号无效")
		return
	}
	if currentVersion == release.TagName {
		writeJSON(w, http.StatusOK, map[string]string{"message": "当前已是最新版本", "status": "latest", "version": currentVersion})
		return
	}

	assetURL := findMihomoCompatibleAsset(release.Assets)
	if assetURL == "" {
		writeErr(w, http.StatusBadGateway, "未找到有效的 linux-amd64-compatible 更新包")
		return
	}

	gzFile, err := os.CreateTemp("", "s5m-mihomo-update-*.gz")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "创建下载临时文件失败")
		return
	}
	gzPath := gzFile.Name()
	if err := gzFile.Close(); err != nil {
		_ = os.Remove(gzPath)
		writeErr(w, http.StatusInternalServerError, "准备下载临时文件失败")
		return
	}
	defer os.Remove(gzPath)

	download := func(url string) error {
		cmd := exec.CommandContext(r.Context(), "curl", "--fail", "--location", "--retry", "2",
			"--connect-timeout", "15", "--max-time", "240", "--output", gzPath, url)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
		}
		info, err := os.Stat(gzPath)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("下载文件为空或无效")
		}
		downloaded, err := os.Open(gzPath)
		if err != nil {
			return err
		}
		header := make([]byte, 2)
		n, readErr := io.ReadFull(downloaded, header)
		closeErr := downloaded.Close()
		if readErr != nil || closeErr != nil || !isGzipHeader(header[:n]) {
			return fmt.Errorf("下载内容不是有效的 gzip 文件")
		}
		return nil
	}
	if err := download("https://ghproxy.net/" + assetURL); err != nil {
		_ = os.Remove(gzPath)
		if directErr := download(assetURL); directErr != nil {
			writeErr(w, http.StatusBadGateway, "通过代理和 GitHub 直连下载均失败: "+directErr.Error())
			return
		}
	}

	gz, err := os.Open(gzPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "打开下载文件失败")
		return
	}
	reader, err := gzip.NewReader(gz)
	if err != nil {
		_ = gz.Close()
		writeErr(w, http.StatusBadGateway, "更新包不是有效的 gzip 文件")
		return
	}
	candidate, err := os.CreateTemp(filepath.Dir(binaryPath), ".mihomo-candidate-*")
	if err != nil {
		_ = reader.Close()
		_ = gz.Close()
		writeErr(w, http.StatusInternalServerError, "创建候选二进制失败")
		return
	}
	candidatePath := candidate.Name()
	defer os.Remove(candidatePath)
	_, copyErr := io.Copy(candidate, reader)
	readerErr := reader.Close()
	gzErr := gz.Close()
	if copyErr != nil || readerErr != nil || gzErr != nil {
		_ = candidate.Close()
		writeErr(w, http.StatusBadGateway, "解压 Mihomo 更新包失败")
		return
	}
	if err := candidate.Chmod(0o755); err != nil {
		_ = candidate.Close()
		writeErr(w, http.StatusInternalServerError, "设置候选二进制权限失败")
		return
	}
	if err := candidate.Sync(); err != nil {
		_ = candidate.Close()
		writeErr(w, http.StatusInternalServerError, "写入候选二进制失败")
		return
	}
	if err := candidate.Close(); err != nil {
		writeErr(w, http.StatusInternalServerError, "关闭候选二进制失败")
		return
	}

	candidateOutput, err := exec.Command(candidatePath, "-v").CombinedOutput()
	if err != nil {
		writeErr(w, http.StatusBadGateway, "候选 Mihomo 二进制无法运行: "+strings.TrimSpace(string(candidateOutput)))
		return
	}
	candidateVersion := parseMihomoVersion(candidateOutput)
	if candidateVersion != release.TagName {
		writeErr(w, http.StatusBadGateway, fmt.Sprintf("候选版本校验失败：期望 %s，实际 %s", release.TagName, candidateVersion))
		return
	}
	if err := copyFileAtomic(binaryPath, backupPath); err != nil {
		writeErr(w, http.StatusInternalServerError, "备份当前 Mihomo 失败，未执行更新: "+err.Error())
		return
	}
	if output, err := exec.Command("systemctl", "stop", "mihomo").CombinedOutput(); err != nil {
		writeErr(w, http.StatusInternalServerError, "停止 Mihomo 服务失败，未替换二进制: "+strings.TrimSpace(string(output)))
		return
	}
	if err := os.Rename(candidatePath, binaryPath); err != nil {
		startOutput, startErr := exec.Command("systemctl", "start", "mihomo").CombinedOutput()
		msg := "替换 Mihomo 二进制失败: " + err.Error()
		if startErr != nil {
			msg += "; 旧服务重新启动失败: " + strings.TrimSpace(string(startOutput))
		}
		writeErr(w, http.StatusInternalServerError, msg)
		return
	}
	if output, err := exec.Command("systemctl", "start", "mihomo").CombinedOutput(); err != nil {
		rollbackErr := copyFileAtomic(backupPath, binaryPath)
		restartOutput, restartErr := exec.Command("systemctl", "start", "mihomo").CombinedOutput()
		msg := "新 Mihomo 启动失败: " + strings.TrimSpace(string(output))
		if rollbackErr != nil {
			msg += "; 自动恢复旧二进制失败: " + rollbackErr.Error()
		} else if restartErr != nil {
			msg += "; 已恢复旧二进制，但旧服务启动失败: " + strings.TrimSpace(string(restartOutput))
		} else {
			msg += "; 已恢复旧二进制并重新启动服务"
		}
		writeErr(w, http.StatusInternalServerError, msg)
		return
	}
	if _, err := exec.Command("systemctl", "is-active", "--quiet", "mihomo").CombinedOutput(); err != nil {
		rollbackErr := copyFileAtomic(backupPath, binaryPath)
		restartOutput, restartErr := exec.Command("systemctl", "restart", "mihomo").CombinedOutput()
		msg := "Mihomo 服务启动后未进入 active 状态"
		if rollbackErr != nil {
			msg += "; 自动恢复旧二进制失败: " + rollbackErr.Error()
		} else if restartErr != nil {
			msg += "; 已恢复旧二进制，但重启旧服务失败: " + strings.TrimSpace(string(restartOutput))
		} else {
			msg += "; 已恢复旧二进制并重启服务"
		}
		writeErr(w, http.StatusInternalServerError, msg)
		return
	}

	// A successful systemd start only confirms the unit state, not which version
	// the running Mihomo API actually serves. Verify the live version before ACKing.
	if err := a.waitForMihomoAPIVersion(candidateVersion, 30*time.Second); err != nil {
		rollbackErr := copyFileAtomic(backupPath, binaryPath)
		restartOutput, restartErr := exec.Command("systemctl", "restart", "mihomo").CombinedOutput()
		msg := "Mihomo 更新后运行版本确认失败: " + err.Error()
		if rollbackErr != nil {
			msg += "; 自动恢复旧二进制失败: " + rollbackErr.Error()
		} else if restartErr != nil {
			msg += "; 已恢复旧二进制，但重启旧服务失败: " + strings.TrimSpace(string(restartOutput))
		} else {
			msg += "; 已恢复旧二进制并重启服务"
		}
		writeErr(w, http.StatusBadGateway, msg)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "已更新并确认运行版本为 " + candidateVersion, "status": "updated", "version": candidateVersion})
}

func (a *App) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	// Support both the legacy s5m-next unit and the current s5m-server unit.
	cmd := exec.Command("journalctl", "-u", "s5m-server", "-u", "s5m-next", "-n", "100", "--no-pager", "-o", "short-iso", "--quiet")
	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Warn("读取 S5M systemd 日志失败", "error", err, "output", strings.TrimSpace(string(output)))
		writeJSON(w, http.StatusOK, map[string]string{
			"logs": "无法读取 S5M 服务日志。请确认服务账号具有 systemd-journal 组权限，并检查 s5m-server / s5m-next 服务是否存在。\n" + strings.TrimSpace(string(output)),
		})
		return
	}
	lines := strings.Split(string(output), "\n")
	var result []string
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		line = regexp.MustCompile(`\s+[a-zA-Z0-9.-]+\.bytevirt\.com\s+`).ReplaceAllString(line, " ")
		line = strings.ReplaceAll(line, " systemd[1]: ", " ")
		line = strings.ReplaceAll(line, "s5m-next.service:", "S5M:")
		line = regexp.MustCompile(`time=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?\s*`).ReplaceAllString(line, "")
		if len(line) >= 25 && line[10] == 'T' {
			line = strings.Replace(line[:19], "T", " ", 1) + " " + strings.TrimSpace(line[25:])
		}
		result = append(result, line)
	}
	writeJSON(w, 200, map[string]string{"logs": strings.Join(result, "\n")})
}

func (a *App) handleDownloadBackup(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u == nil || !u.Enabled {
		writeErr(w, http.StatusUnauthorized, "未登录或账号已禁用")
		return
	}
	if u.Role != "admin" {
		writeErr(w, http.StatusForbidden, "需要管理员权限")
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(a.cfg.DBPath), ".s5m-backup-*.db")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "创建数据库快照失败")
		return
	}
	snapshotPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(snapshotPath)
		writeErr(w, http.StatusInternalServerError, "准备数据库快照失败")
		return
	}
	if err := os.Remove(snapshotPath); err != nil {
		writeErr(w, http.StatusInternalServerError, "准备数据库快照失败")
		return
	}
	defer os.Remove(snapshotPath)
	if _, err := a.store.db.ExecContext(r.Context(), "VACUUM INTO ?", snapshotPath); err != nil {
		slog.Error("创建数据库备份快照失败", "error", err)
		writeErr(w, http.StatusInternalServerError, "创建一致性数据库快照失败")
		return
	}
	if err := os.Chmod(snapshotPath, 0600); err != nil {
		writeErr(w, http.StatusInternalServerError, "保护数据库快照权限失败")
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=s5m_backup.db")
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, snapshotPath)
}
func (a *App) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	const maxBackupSize = int64(128 << 20)
	if strings.TrimSpace(a.cfg.DBPath) == "" || a.cfg.DBPath == ":memory:" {
		writeErr(w, http.StatusBadRequest, "当前数据库路径不支持文件恢复")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupSize+(1<<20))
	file, _, err := r.FormFile("file")
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeErr(w, http.StatusRequestEntityTooLarge, "备份上传超过大小限制")
		} else {
			writeErr(w, http.StatusBadRequest, "上传失败：请提供有效的备份文件")
		}
		return
	}
	defer file.Close()
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	dbDir := filepath.Dir(a.cfg.DBPath)
	tmp, err := os.CreateTemp(dbDir, ".s5m-restore-*.db")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "创建恢复临时文件失败")
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	written, copyErr := io.Copy(tmp, io.LimitReader(file, maxBackupSize+1))
	if copyErr != nil {
		_ = tmp.Close()
		writeErr(w, http.StatusBadRequest, "读取备份文件失败")
		return
	}
	if written == 0 || written > maxBackupSize {
		_ = tmp.Close()
		writeErr(w, http.StatusRequestEntityTooLarge, "备份文件为空或超过 128 MiB 限制")
		return
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		writeErr(w, http.StatusInternalServerError, "写入恢复临时文件失败")
		return
	}
	if err := tmp.Close(); err != nil {
		writeErr(w, http.StatusInternalServerError, "关闭恢复临时文件失败")
		return
	}

	// OpenStore validates the SQLite file and applies any compatible schema migrations.
	candidate, err := OpenStore(tmpPath)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "备份不是有效的 S5M 数据库")
		return
	}
	var integrity string
	if err := candidate.db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		_ = candidate.db.Close()
		writeErr(w, http.StatusBadRequest, "备份数据库完整性检查失败")
		return
	}
	users, err := candidate.CountUsers()
	if err != nil || users < 1 {
		_ = candidate.db.Close()
		writeErr(w, http.StatusBadRequest, "备份缺少有效管理员账户，拒绝恢复")
		return
	}
	if err := candidate.db.Close(); err != nil {
		writeErr(w, http.StatusInternalServerError, "关闭校验数据库失败")
		return
	}

	backupFile, err := os.CreateTemp(dbDir, ".s5m-before-restore-*.db")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "创建恢复前备份路径失败")
		return
	}
	backupPath := backupFile.Name()
	if err := backupFile.Close(); err != nil {
		_ = os.Remove(backupPath)
		writeErr(w, http.StatusInternalServerError, "准备恢复前备份失败")
		return
	}
	if err := os.Remove(backupPath); err != nil {
		writeErr(w, http.StatusInternalServerError, "准备恢复前备份失败")
		return
	}
	if err := a.store.db.Close(); err != nil {
		writeErr(w, http.StatusInternalServerError, "关闭当前数据库失败；请重启服务后重试")
		return
	}
	if err := os.Rename(a.cfg.DBPath, backupPath); err != nil {
		writeErr(w, http.StatusInternalServerError, "保留当前数据库失败；请重启服务后检查")
		return
	}
	if err := os.Rename(tmpPath, a.cfg.DBPath); err != nil {
		if rollbackErr := os.Rename(backupPath, a.cfg.DBPath); rollbackErr != nil {
			slog.Error("数据库恢复失败且回滚失败", "restore_error", err, "rollback_error", rollbackErr, "backup", backupPath)
			writeErr(w, http.StatusInternalServerError, "恢复失败且自动回滚失败；请保留备份文件并立即检查服务器")
			return
		}
		writeErr(w, http.StatusInternalServerError, "恢复失败，已恢复原数据库文件；请重启服务")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "数据库恢复成功；恢复前数据库已保存在同目录的备份文件中，请重启面板完成切换",
		"backup":  backupPath,
	})
}

func (a *App) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	s, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取订阅设置失败")
		return
	}
	if s["sub_token"] == "" || r.URL.Query().Get("token") != s["sub_token"] {
		writeErr(w, 403, "无效 token")
		return
	}
	proxies, err := a.store.ListProxies()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取订阅代理失败")
		return
	}
	var outs []proxyOut
	for _, p := range proxies {
		if !p.Enabled || p.Mode == "direct" || p.Mode == "reject" {
			continue
		}
		ex := map[string]any{}
		for k, v := range p.Extra {
			switch k {
			case "name", "type", "server", "port":
				continue
			}
			ex[k] = v
		}
		outs = append(outs, proxyOut{Name: p.Name, Type: p.Type, Server: p.Server, Port: p.Port, Extra: ex})
	}
	b, _ := yaml.Marshal(map[string]any{"proxies": outs, "rules": []string{"MATCH,DIRECT"}})
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Write(b)
}

func decodeProxyBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("Base64 内容无效")
}

func proxyPort(value any) (int, error) {
	switch v := value.(type) {
	case string:
		return strconv.Atoi(strings.TrimSpace(v))
	case float64:
		if v != float64(int(v)) {
			return 0, fmt.Errorf("端口无效")
		}
		return int(v), nil
	case json.Number:
		n, err := v.Int64()
		return int(n), err
	case int:
		return v, nil
	default:
		return 0, fmt.Errorf("缺少有效端口")
	}
}

func parseProxyLine(line string) (*Proxy, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("内容为空")
	}
	p := &Proxy{Mode: "rule", SourceCIDR: "0.0.0.0/0", Enabled: true, Extra: map[string]any{}}
	if idx := strings.LastIndex(line, "#"); idx != -1 {
		name, _ := url.QueryUnescape(line[idx+1:])
		p.Name = strings.TrimSpace(name)
		line = line[:idx]
	}
	schemeIdx := strings.Index(line, "://")
	if schemeIdx == -1 {
		return nil, fmt.Errorf("缺少协议前缀")
	}
	p.Type = strings.ToLower(strings.TrimSpace(line[:schemeIdx]))
	if p.Type == "socks" {
		p.Type = "socks5"
	}
	if p.Type == "https" {
		p.Type = "http"
	}
	if p.Type == "vmess" {
		raw, err := decodeProxyBase64(line[schemeIdx+3:])
		if err != nil {
			return nil, fmt.Errorf("VMess 配置解码失败")
		}
		var vm map[string]any
		if err := json.Unmarshal(raw, &vm); err != nil {
			return nil, fmt.Errorf("VMess 配置 JSON 无效")
		}
		p.Server = strings.TrimSpace(fmt.Sprint(vm["add"]))
		p.Port, err = proxyPort(vm["port"])
		if err != nil {
			return nil, err
		}
		if p.Name == "" {
			p.Name = strings.TrimSpace(fmt.Sprint(vm["ps"]))
		}
		for key, value := range vm {
			switch key {
			case "add", "port", "ps", "v", "aid", "scy", "net", "tls", "sni", "host", "path", "type", "id", "alpn", "fp":
				continue
			}
			p.Extra[key] = value
		}
		if uuid := strings.TrimSpace(fmt.Sprint(vm["id"])); uuid != "" && uuid != "<nil>" {
			p.Extra["uuid"] = uuid
		}
		if cipher := strings.TrimSpace(fmt.Sprint(vm["scy"])); cipher != "" && cipher != "<nil>" {
			p.Extra["cipher"] = cipher
		} else {
			p.Extra["cipher"] = "auto"
		}
		if alterID, err := proxyPort(vm["aid"]); err == nil {
			p.Extra["alterId"] = alterID
		}
		network := strings.TrimSpace(fmt.Sprint(vm["net"]))
		if network != "" && network != "<nil>" {
			p.Extra["network"] = network
			host := strings.TrimSpace(fmt.Sprint(vm["host"]))
			path := strings.TrimSpace(fmt.Sprint(vm["path"]))
			if host == "<nil>" { host = "" }
			if path == "<nil>" { path = "" }
			switch network {
			case "ws":
				ws := map[string]any{}
				if path != "" { ws["path"] = path }
				if host != "" { ws["headers"] = map[string]any{"Host": host} }
				p.Extra["ws-opts"] = ws
			case "grpc":
				if path != "" { p.Extra["grpc-opts"] = map[string]any{"grpc-service-name": path} }
			case "tcp":
				headerType := strings.TrimSpace(fmt.Sprint(vm["type"]))
				if headerType == "http" {
					httpOpts := map[string]any{"method": "GET"}
					if path != "" { httpOpts["path"] = []string{path} }
					if host != "" { httpOpts["headers"] = map[string]any{"Host": []string{host}} }
					p.Extra["http-opts"] = httpOpts
				}
			}
		}
		if tls := strings.TrimSpace(fmt.Sprint(vm["tls"])); tls != "" && tls != "none" && tls != "<nil>" {
			p.Extra["tls"] = true
		}
		if sni := strings.TrimSpace(fmt.Sprint(vm["sni"])); sni != "" && sni != "<nil>" {
			p.Extra["servername"] = sni
		}
		if fingerprint := strings.TrimSpace(fmt.Sprint(vm["fp"])); fingerprint != "" && fingerprint != "<nil>" {
			p.Extra["client-fingerprint"] = fingerprint
		}
		if rawALPN := strings.TrimSpace(fmt.Sprint(vm["alpn"])); rawALPN != "" && rawALPN != "<nil>" {
			alpn := make([]string, 0)
			for _, item := range strings.Split(rawALPN, ",") {
				if item = strings.TrimSpace(item); item != "" { alpn = append(alpn, item) }
			}
			if len(alpn) > 0 { p.Extra["alpn"] = alpn }
		}
	} else if p.Type == "ss" {
		payload := line[schemeIdx+3:]
		if at := strings.LastIndex(payload, "@"); at != -1 {
			auth, hostpart := payload[:at], payload[at+1:]
			if decoded, err := decodeProxyBase64(auth); err == nil {
				auth = string(decoded)
			}
			method, password, ok := strings.Cut(auth, ":")
			if !ok {
				return nil, fmt.Errorf("Shadowsocks 认证信息无效")
			}
			p.Extra["cipher"], p.Extra["password"] = method, password
			payload = hostpart
		} else {
			// SIP002 also permits the entire method:password@host:port to be Base64 encoded.
			decoded, err := decodeProxyBase64(strings.SplitN(payload, "?", 2)[0])
			if err != nil {
				return nil, fmt.Errorf("Shadowsocks URI 缺少认证信息")
			}
			decodedText := string(decoded)
			at = strings.LastIndex(decodedText, "@")
			if at < 0 {
				return nil, fmt.Errorf("Shadowsocks 认证信息无效")
			}
			auth := decodedText[:at]
			method, password, ok := strings.Cut(auth, ":")
			if !ok {
				return nil, fmt.Errorf("Shadowsocks 认证信息无效")
			}
			p.Extra["cipher"], p.Extra["password"] = method, password
			payload = decodedText[at+1:]
		}
		parsed, err := url.Parse("ss://" + payload)
		if err != nil {
			return nil, fmt.Errorf("Shadowsocks URI 无效")
		}
		p.Server = parsed.Hostname()
		p.Port, _ = strconv.Atoi(parsed.Port())
	} else {
		parsed, err := url.Parse(line)
		if err != nil {
			return nil, fmt.Errorf("代理 URI 无效")
		}
		p.Server = parsed.Hostname()
		port, portErr := strconv.Atoi(parsed.Port())
		if portErr != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("端口无效")
		}
		p.Port = port
		if parsed.User != nil {
			user := parsed.User.Username()
			password, hasPassword := parsed.User.Password()
			switch p.Type {
			case "socks5", "http":
				if user != "" {
					p.Extra["username"] = user
				}
				if hasPassword {
					p.Extra["password"] = password
				}
			case "trojan":
				p.Extra["password"] = user
			case "vless", "vmess":
				if user != "" {
					p.Extra["uuid"] = user
				}
			}
		}
		query := parsed.Query()
		if value := query.Get("type"); value != "" {
			p.Extra["network"] = value
		}
		security := strings.ToLower(query.Get("security"))
		if security == "tls" || security == "reality" || query.Get("tls") == "true" {
			p.Extra["tls"] = true
		}
		if sni := query.Get("sni"); sni != "" {
			p.Extra["servername"] = sni
		} else if sni := query.Get("peer"); sni != "" {
			p.Extra["servername"] = sni
		}
		if fp := query.Get("fp"); fp != "" {
			p.Extra["client-fingerprint"] = fp
		}
		if security == "reality" {
			reality := map[string]any{}
			if publicKey := query.Get("pbk"); publicKey != "" { reality["public-key"] = publicKey }
			if shortID := query.Get("sid"); shortID != "" { reality["short-id"] = shortID }
			if len(reality) > 0 { p.Extra["reality-opts"] = reality }
		}
		if flow := query.Get("flow"); flow != "" {
			p.Extra["flow"] = flow
		}
		if network := query.Get("type"); network == "ws" {
			ws := map[string]any{}
			if path := query.Get("path"); path != "" {
				ws["path"] = path
			}
			if host := query.Get("host"); host != "" {
				ws["headers"] = map[string]any{"Host": host}
			}
			p.Extra["ws-opts"] = ws
		} else if network == "grpc" {
			if service := query.Get("serviceName"); service != "" {
				p.Extra["grpc-opts"] = map[string]any{"grpc-service-name": service}
			}
		}
		if method := query.Get("encryption"); method != "" {
			p.Extra["encryption"] = method
		}
		if cipher := query.Get("method"); cipher != "" {
			p.Extra["cipher"] = cipher
		}
		if p.Type == "ss" {
			if parsed.User != nil {
				credential, _ := parsed.User.Password()
				raw := parsed.User.Username()
				if decoded, err := decodeProxyBase64(raw); err == nil {
					raw = string(decoded)
				}
				method, password, ok := strings.Cut(raw, ":")
				if ok {
					p.Extra["cipher"], p.Extra["password"] = method, password
				} else if credential != "" {
					p.Extra["password"] = credential
				}
			}
		}
	}
	if p.Server == "" || p.Port < 1 || p.Port > 65535 {
		return nil, fmt.Errorf("服务器或端口无效")
	}
	if p.Name == "" {
		p.Name = fmt.Sprintf("%s-%s:%d", p.Type, p.Server, p.Port)
	}
	if p.Type == "vless" || p.Type == "vmess" || p.Type == "trojan" || p.Type == "socks5" {
		p.Extra["udp"] = true
	}
	return p, nil
}

func parseProxyImportContent(content string) ([]*Proxy, []string) {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return nil, []string{"导入内容为空"}
	}
	if strings.HasPrefix(trimmed, "{") {
		var input struct {
			Protocol       string `json:"protocol"`
			Authentication struct {
				Enabled  bool   `json:"enabled"`
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"authentication"`
			Servers []struct {
				Server     string `json:"server"`
				Address    string `json:"address"`
				Port       int    `json:"port"`
				Username   string `json:"username"`
				Password   string `json:"password"`
				UDP        bool   `json:"udp"`
				Name       string `json:"name"`
				Remarks    string `json:"remarks"`
				VmessLink  string `json:"vmess_link"`
				UUID       string `json:"uuid"`
				ID         string `json:"id"`
				AlterID    int    `json:"alterId"`
				Cipher     string `json:"cipher"`
				Security   string `json:"security"`
				Network    string `json:"network"`
				TLS        bool   `json:"tls"`
				ServerName string `json:"servername"`
				SNI        string `json:"sni"`
				Host       string `json:"host"`
				Path       string `json:"path"`
			} `json:"servers"`
		}
		if err := json.Unmarshal([]byte(trimmed), &input); err != nil {
			return nil, []string{"JSON 文件格式错误: " + err.Error()}
		}
		protocol := strings.ToLower(strings.TrimSpace(input.Protocol))
		if len(input.Servers) == 0 {
			return nil, []string{"JSON 文件缺少 servers 节点"}
		}
		// Legacy v2rayN exports omit a top-level protocol and use address/id/
		// alterId/security/network fields instead of server/type/protocol.
		if protocol == "" {
			for _, server := range input.Servers {
				if strings.TrimSpace(server.ID) != "" || strings.TrimSpace(server.UUID) != "" {
					if strings.TrimSpace(server.Network) != "" || server.AlterID >= 0 {
						protocol = "vmess"
						break
					}
				}
			}
		}
		if protocol == "" {
			return nil, []string{"JSON 文件缺少 protocol，且无法根据节点字段识别代理协议"}
		}
		proxies := make([]*Proxy, 0, len(input.Servers))
		var failures []string
		for i, server := range input.Servers {
			serverAddress := strings.TrimSpace(server.Server)
			if serverAddress == "" { serverAddress = strings.TrimSpace(server.Address) }
			p := &Proxy{Mode: "rule", Type: protocol, Server: serverAddress, Port: server.Port, SourceCIDR: "0.0.0.0/0", Enabled: true, Extra: map[string]any{}}
			p.Name = strings.TrimSpace(server.Name)
			if p.Name == "" { p.Name = strings.TrimSpace(server.Remarks) }
			// Some provider JSON formats include a complete vmess:// URI per server.
			// Parse that URI through the same tested path used by text imports so UUID,
			// cipher, transport, WebSocket path/Host and TLS/SNI are not discarded.
			if protocol == "vmess" && strings.TrimSpace(server.VmessLink) != "" {
				parsed, err := parseProxyLine(strings.TrimSpace(server.VmessLink))
				if err != nil {
					failures = append(failures, fmt.Sprintf("第 %d 个节点 VMess 链接无效: %s", i+1, err))
					continue
				}
				p = parsed
				p.Mode = "rule"
				p.SourceCIDR = "0.0.0.0/0"
				p.Enabled = true
				if name := strings.TrimSpace(server.Name); name != "" {
					p.Name = name
				}
			} else {
				if p.Name == "" {
					p.Name = fmt.Sprintf("%s-%s:%d", protocol, p.Server, p.Port)
				}
				if protocol == "vmess" {
					uuid := strings.TrimSpace(server.UUID)
					if uuid == "" { uuid = strings.TrimSpace(server.ID) }
					if uuid != "" { p.Extra["uuid"] = uuid }
					if server.AlterID >= 0 {
						p.Extra["alterId"] = server.AlterID
					}
					cipher := strings.TrimSpace(server.Cipher)
					if cipher == "" { cipher = strings.TrimSpace(server.Security) }
					if cipher == "" { cipher = "auto" }
					p.Extra["cipher"] = cipher
					if network := strings.TrimSpace(server.Network); network != "" {
						p.Extra["network"] = network
					}
					if server.TLS {
						p.Extra["tls"] = true
					}
					serverName := strings.TrimSpace(server.ServerName)
					if serverName == "" {
						serverName = strings.TrimSpace(server.SNI)
					}
					if serverName != "" {
						p.Extra["servername"] = serverName
					}
					if strings.EqualFold(strings.TrimSpace(server.Network), "ws") {
						ws := map[string]any{}
						if path := strings.TrimSpace(server.Path); path != "" {
							ws["path"] = path
						}
						if host := strings.TrimSpace(server.Host); host != "" {
							ws["headers"] = map[string]any{"Host": host}
						}
						p.Extra["ws-opts"] = ws
					}
				}
			}
			username, password := server.Username, server.Password
			if username == "" && password == "" && input.Authentication.Enabled {
				username, password = input.Authentication.Username, input.Authentication.Password
			}
			if username != "" {
				p.Extra["username"] = username
			}
			if password != "" {
				p.Extra["password"] = password
			}
			// Preserve URI-derived VMess UDP defaults unless JSON explicitly enables UDP.
			if protocol != "vmess" || server.UDP {
				p.Extra["udp"] = server.UDP
			}
			if msg := (&App{}).validateProxy(p); msg != "" {
				failures = append(failures, fmt.Sprintf("第 %d 个节点失败: %s", i+1, msg))
				continue
			}
			proxies = append(proxies, p)
		}
		return proxies, failures
	}
	var proxies []*Proxy
	var failures []string
	lines := strings.Split(strings.ReplaceAll(trimmed, "\r\n", "\n"), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		p, err := parseProxyLine(line)
		if err != nil {
			failures = append(failures, fmt.Sprintf("第 %d 行失败: %v", i+1, err))
			continue
		}
		if msg := (&App{}).validateProxy(p); msg != "" {
			failures = append(failures, fmt.Sprintf("第 %d 行失败: %s", i+1, msg))
			continue
		}
		proxies = append(proxies, p)
	}
	return proxies, failures
}

func proxyImportFingerprint(p *Proxy) string {
	if p == nil { return "" }
	extra, _ := json.Marshal(p.Extra)
	payload, _ := json.Marshal(struct {
		Type string `json:"type"`
		Server string `json:"server"`
		Port int `json:"port"`
		Extra json.RawMessage `json:"extra"`
	}{Type: strings.ToLower(strings.TrimSpace(p.Type)), Server: strings.ToLower(strings.TrimSpace(p.Server)), Port: p.Port, Extra: extra})
	return string(payload)
}

func filterDuplicateProxyImports(existing []Proxy, incoming []*Proxy) (unique []*Proxy, skipped int) {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	for i := range existing {
		seen[proxyImportFingerprint(&existing[i])] = struct{}{}
	}
	for _, proxy := range incoming {
		key := proxyImportFingerprint(proxy)
		if key == "" { continue }
		if _, ok := seen[key]; ok { skipped++; continue }
		seen[key] = struct{}{}
		unique = append(unique, proxy)
	}
	return unique, skipped
}

func (a *App) handleImportProxies(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Content string `json:"content"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := decode(r, &in); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeErr(w, http.StatusRequestEntityTooLarge, "代理导入请求超过 1 MiB 限制")
		} else {
			writeErr(w, http.StatusBadRequest, "参数错误")
		}
		return
	}
	successCount := 0
	proxies, failReasons := parseProxyImportContent(in.Content)
	existing, err := a.store.ListProxies()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取现有代理列表失败，未执行导入")
		return
	}
	proxies, skippedCount := filterDuplicateProxyImports(existing, proxies)
	for _, p := range proxies {
		if err := a.store.CreateProxy(p); err != nil {
			p.Name = p.Name + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
			if err := a.store.CreateProxy(p); err != nil {
				failReasons = append(failReasons, fmt.Sprintf("节点 %q 存入失败", p.Name))
				continue
			}
		}
		successCount++
	}
	msg := "导入完成"
	if skippedCount > 0 {
		msg = fmt.Sprintf("已跳过 %d 条已存在的相同节点", skippedCount)
	}
	if len(failReasons) > 0 {
		msg = strings.Join(failReasons, "; ")
	}
	syncFailed := false
	if successCount > 0 {
		if err := a.syncAuthorizedNodeConfigs(); err != nil {
			syncFailed = true
			msg = strings.TrimSpace(msg + "; 已导入 " + strconv.Itoa(successCount) + " 条，但节点配置同步失败: " + err.Error())
		}
	}
	writeJSON(w, 200, map[string]any{
		"success":     successCount,
		"fail":        len(failReasons),
		"skipped":     skippedCount,
		"sync_failed": syncFailed,
		"message":     msg,
	})
}

func validateAgentRegistrationInput(machineCode, secret string) (string, string, string) {
	machineCode = strings.TrimSpace(machineCode)
	secret = strings.TrimSpace(secret)
	if len(machineCode) < 1 || len(machineCode) > 64 || !regexp.MustCompile("^[A-Za-z0-9_-]+$").MatchString(machineCode) {
		return machineCode, secret, "机器码格式错误"
	}
	if len(secret) < 1 || len(secret) > 256 {
		return machineCode, secret, "专属 Token 长度无效"
	}
	return machineCode, secret, ""
}

func (a *App) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MachineCode string `json:"machine_code"`
		Secret      string `json:"secret"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	var validationError string
	in.MachineCode, in.Secret, validationError = validateAgentRegistrationInput(in.MachineCode, in.Secret)
	if validationError != "" {
		writeErr(w, http.StatusBadRequest, validationError)
		return
	}
	// Serialize registration with dedicated-token allocation and revocation.
	// Otherwise a registration racing with deletion could receive a freshly
	// minted JWT for a credential that was revoked while the request was in flight.
	agentTokenGenerateMu.Lock()
	defer agentTokenGenerateMu.Unlock()

	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取 Agent 注册配置失败")
		return
	}
	expectedSecret := settings["agent_token"]
	if expectedSecret == "" {
		writeErr(w, 500, "主控台未初始化全局 Token")
		return
	}

	// 只允许预先分配的专属 Token 注册对应机器码。
	machineToken := settings["agent_machine_"+in.MachineCode]
	if strings.TrimSpace(machineToken) == "" ||
		machineToken == expectedSecret ||
		in.Secret == expectedSecret ||
		in.Secret != machineToken {
		writeErr(w, 403, "机器码或专属 Token 不匹配")
		return
	}

	version := fmt.Sprintf("%x", sha256.Sum256([]byte(machineToken)))
	claims := jwt.MapClaims{"sub": in.MachineCode, "role": "agent", "ver": version}
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.jwtKey)
	writeJSON(w, 200, map[string]string{"message": "注册成功", "token": token})
}

func (a *App) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	machineCode, authErr := a.agentMachineFromRequest(r)
	if authErr != nil {
		status := http.StatusUnauthorized
		if strings.HasPrefix(authErr.Error(), "读取 Agent 授权失败:") {
			status = http.StatusInternalServerError
		}
		writeErr(w, status, authErr.Error())
		return
	}

	// Serialize the legacy HTTP config endpoint with Agent revocation, and
	// revalidate after acquiring the lock. Otherwise a request authenticated
	// just before revocation could recreate last-seen state or return config
	// after its binding has been removed.
	a.agentWSMu.Lock()
	defer a.agentWSMu.Unlock()
	currentCode, currentAuthErr := a.agentMachineFromRequest(r)
	if currentAuthErr != nil || currentCode != machineCode {
		writeErr(w, http.StatusUnauthorized, "Agent 授权已失效")
		return
	}

	now := fmt.Sprintf("%d", time.Now().Unix())
	if err := a.store.UpdateSettings(map[string]string{
		"agent_lastseen_" + machineCode: now,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "更新设备心跳失败")
		return
	}

	nodeConfig, err := a.store.GetNodeConfig(machineCode)
	if err != nil {
		slog.Error("读取节点配置失败", "machine_code", machineCode, "error", err)
		writeErr(w, http.StatusInternalServerError, "读取节点配置失败")
		return
	}
	yml := ""
	if nodeConfig != nil {
		// Preserve exact stored bytes so the optimistic compare matches the DB snapshot.
		yml = nodeConfig.YAML
	}
	if strings.TrimSpace(yml) == "" {
		yml, err = a.BuildConfigForMachine(machineCode)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "生成节点配置失败: "+err.Error())
			return
		}
	}
	// Normalize legacy node YAML before delivery so no explicit proxy listener is exposed.
	normalized, normalizeErr := normalizeAgentProxyConfig(yml)
	if normalizeErr != nil {
		writeErr(w, http.StatusInternalServerError, "透明代理配置校正失败")
		return
	}
	if normalized != yml {
		updated, saveErr := a.store.SaveNodeConfigIfUnchanged(machineCode, yml, normalized)
		if saveErr != nil {
			writeErr(w, http.StatusInternalServerError, "保存校正后的节点配置失败")
			return
		}
		if updated {
			yml = normalized
		} else {
			// Do not send a stale config after a concurrent manual save.
			latest, readErr := a.store.GetNodeConfig(machineCode)
			if readErr != nil || latest == nil {
				writeErr(w, http.StatusInternalServerError, "重新读取并发更新后的节点配置失败")
				return
			}
			yml = latest.YAML
		}
	}
	sum := sha256.Sum256([]byte(yml))
	etag := fmt.Sprintf("\"%x\"", sum[:])
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if agentIfNoneMatch(r.Header.Values("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(yml))
}

// agentMachineFromRequest validates the per-machine JWT and confirms its dedicated token is still active.
func (a *App) agentMachineFromRequest(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return "", fmt.Errorf("缺少 Agent Token")
	}
	token, err := jwt.Parse(strings.TrimPrefix(header, "Bearer "), func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("不支持的 JWT 签名算法")
		}
		return a.jwtKey, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || token == nil || !token.Valid {
		return "", fmt.Errorf("无效或已过期的 Agent Token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("Agent Token claims 无效")
	}
	code, codeOK := claims["sub"].(string)
	role, roleOK := claims["role"].(string)
	version, versionOK := claims["ver"].(string)
	if !codeOK || code == "" || !roleOK || role != "agent" || !versionOK || version == "" {
		return "", fmt.Errorf("Agent 身份无效")
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		return "", fmt.Errorf("读取 Agent 授权失败: %w", err)
	}
	machineToken := settings["agent_machine_"+code]
	// A whitespace-only per-Agent token is not an active credential. Keep the
	// exact token bytes for version verification; only use TrimSpace to reject
	// blank values so valid credentials are never silently rewritten.
	if strings.TrimSpace(machineToken) == "" || machineToken == settings["agent_token"] ||
		version != fmt.Sprintf("%x", sha256.Sum256([]byte(machineToken))) {
		return "", fmt.Errorf("Agent 未授权或授权已失效")
	}
	return code, nil
}

// handleAgentMihomoUpdateInfo resolves the official latest stable release for a
// registered Agent's architecture and calculates the checksum from the downloaded
// official release asset. The checksum is never accepted from browser input.
func (a *App) handleAgentMihomoUpdateInfo(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.URL.Query().Get("machine_code"))
	if code == "" {
		writeErr(w, http.StatusBadRequest, "缺少目标机器码")
		return
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取 Agent 设置失败")
		return
	}
	if strings.TrimSpace(settings["agent_machine_"+code]) == "" {
		writeErr(w, http.StatusNotFound, "目标 Agent 未注册")
		return
	}
	// Agent runtime telemetry is stored in settings as agent_status_<machine_code>.
	// The legacy agent_status table was removed with retired container-management
	// telemetry, so OS and architecture must be read from the authenticated heartbeat.
	var status map[string]any
	if raw := settings["agent_status_"+code]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &status); err != nil {
			writeErr(w, http.StatusBadRequest, "Agent 状态数据格式无效，请等待节点重新上报心跳")
			return
		}
	}
	arch, _ := status["arch"].(string)
	arch = strings.ToLower(strings.TrimSpace(arch))
	var assetPattern string
	switch arch {
	case "amd64", "x86_64":
		assetPattern = "mihomo-linux-amd64-compatible-"
	case "arm64", "aarch64":
		assetPattern = "mihomo-linux-arm64-"
	default:
		writeErr(w, http.StatusBadRequest, "Agent 尚未上报受支持的架构，暂不能自动更新")
		return
	}
	client := &http.Client{Timeout: 45 * time.Second}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest", nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "创建官方 Release 请求失败")
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "S5M-Master")
	resp, err := client.Do(req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "查询 Mihomo 官方稳定版本失败: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeErr(w, http.StatusBadGateway, fmt.Sprintf("Mihomo 官方 Release 返回 HTTP %d", resp.StatusCode))
		return
	}
	var release struct {
		TagName string               `json:"tag_name"`
		Assets  []mihomoReleaseAsset `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&release); err != nil {
		writeErr(w, http.StatusBadGateway, "解析官方 Release 失败")
		return
	}
	if !regexp.MustCompile("^v[0-9]+\\.[0-9]+\\.[0-9]+$").MatchString(release.TagName) {
		writeErr(w, http.StatusBadGateway, "官方 Release 版本标签格式无效")
		return
	}
	assetURL, assetName := "", ""
	for _, asset := range release.Assets {
		if strings.HasPrefix(asset.Name, assetPattern) && strings.HasSuffix(asset.Name, ".gz") &&
			!strings.HasSuffix(asset.Name, ".tar.gz") && strings.HasPrefix(asset.BrowserDownloadURL, "https://github.com/MetaCubeX/mihomo/releases/download/") {
			assetURL, assetName = asset.BrowserDownloadURL, asset.Name
			break
		}
	}
	if assetURL == "" {
		writeErr(w, http.StatusBadGateway, "官方 Release 中没有找到匹配 Agent 架构的压缩包")
		return
	}
	assetReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, assetURL, nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "创建内核下载请求失败")
		return
	}
	assetReq.Header.Set("User-Agent", "S5M-Master")
	assetResp, err := client.Do(assetReq)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "下载官方内核以计算 SHA-256 失败: "+err.Error())
		return
	}
	defer assetResp.Body.Close()
	if assetResp.StatusCode != http.StatusOK {
		writeErr(w, http.StatusBadGateway, fmt.Sprintf("官方内核下载返回 HTTP %d", assetResp.StatusCode))
		return
	}
	hash := sha256.New()
	limited := io.LimitReader(assetResp.Body, 128<<20)
	n, err := io.Copy(hash, limited)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "读取官方内核文件失败")
		return
	}
	if n == 0 || n >= 128<<20 {
		writeErr(w, http.StatusBadGateway, "官方内核文件为空或超过 128 MiB 安全限制")
		return
	}
	currentVersion, _ := status["mihomo_version"].(string)
	writeJSON(w, http.StatusOK, map[string]any{
		"machine_code": code, "arch": arch, "current_version": currentVersion,
		"latest_version": release.TagName, "asset_name": assetName,
		"sha256": fmt.Sprintf("%x", hash.Sum(nil)),
	})
}

func (a *App) handleQueueMihomoUpdate(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u == nil || u.Role != "admin" {
		writeErr(w, http.StatusForbidden, "仅管理员可以更新 Agent Mihomo 内核")
		return
	}
	var in struct {
		MachineCode string `json:"machine_code"`
		Version     string `json:"version"`
		SHA256      string `json:"sha256"`
	}
	if err := decodeLimited(r, 8<<10, "8 KiB", &in); err != nil {
		writeErr(w, decodeErrorStatus(err), "请求 JSON 无效")
		return
	}
	if err := a.queueAgentMihomoUpdate(in.MachineCode, in.Version, in.SHA256); err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "未授权") {
			status = http.StatusNotFound
		}
		if strings.Contains(err.Error(), "已有待执行命令") {
			status = http.StatusConflict
		}
		if strings.Contains(err.Error(), "读取 Agent 授权") || strings.Contains(err.Error(), "保存内核更新命令") {
			status = http.StatusInternalServerError
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"message": "更新命令已排队；Agent 在线时会下载、校验并应用指定内核版本"})
}

func (a *App) handleAgentCommand(w http.ResponseWriter, r *http.Request) {
	code, err := a.agentMachineFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Keep command delivery serialized with credential revocation. The second
	// authorization check closes the gap between the initial JWT validation
	// and reading the pending command.
	a.agentWSMu.Lock()
	defer a.agentWSMu.Unlock()
	currentCode, authErr := a.agentMachineFromRequest(r)
	if authErr != nil || currentCode != code {
		writeErr(w, http.StatusUnauthorized, "Agent 授权已失效")
		return
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取 Agent 命令失败")
		return
	}
	if raw := settings["agent_command_"+code]; raw != "" {
		var command map[string]string
		if err := json.Unmarshal([]byte(raw), &command); err != nil {
			writeErr(w, http.StatusInternalServerError, "待执行命令数据损坏")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"command": command})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"command": nil})
}

func (a *App) handleAgentCommandAck(w http.ResponseWriter, r *http.Request) {
	code, err := a.agentMachineFromRequest(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	var in struct {
		ID      string `json:"id"`
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := decodeLimited(r, 8<<10, "8 KiB", &in); err != nil {
		writeErr(w, decodeErrorStatus(err), "命令结果 JSON 无效")
		return
	}
	if strings.TrimSpace(in.ID) == "" || (in.Status != "success" && in.Status != "failed") || len(in.Message) > 2048 {
		writeErr(w, http.StatusBadRequest, "命令 ID、状态或结果消息无效")
		return
	}
	// Serialize ACK persistence with Agent binding revocation, then revalidate
	// the credential while holding the same mutex used by DeleteAgentBinding.
	// The initial authentication above can become stale while the request is decoded.
	a.agentWSMu.Lock()
	currentCode, authErr := a.agentMachineFromRequest(r)
	if authErr != nil || currentCode != code {
		a.agentWSMu.Unlock()
		writeErr(w, http.StatusUnauthorized, "Agent 授权已失效")
		return
	}
	duplicate, matched, err := a.store.AckAgentCommand(code, in.ID, in.Status, in.Message, time.Now().Unix())
	a.agentWSMu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "原子保存命令结果失败")
		return
	}
	if !matched {
		writeErr(w, http.StatusConflict, "命令已被替换或不存在")
		return
	}
	if duplicate {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "duplicate": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAgentHeartbeat stores authenticated per-Agent runtime telemetry.
func (a *App) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	var in map[string]any
	if err := decodeLimited(r, 16<<10, "16 KiB", &in); err != nil {
		writeErr(w, decodeErrorStatus(err), "心跳 JSON 格式错误")
		return
	} else if in == nil {
		writeErr(w, http.StatusBadRequest, "心跳 JSON 格式错误")
		return
	}
	if err := validateAgentWSStatus(in); err != nil {
		writeErr(w, http.StatusBadRequest, "心跳数据无效: "+err.Error())
		return
	}
	code, authErr := a.agentMachineFromRequest(r)
	if authErr != nil {
		status := http.StatusUnauthorized
		if strings.HasPrefix(authErr.Error(), "读取 Agent 授权失败:") {
			status = http.StatusInternalServerError
		}
		writeErr(w, status, authErr.Error())
		return
	}
	receivedAt := time.Now()
	in["received_at"] = receivedAt.Unix()
	payload, err := json.Marshal(in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "心跳字段无法序列化")
		return
	}
	a.agentWSMu.Lock()
	// Authorization may have been revoked while this request waited for the
	// heartbeat lock. Recheck it inside the critical section before persistence.
	currentCode, currentAuthErr := a.agentMachineFromRequest(r)
	if currentAuthErr != nil || currentCode != code {
		a.agentWSMu.Unlock()
		writeErr(w, http.StatusUnauthorized, "Agent 授权已失效")
		return
	}
	if a.agentHeartbeatAt == nil {
		a.agentHeartbeatAt = make(map[string]int64)
	}
	if receivedAt.UnixNano() < a.agentHeartbeatAt[code] {
		a.agentWSMu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "message": "已忽略较旧的 Agent 心跳"})
		return
	}
	if err := a.store.UpdateSettings(map[string]string{
		"agent_lastseen_" + code: strconv.FormatInt(receivedAt.Unix(), 10),
		"agent_status_" + code:   string(payload),
	}); err != nil {
		a.agentWSMu.Unlock()
		writeErr(w, http.StatusInternalServerError, "保存心跳数据失败")
		return
	}
	a.agentHeartbeatAt[code] = receivedAt.UnixNano()
	a.agentWSMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "received_at": time.Now().Unix()})
}

// 删除指定的机器码
func (a *App) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		writeErr(w, 400, "机器码和密钥不能为空")
		return
	}
	// Serialize revocation with token allocation as well as heartbeat persistence.
	// Without the shared token lock, a concurrent generator could insert a new
	// credential after this delete commits, effectively resurrecting the binding.
	agentTokenGenerateMu.Lock()
	defer agentTokenGenerateMu.Unlock()
	a.agentWSMu.Lock()
	if err := a.store.DeleteAgentBinding(code); err != nil {
		a.agentWSMu.Unlock()
		writeErr(w, http.StatusInternalServerError, "删除失败")
		return
	}
	if a.agentWSGeneration == nil {
		a.agentWSGeneration = make(map[string]uint64)
	}
	// Force any existing WebSocket connection to fail its generation check
	// before it can persist another heartbeat.
	a.agentWSGeneration[code]++
	delete(a.agentHeartbeatAt, code)
	// Close the live socket immediately so a revoked idle Agent cannot remain
	// connected until its next heartbeat timeout.
	if session := a.agentWSConnections[code]; session != nil {
		delete(a.agentWSConnections, code)
		if session.conn != nil {
			closeAgentWebSocket(session.conn, "Agent authorization revoked")
		}
	}
	a.agentWSMu.Unlock()

	// Publish only after revocation is committed and the Agent heartbeat lock is released.
	a.publishBrowserEvent(map[string]any{
		"type": "agent.binding.revoked", "machine_code": code, "at": time.Now().Unix(),
	})
	writeJSON(w, 200, map[string]string{"message": "已删除"})
}

// 返回所有已注册的机器码 -> Token 映射
// 依赖 store 里 settings 表的 agent_machine_<code> 键
func (a *App) handleGetAgents(w http.ResponseWriter, r *http.Request) {
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, 500, "读取设置失败: "+err.Error())
		return
	}
	type AgentInfo struct {
		Authorized          bool              `json:"authorized"`
		TokenConfigured     bool              `json:"token_configured"`
		LastSeen            int64             `json:"last_seen"`
		Status              map[string]any    `json:"status,omitempty"`
		CommandResult       map[string]any    `json:"command_result,omitempty"`
		PendingCommand      map[string]string `json:"pending_command,omitempty"`
		DesiredConfigSHA256 string            `json:"desired_config_sha256,omitempty"`
	}
	result := make(map[string]AgentInfo)

	// 1. 收集所有出现过的机器码（来自 agent_machine_ 或 agent_lastseen_）
	codes := make(map[string]bool)
	for k := range settings {
		if strings.HasPrefix(k, "agent_machine_") {
			codes[strings.TrimPrefix(k, "agent_machine_")] = true
		}
		if strings.HasPrefix(k, "agent_lastseen_") {
			codes[strings.TrimPrefix(k, "agent_lastseen_")] = true
		}
	}

	// 2. 仅返回具有有效专属 Token 的设备。
	// 不使用全局 Token 回退，也不展示只有心跳记录的未授权设备。
	for code := range codes {
		token := settings["agent_machine_"+code]
		if strings.TrimSpace(token) == "" || token == settings["agent_token"] {
			continue
		}

		var lastSeen int64
		if tsStr := settings["agent_lastseen_"+code]; tsStr != "" {
			lastSeen, _ = strconv.ParseInt(tsStr, 10, 64)
		}

		var status map[string]any
		if raw := settings["agent_status_"+code]; raw != "" {
			_ = json.Unmarshal([]byte(raw), &status)
		}
		var commandResult map[string]any
		if raw := settings["agent_command_result_"+code]; raw != "" {
			_ = json.Unmarshal([]byte(raw), &commandResult)
		}
		var pendingCommand map[string]string
		if raw := settings["agent_command_"+code]; raw != "" {
			_ = json.Unmarshal([]byte(raw), &pendingCommand)
		}
		info := AgentInfo{
			Authorized: true, TokenConfigured: true, LastSeen: lastSeen, Status: status,
			CommandResult: commandResult, PendingCommand: pendingCommand,
		}
		if nodeConfig, configErr := a.store.GetNodeConfig(code); configErr == nil && nodeConfig != nil && strings.TrimSpace(nodeConfig.YAML) != "" {
			sum := sha256.Sum256([]byte(strings.TrimSpace(nodeConfig.YAML)))
			info.DesiredConfigSHA256 = fmt.Sprintf("%x", sum[:])
		}
		result[code] = info
	}

	writeJSON(w, 200, result)
}

// agentTokenGenerateMu 防止同一进程内并发请求重复分配同一机器码。
var agentTokenGenerateMu sync.Mutex

// 为指定机器码分配专属 Token。
// 已存在的 Token 不会被覆盖；需要更换时应走单独、明确授权的轮换流程。
func (a *App) handleGenerateAgentToken(w http.ResponseWriter, r *http.Request) {
	// 额外检查管理员角色，不能只依赖登录认证。
	u := currentUser(r)
	if u == nil || u.Role != "admin" {
		writeErr(w, http.StatusForbidden, "仅管理员可以生成机器 Token")
		return
	}

	var in struct {
		MachineCode string `json:"machine_code"`
	}

	// 限制请求体大小，避免异常大请求占用资源。
	if err := decodeLimited(r, 8<<10, "8 KiB", &in); err != nil {
		writeErr(w, decodeErrorStatus(err), "JSON 参数错误")
		return
	}

	in.MachineCode = strings.TrimSpace(in.MachineCode)

	// 保留旧机器码兼容性，同时禁止将任意内容拼接进 settings 键名。
	// 新节点仍应使用 11 位十六进制机器码。
	if len(in.MachineCode) < 1 || len(in.MachineCode) > 64 ||
		!regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(in.MachineCode) {
		writeErr(w, http.StatusBadRequest, "机器码格式错误")
		return
	}

	agentTokenGenerateMu.Lock()
	defer agentTokenGenerateMu.Unlock()

	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "读取机器码配置失败")
		return
	}

	globalToken := strings.TrimSpace(settings["agent_token"])
	key := "agent_machine_" + in.MachineCode

	// 不允许用生成接口覆盖已有绑定凭证。
	if existing := strings.TrimSpace(settings[key]); existing != "" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error":        "该机器码已经分配专属 Token，未进行覆盖",
			"machine_code": in.MachineCode,
		})
		return
	}

	// 防止生成结果与全局 Token 相同。
	var token string
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			writeErr(w, http.StatusInternalServerError, "生成随机 Token 失败")
			return
		}
		token = fmt.Sprintf("s5m-%x", buf)
		if token != globalToken {
			break
		}
		token = ""
	}
	if token == "" {
		writeErr(w, http.StatusInternalServerError, "无法生成有效的专属 Token")
		return
	}

	// 原子创建绑定，绝不覆盖已存在的 Token。
	created, err := a.store.CreateSettingIfAbsent(key, token)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "保存 Token 失败")
		return
	}
	if !created {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error":        "该机器码已经分配专属 Token，未进行覆盖",
			"machine_code": in.MachineCode,
		})
		return
	}

	// 回读验证，避免把未成功保存的凭证返回给调用方。
	saved, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "Token 已提交保存，但回读验证失败")
		return
	}
	if saved[key] != token {
		writeErr(w, http.StatusInternalServerError, "Token 保存校验失败")
		return
	}

	a.publishBrowserEvent(map[string]any{
		"type": "agent.binding.updated", "machine_code": in.MachineCode,
		"authorized": true, "at": time.Now().Unix(),
	})
	writeJSON(w, http.StatusOK, map[string]string{
		"message":      "生成成功",
		"machine_code": in.MachineCode,
		"token":        token,
	})
}

// 保存全局配置并下发给 Agent
func (a *App) handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ConfigYaml string `json:"config_yaml"`
	}
	if err := decodeLimited(r, 2<<20, "2 MiB", &in); err != nil {
		if decodeErrorStatus(err) == http.StatusRequestEntityTooLarge {
			writeErr(w, http.StatusRequestEntityTooLarge, "全局配置请求超过 2 MiB 限制")
		} else {
			writeErr(w, http.StatusBadRequest, "请求 JSON 无效")
		}
		return
	}
	if strings.TrimSpace(in.ConfigYaml) == "" {
		writeErr(w, http.StatusBadRequest, "全局 YAML 不能为空")
		return
	}
	var config map[string]any
	if err := yaml.Unmarshal([]byte(in.ConfigYaml), &config); err != nil {
		writeErr(w, http.StatusBadRequest, "全局 YAML 语法错误: "+err.Error())
		return
	}
	if len(config) == 0 {
		writeErr(w, http.StatusBadRequest, "全局 YAML 必须是非空对象")
		return
	}
	if err := a.store.UpdateSettings(map[string]string{"config_yaml": in.ConfigYaml}); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存配置失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "全局配置草稿已保存，尚未发布；这不会自动更新节点独立 YAML"})
}

func (a *App) handleGetNodeConfig(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.PathValue("code"))
	if code == "" {
		writeErr(w, 400, "机器码不能为空")
		return
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, 500, "读取授权状态失败")
		return
	}
	mt := settings["agent_machine_"+code]
	if strings.TrimSpace(mt) == "" || mt == settings["agent_token"] {
		writeErr(w, 404, "节点未授权")
		return
	}
	cfg, err := a.store.GetNodeConfig(code)
	if err != nil {
		writeErr(w, 500, "读取节点配置失败")
		return
	}
	if cfg == nil || strings.TrimSpace(cfg.YAML) == "" {
		yml, buildErr := a.BuildConfigForMachine(code)
		if buildErr != nil {
			writeErr(w, 500, "生成节点默认配置失败: "+buildErr.Error())
			return
		}
		if saveErr := a.store.SaveNodeConfig(code, yml); saveErr != nil {
			writeErr(w, 500, "保存节点默认配置失败")
			return
		}
		cfg, err = a.store.GetNodeConfig(code)
		if err != nil || cfg == nil {
			writeErr(w, 500, "读取刚生成的节点配置失败")
			return
		}
	}
	// Repair stale persisted Agent YAML before returning it to the management UI.
	// Keep the controller/global template untouched and update only this machine's config.
	normalized, normalizeErr := normalizeAgentProxyConfig(cfg.YAML)
	if normalizeErr != nil {
		writeErr(w, http.StatusInternalServerError, "节点配置端口校正失败: "+normalizeErr.Error())
		return
	}
	if normalized != cfg.YAML {
		updated, saveErr := a.store.SaveNodeConfigIfUnchanged(code, cfg.YAML, normalized)
		if saveErr != nil {
			writeErr(w, http.StatusInternalServerError, "保存校正后的节点配置失败")
			return
		}
		if updated {
			// Keep any existing template/independent binding metadata intact; only refresh its config hash.
			cfg.YAML = normalized
		} else {
			// A manual save won the race. Return the latest YAML instead of the stale snapshot.
			cfg, err = a.store.GetNodeConfig(code)
			if err != nil || cfg == nil {
				writeErr(w, http.StatusInternalServerError, "重新读取并发更新后的节点配置失败")
				return
			}
		}
	}
	writeJSON(w, 200, cfg)
}

func (a *App) handleSaveNodeConfig(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.PathValue("code"))
	if code == "" {
		writeErr(w, 400, "机器码不能为空")
		return
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, 500, "读取授权状态失败")
		return
	}
	mt := settings["agent_machine_"+code]
	if strings.TrimSpace(mt) == "" || mt == settings["agent_token"] {
		writeErr(w, 404, "节点未授权")
		return
	}
	var in struct {
		YAML string `json:"config_yaml"`
	}
	if err := decodeLimited(r, 2<<20, "2 MiB", &in); err != nil {
		if strings.Contains(err.Error(), "2 MiB") {
			writeErr(w, http.StatusRequestEntityTooLarge, "节点配置请求超过 2 MiB 限制")
		} else {
			writeErr(w, http.StatusBadRequest, "请求 JSON 无效")
		}
		return
	}
	if strings.TrimSpace(in.YAML) == "" {
		writeErr(w, 400, "YAML 不能为空")
		return
	}
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(in.YAML), &cfg); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("Mihomo YAML 解析失败：%v", err))
		return
	}
	if len(cfg) == 0 {
		writeErr(w, http.StatusBadRequest, "Mihomo YAML 配置为空：至少需要一个顶层配置项")
		return
	}
	secret, _ := cfg["secret"].(string)
	if strings.TrimSpace(secret) == "" {
		writeErr(w, 400, "完整配置必须包含非空 secret")
		return
	}
	if _, ok := cfg["tun"]; !ok {
		writeErr(w, 400, "完整配置缺少 tun 配置块；关闭 TUN 时也应设置 tun.enable: false")
		return
	}
	if _, ok := cfg["dns"]; !ok {
		writeErr(w, 400, "完整配置缺少 dns 配置块")
		return
	}
	normalizedYAML, normalizeErr := normalizeAgentProxyConfig(in.YAML)
	if normalizeErr != nil {
		writeErr(w, http.StatusBadRequest, "透明代理配置校验失败: "+normalizeErr.Error())
		return
	}
	if err := a.store.SaveNodeConfig(code, normalizedYAML); err != nil {
		writeErr(w, 500, "保存节点配置失败")
		return
	}
	// Persist the exact normalized bytes that the Agent will receive and hash.
	_, _ = a.store.db.Exec("INSERT INTO node_template_bindings(machine_code, template_version, config_sha256, source, updated_at) VALUES(?, 0, ?, 'independent', ?) ON CONFLICT(machine_code) DO UPDATE SET template_version=0, config_sha256=excluded.config_sha256, source='independent', updated_at=excluded.updated_at", code, hashConfig(normalizedYAML), time.Now().UTC().Format(time.RFC3339))
	writeJSON(w, 200, map[string]string{"message": "完整节点配置已保存为独立配置；Agent 将在下一次拉取时应用"})
}

// handleRetryNodeConfigSync regenerates cached node YAML for all authorized Agents.
// The Agent applies the refreshed config when it next polls the config endpoint.
func (a *App) handleRetryNodeConfigSync(w http.ResponseWriter, _ *http.Request) {
	if err := a.syncAuthorizedNodeConfigs(); err != nil {
		writeErr(w, http.StatusInternalServerError, "节点配置同步失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "已重新生成并保存所有已授权节点的配置；在线 Agent 将在下次拉取时应用",
	})
}


// agentIfNoneMatch implements the weak comparison required by If-None-Match
// for GET requests. Commas inside a quoted opaque-tag are not list separators.
func agentIfNoneMatch(values []string, currentETag string) bool {
	for _, value := range values {
		for i := 0; i < len(value); {
			for i < len(value) && (value[i] == ' ' || value[i] == '\t' || value[i] == ',') {
				i++
			}
			if i >= len(value) {
				break
			}
			if value[i] == '*' {
				i++
				for i < len(value) && (value[i] == ' ' || value[i] == '\t') {
					i++
				}
				if i == len(value) || value[i] == ',' {
					return true
				}
				continue
			}

			weak := false
			if strings.HasPrefix(value[i:], "W/") {
				weak = true
				i += 2
			}
			if i >= len(value) || value[i] != '"' {
				for i < len(value) && value[i] != ',' {
					i++
				}
				continue
			}
			start := i
			i++
			for i < len(value) && value[i] != '"' {
				// entity-tag opaque characters exclude controls and DEL.
				if value[i] < 0x21 || value[i] == 0x7f {
					break
				}
				i++
			}
			if i >= len(value) || value[i] != '"' {
				for i < len(value) && value[i] != ',' {
					i++
				}
				continue
			}
			i++
			candidate := value[start:i]
			for i < len(value) && (value[i] == ' ' || value[i] == '\t') {
				i++
			}
			if (i == len(value) || value[i] == ',') && candidate == currentETag {
				_ = weak // GET If-None-Match uses weak comparison for both forms.
				return true
			}
		}
	}
	return false
}
