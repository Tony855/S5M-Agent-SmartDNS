package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// defaultMihomoTemplate is shown when no draft has been saved yet. It is a
// safe starter template based on the project's generated configuration shape.
// Replace the example proxy endpoint and secret before applying it to a node.
const defaultMihomoTemplate = `# 透明代理：不开放 HTTP/SOCKS 显式代理端口
allow-lan: false
mode: rule
log-level: info
ipv6: false

# 控制接口
external-controller: 127.0.0.1:8088
secret: "REPLACE_WITH_A_UNIQUE_RANDOM_SECRET"

# 状态持久化
profile:
  store-selected: true
  store-fake-ip: true

# DNS 设置
dns:
  enable: true
  listen: 127.0.0.1:5353
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "+.v2net.cc"
  nameserver:
    - 223.5.5.5
    - 119.29.29.29

# 代理节点与代理组
proxies: []
proxy-groups: []

# 分流规则
rules:
  - DOMAIN-SUFFIX,v2net.cc,DIRECT
  - MATCH,DIRECT

# TUN 设置
tun:
  enable: false
  stack: system
  auto-route: true
  auto-detect-interface: true
`

type mihomoTemplateVersion struct {
	Version   int    `json:"version"`
	SHA256    string `json:"sha256"`
	Note      string `json:"note"`
	CreatedAt string `json:"created_at"`
}

func (a *App) ensureTemplateSchema() error {
	_, err := a.store.db.Exec(`
CREATE TABLE IF NOT EXISTS mihomo_template_versions (
 version INTEGER PRIMARY KEY,
 yaml_text TEXT NOT NULL,
 sha256 TEXT NOT NULL,
 note TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS node_template_bindings (
 machine_code TEXT PRIMARY KEY,
 template_version INTEGER NOT NULL DEFAULT 0,
 config_sha256 TEXT NOT NULL DEFAULT '',
 source TEXT NOT NULL DEFAULT 'independent',
 updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS node_template_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 machine_code TEXT NOT NULL,
 previous_yaml TEXT NOT NULL,
 previous_template_version INTEGER NOT NULL DEFAULT 0,
 previous_source TEXT NOT NULL DEFAULT 'independent',
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_node_template_history_machine ON node_template_history(machine_code, id DESC);
`)
	return err
}

func validateMihomoTemplate(yml string) error {
	if strings.TrimSpace(yml) == "" {
		return fmt.Errorf("模板 YAML 不能为空")
	}
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(yml), &cfg); err != nil {
		return fmt.Errorf("YAML 语法错误: %w", err)
	}
	if len(cfg) == 0 {
		return fmt.Errorf("模板配置不能为空")
	}
	if secret, ok := cfg["secret"]; ok {
		if value, ok := secret.(string); !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("secret 必须是非空字符串")
		}
	}
	if tun, ok := cfg["tun"]; ok {
		if _, ok := tun.(map[string]any); !ok {
			return fmt.Errorf("tun 必须是 YAML 配置块")
		}
	}
	if dns, ok := cfg["dns"]; ok {
		if _, ok := dns.(map[string]any); !ok {
			return fmt.Errorf("dns 必须是 YAML 配置块")
		}
	}
	return nil
}

func hashConfig(yml string) string {
	sum := sha256.Sum256([]byte(yml))
	return hex.EncodeToString(sum[:])
}

func (a *App) handleGetMihomoTemplate(w http.ResponseWriter, r *http.Request) {
	draft, _ := a.store.GetSetting("mihomo_template_draft")
	currentRaw, _ := a.store.GetSetting("mihomo_template_current_version")
	current := 0
	fmt.Sscanf(currentRaw, "%d", &current)
	rows, err := a.store.db.Query("SELECT version, sha256, note, created_at FROM mihomo_template_versions ORDER BY version DESC")
	if err != nil {
		writeErr(w, 500, "读取模板版本失败")
		return
	}
	defer rows.Close()
	versions := make([]mihomoTemplateVersion, 0)
	for rows.Next() {
		var v mihomoTemplateVersion
		if err := rows.Scan(&v.Version, &v.SHA256, &v.Note, &v.CreatedAt); err != nil {
			writeErr(w, 500, "读取模板版本失败")
			return
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, 500, "读取模板版本失败")
		return
	}
	if strings.TrimSpace(draft) == "" {
		// Do not persist the starter until the administrator explicitly saves it.
		draft = defaultMihomoTemplate
	}
	writeJSON(w, 200, map[string]any{"draft_yaml": draft, "current_version": current, "versions": versions})
}

func (a *App) handleSaveMihomoTemplateDraft(w http.ResponseWriter, r *http.Request) {
	var in struct {
		YAML string `json:"yaml"`
	}
	if err := decodeLimited(r, 2<<20, "2 MiB", &in); err != nil {
		writeErr(w, 400, "请求 JSON 无效或超过 2 MiB")
		return
	}
	if err := validateMihomoTemplate(in.YAML); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := a.store.UpdateSettings(map[string]string{"mihomo_template_draft": in.YAML}); err != nil {
		writeErr(w, 500, "保存模板草稿失败")
		return
	}
	writeJSON(w, 200, map[string]string{"message": "模板草稿已保存；尚未发布，也不会覆盖任何节点"})
}

func (a *App) handlePublishMihomoTemplate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Note string `json:"note"`
	}
	if r.Body != nil {
		_ = decodeLimited(r, 16<<10, "16 KiB", &in)
	}
	draft, err := a.store.GetSetting("mihomo_template_draft")
	if err != nil || strings.TrimSpace(draft) == "" {
		writeErr(w, 400, "请先保存模板草稿")
		return
	}
	if err := validateMihomoTemplate(draft); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	tx, err := a.store.db.Begin()
	if err != nil {
		writeErr(w, 500, "创建模板版本失败")
		return
	}
	defer tx.Rollback()
	var current int
	_ = tx.QueryRow("SELECT COALESCE(MAX(version),0) FROM mihomo_template_versions").Scan(&current)
	next := current + 1
	created := time.Now().UTC().Format(time.RFC3339)
	if _, err = tx.Exec("INSERT INTO mihomo_template_versions(version,yaml_text,sha256,note,created_at) VALUES(?,?,?,?,?)", next, draft, hashConfig(draft), strings.TrimSpace(in.Note), created); err != nil {
		writeErr(w, 500, "发布模板版本失败")
		return
	}
	if _, err = tx.Exec("INSERT INTO settings(key,value) VALUES('mihomo_template_current_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", fmt.Sprint(next)); err != nil {
		writeErr(w, 500, "更新当前模板版本失败")
		return
	}
	if err = tx.Commit(); err != nil {
		writeErr(w, 500, "提交模板版本失败")
		return
	}
	writeJSON(w, 200, map[string]any{"message": "模板已发布；已有节点不会自动更新", "version": next, "sha256": hashConfig(draft)})
}

// handleDeleteMihomoTemplateVersion removes only an unused historical template version.
func (a *App) handleDeleteMihomoTemplateVersion(w http.ResponseWriter, r *http.Request) {
	version, err := strconv.Atoi(strings.TrimSpace(r.PathValue("version")))
	if err != nil || version < 1 {
		writeErr(w, http.StatusBadRequest, "模板版本号无效")
		return
	}

	// Load settings before opening the transaction. The SQLite store may use
	// a single connection; calling Store.GetSettings while a transaction is
	// active can wait forever for that same connection.
	settings, settingsErr := a.store.GetSettings()
	if settingsErr != nil {
		writeErr(w, http.StatusInternalServerError, "读取节点授权状态失败")
		return
	}

	tx, err := a.store.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "开始删除模板版本事务失败")
		return
	}
	defer tx.Rollback()

	var currentRaw string
	if err := tx.QueryRowContext(r.Context(), "SELECT value FROM settings WHERE key='mihomo_template_current_version'").Scan(&currentRaw); err != nil {
		if err == sql.ErrNoRows {
			writeErr(w, http.StatusInternalServerError, "当前模板版本记录缺失，拒绝删除")
		} else {
			writeErr(w, http.StatusInternalServerError, "读取当前模板版本失败")
		}
		return
	}
	currentRaw = strings.TrimSpace(currentRaw)
	current, err := strconv.Atoi(currentRaw)
	if err != nil || current < 1 {
		writeErr(w, http.StatusInternalServerError, "当前模板版本记录无效，拒绝删除")
		return
	}
	if version == current {
		writeErr(w, http.StatusConflict, "不能删除当前发布版本；请先发布新版本")
		return
	}

	var exists int
	if err := tx.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM mihomo_template_versions WHERE version=?", version).Scan(&exists); err != nil {
		writeErr(w, http.StatusInternalServerError, "检查模板版本失败")
		return
	}
	if exists == 0 {
		writeErr(w, http.StatusNotFound, "模板版本不存在")
		return
	}

	rows, err := tx.QueryContext(r.Context(),
		"SELECT machine_code FROM node_template_bindings WHERE source='template' AND template_version=? ORDER BY machine_code", version)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "检查节点模板绑定失败")
		return
	}
	boundNodes := make([]string, 0)
	for rows.Next() {
		var machineCode string
		if err := rows.Scan(&machineCode); err != nil {
			rows.Close()
			writeErr(w, http.StatusInternalServerError, "读取节点模板绑定失败")
			return
		}
		// A binding is blocking deletion only while the machine has a valid
		// dedicated Agent credential. Deleted/revoked machines may leave legacy
		// rows behind from older versions; remove those orphan bindings safely.
		token := strings.TrimSpace(settings["agent_machine_"+machineCode])
		globalToken := strings.TrimSpace(settings["agent_token"])
		// Only infer a deleted/revoked machine when the server has a configured
		// global Agent token. In minimal test/legacy databases without that
		// setting, missing per-machine credentials are not enough to prove that
		// a binding is orphaned, so retain the safe blocking behavior.
		if globalToken != "" && (token == "" || token == globalToken) {
			if _, err := tx.ExecContext(r.Context(),
				"DELETE FROM node_template_bindings WHERE machine_code=? AND source='template' AND template_version=?",
				machineCode, version); err != nil {
				rows.Close()
				writeErr(w, http.StatusInternalServerError, "清理已删除节点的遗留模板绑定失败")
				return
			}
			continue
		}
		boundNodes = append(boundNodes, machineCode)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		writeErr(w, http.StatusInternalServerError, "读取节点模板绑定失败")
		return
	}
	rows.Close()
	if len(boundNodes) > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":       fmt.Sprintf("模板 v%d 仍被 %d 个节点绑定，不能删除", version, len(boundNodes)),
			"version":     version,
			"bound_nodes": boundNodes,
			"message":     "请先将这些节点迁移到其他模板版本或改为独立配置",
		})
		return
	}

	result, err := tx.ExecContext(r.Context(), "DELETE FROM mihomo_template_versions WHERE version=?", version)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "删除模板版本失败")
		return
	}
	affected, err := result.RowsAffected()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "确认模板版本删除结果失败")
		return
	}
	if affected == 0 {
		writeErr(w, http.StatusNotFound, "模板版本不存在")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, http.StatusInternalServerError, "提交模板版本删除失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"message": fmt.Sprintf("模板历史版本 v%d 已删除", version), "version": version})
}

func (a *App) handleGetNodeTemplateStatus(w http.ResponseWriter, r *http.Request) {
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, 500, "读取节点授权状态失败")
		return
	}
	current := 0
	fmt.Sscanf(settings["mihomo_template_current_version"], "%d", &current)
	rows, err := a.store.db.Query("SELECT machine_code, template_version, config_sha256, source, updated_at FROM node_template_bindings")
	if err != nil {
		writeErr(w, 500, "读取节点模板状态失败")
		return
	}
	defer rows.Close()
	type state struct {
		MachineCode     string `json:"machine_code"`
		TemplateVersion int    `json:"template_version"`
		LatestVersion   int    `json:"latest_version"`
		ConfigSHA256    string `json:"config_sha256"`
		Source          string `json:"source"`
		Status          string `json:"status"`
		UpdatedAt       string `json:"updated_at"`
	}
	bindings := map[string]state{}
	for rows.Next() {
		var s state
		if err := rows.Scan(&s.MachineCode, &s.TemplateVersion, &s.ConfigSHA256, &s.Source, &s.UpdatedAt); err != nil {
			writeErr(w, 500, "读取节点模板状态失败")
			return
		}
		s.LatestVersion = current
		if s.Source == "independent" {
			s.Status = "independent"
		} else if s.TemplateVersion < current {
			s.Status = "outdated"
		} else {
			s.Status = "current"
		}
		bindings[s.MachineCode] = s
	}
	codes := make([]string, 0)
	for key, value := range settings {
		if strings.HasPrefix(key, "agent_machine_") && value != "" && value != settings["agent_token"] {
			codes = append(codes, strings.TrimPrefix(key, "agent_machine_"))
		}
	}
	sort.Strings(codes)
	out := make([]state, 0, len(codes))
	for _, code := range codes {
		s, ok := bindings[code]
		if !ok {
			s = state{MachineCode: code, LatestVersion: current, Source: "untracked", Status: "untracked"}
		}
		// Compare the stored configuration hash to identify manual edits after template application.
		if s.Source != "untracked" && s.Source != "independent" {
			if cfg, e := a.store.GetNodeConfig(code); e == nil && cfg != nil && hashConfig(cfg.YAML) != s.ConfigSHA256 {
				s.Status = "drifted"
			}
		}
		out = append(out, s)
	}
	writeJSON(w, 200, map[string]any{"current_version": current, "nodes": out})
}

func (a *App) handleApplyMihomoTemplate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MachineCode string `json:"machine_code"`
		Version     int    `json:"version"`
		Confirm     bool   `json:"confirm"`
	}
	if err := decodeLimited(r, 16<<10, "16 KiB", &in); err != nil {
		writeErr(w, 400, "请求 JSON 无效")
		return
	}
	code := strings.TrimSpace(in.MachineCode)
	if code == "" || in.Version < 1 {
		writeErr(w, 400, "必须选择节点和有效模板版本")
		return
	}
	if !in.Confirm {
		writeErr(w, 400, "必须明确确认覆盖所选节点配置")
		return
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, 500, "读取节点授权状态失败")
		return
	}
	mt := settings["agent_machine_"+code]
	if mt == "" || mt == settings["agent_token"] {
		writeErr(w, 404, "节点未授权")
		return
	}
	var template string
	if err := a.store.db.QueryRow("SELECT yaml_text FROM mihomo_template_versions WHERE version=?", in.Version).Scan(&template); err != nil {
		if err == sql.ErrNoRows {
			writeErr(w, 404, "模板版本不存在")
		} else {
			writeErr(w, 500, "读取模板版本失败")
		}
		return
	}
	// Normalize every applied node template to transparent-only listeners before saving.
	normalizedTemplate, normalizeErr := normalizeAgentProxyConfig(template)
	if normalizeErr != nil {
		writeErr(w, 400, "模板不能应用: "+normalizeErr.Error())
		return
	}
	template = normalizedTemplate
	if err := validateMihomoTemplate(template); err != nil {
		writeErr(w, 400, "模板不能应用: "+err.Error())
		return
	}
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(template), &cfg); err != nil {
		writeErr(w, 400, "模板 YAML 无效")
		return
	}
	if secret, ok := cfg["secret"].(string); !ok || strings.TrimSpace(secret) == "" {
		writeErr(w, 400, "应用到节点的完整配置必须包含非空 secret")
		return
	}
	if _, ok := cfg["tun"]; !ok {
		writeErr(w, 400, "应用到节点的完整配置必须包含 tun 配置块")
		return
	}
	if _, ok := cfg["dns"]; !ok {
		writeErr(w, 400, "应用到节点的完整配置必须包含 dns 配置块")
		return
	}
	tx, err := a.store.db.Begin()
	if err != nil {
		writeErr(w, 500, "开始应用模板事务失败")
		return
	}
	defer tx.Rollback()
	var oldYAML string
	_ = tx.QueryRow("SELECT yaml_text FROM node_configs WHERE machine_code=?", code).Scan(&oldYAML)
	var oldVersion int
	var oldSource string
	_ = tx.QueryRow("SELECT template_version,source FROM node_template_bindings WHERE machine_code=?", code).Scan(&oldVersion, &oldSource)
	if oldSource == "" {
		oldSource = "independent"
	}
	if strings.TrimSpace(oldYAML) != "" {
		if _, err = tx.Exec("INSERT INTO node_template_history(machine_code,previous_yaml,previous_template_version,previous_source,created_at) VALUES(?,?,?,?,?)", code, oldYAML, oldVersion, oldSource, time.Now().UTC().Format(time.RFC3339)); err != nil {
			writeErr(w, 500, "备份原节点配置失败")
			return
		}
		if _, err = tx.Exec("DELETE FROM node_template_history WHERE machine_code=? AND id NOT IN (SELECT id FROM node_template_history WHERE machine_code=? ORDER BY id DESC LIMIT 20)", code, code); err != nil {
			writeErr(w, 500, "清理旧节点配置备份失败")
			return
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err = tx.Exec("INSERT INTO node_configs(machine_code,yaml_text,updated_at) VALUES(?,?,?) ON CONFLICT(machine_code) DO UPDATE SET yaml_text=excluded.yaml_text,updated_at=excluded.updated_at", code, template, now); err != nil {
		writeErr(w, 500, "保存节点配置失败")
		return
	}
	if _, err = tx.Exec("INSERT INTO node_template_bindings(machine_code,template_version,config_sha256,source,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(machine_code) DO UPDATE SET template_version=excluded.template_version,config_sha256=excluded.config_sha256,source=excluded.source,updated_at=excluded.updated_at", code, in.Version, hashConfig(template), "template", now); err != nil {
		writeErr(w, 500, "保存节点模板版本信息失败")
		return
	}
	if err = tx.Commit(); err != nil {
		writeErr(w, 500, "提交节点模板配置失败")
		return
	}
	writeJSON(w, 200, map[string]any{"message": "模板已应用到所选节点；原配置已备份，Agent 将在下一次拉取时获取配置", "machine_code": code, "template_version": in.Version})
}

// Ensure the file's JSON contract stays explicit for future API evolution.
var _ = json.Valid

func (a *App) handleRollbackNodeTemplate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MachineCode string `json:"machine_code"`
		Confirm     bool   `json:"confirm"`
	}
	if err := decodeLimited(r, 16<<10, "16 KiB", &in); err != nil {
		writeErr(w, 400, "请求 JSON 无效")
		return
	}
	code := strings.TrimSpace(in.MachineCode)
	if code == "" || !in.Confirm {
		writeErr(w, 400, "必须选择节点并明确确认恢复")
		return
	}
	settings, err := a.store.GetSettings()
	if err != nil {
		writeErr(w, 500, "读取节点授权状态失败")
		return
	}
	mt := settings["agent_machine_"+code]
	if mt == "" || mt == settings["agent_token"] {
		writeErr(w, 404, "节点未授权")
		return
	}
	tx, err := a.store.db.Begin()
	if err != nil {
		writeErr(w, 500, "开始恢复事务失败")
		return
	}
	defer tx.Rollback()

	var historyID int64
	var previousYAML, previousSource string
	var previousVersion int
	err = tx.QueryRow("SELECT id, previous_yaml, previous_template_version, previous_source FROM node_template_history WHERE machine_code=? ORDER BY id DESC LIMIT 1", code).Scan(&historyID, &previousYAML, &previousVersion, &previousSource)
	if err != nil {
		if err == sql.ErrNoRows {
			writeErr(w, 404, "该节点没有可恢复的配置备份")
		} else {
			writeErr(w, 500, "读取节点配置备份失败")
		}
		return
	}
	var currentYAML string
	_ = tx.QueryRow("SELECT yaml_text FROM node_configs WHERE machine_code=?", code).Scan(&currentYAML)
	var currentVersion int
	var currentSource string
	_ = tx.QueryRow("SELECT template_version, source FROM node_template_bindings WHERE machine_code=?", code).Scan(&currentVersion, &currentSource)
	if strings.TrimSpace(currentSource) == "" {
		currentSource = "independent"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if strings.TrimSpace(currentYAML) != "" {
		if _, err := tx.Exec("INSERT INTO node_template_history(machine_code,previous_yaml,previous_template_version,previous_source,created_at) VALUES(?,?,?,?,?)", code, currentYAML, currentVersion, currentSource, now); err != nil {
			writeErr(w, 500, "备份当前节点配置失败")
			return
		}
		if _, err := tx.Exec("DELETE FROM node_template_history WHERE machine_code=? AND id NOT IN (SELECT id FROM node_template_history WHERE machine_code=? ORDER BY id DESC LIMIT 20)", code, code); err != nil {
			writeErr(w, 500, "清理旧节点配置备份失败")
			return
		}
	}
	if _, err := tx.Exec("UPDATE node_configs SET yaml_text=?, updated_at=? WHERE machine_code=?", previousYAML, now, code); err != nil {
		writeErr(w, 500, "恢复节点配置失败")
		return
	}
	if _, err := tx.Exec("INSERT INTO node_template_bindings(machine_code,template_version,config_sha256,source,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(machine_code) DO UPDATE SET template_version=excluded.template_version,config_sha256=excluded.config_sha256,source=excluded.source,updated_at=excluded.updated_at", code, previousVersion, hashConfig(previousYAML), previousSource, now); err != nil {
		writeErr(w, 500, "恢复节点模板版本信息失败")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 500, "提交节点配置恢复失败")
		return
	}
	writeJSON(w, 200, map[string]any{"message": "已恢复节点最近一次配置备份；恢复前配置也已备份，可再次恢复", "machine_code": code, "template_version": previousVersion, "history_id": historyID})
}

// handleValidateMihomoTemplate validates YAML structure first, then asks the
// installed Mihomo binary to parse the candidate without restarting the service.
func (a *App) handleValidateMihomoTemplate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		YAML string `json:"yaml"`
	}
	if err := decodeLimited(r, 2<<20, "2 MiB", &in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求 JSON 无效或超过 2 MiB")
		return
	}
	if err := validateMihomoTemplate(in.YAML); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	const binaryPath = "/opt/mihomo/mihomo"
	info, err := os.Stat(binaryPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		writeErr(w, http.StatusServiceUnavailable, "未找到可执行的主控 Mihomo 内核，无法进行真实内核校验；当前仅完成 YAML 基础校验")
		return
	}
	file, err := os.CreateTemp("", "s5m-mihomo-validate-*.yaml")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "创建临时校验文件失败")
		return
	}
	path := filepath.Clean(file.Name())
	defer os.Remove(path)
	if _, err := file.WriteString(in.YAML); err != nil {
		_ = file.Close()
		writeErr(w, http.StatusInternalServerError, "写入临时校验文件失败")
		return
	}
	if err := file.Close(); err != nil {
		writeErr(w, http.StatusInternalServerError, "关闭临时校验文件失败")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, "-t", "-f", path)
	output, runErr := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		writeErr(w, http.StatusGatewayTimeout, "Mihomo 配置校验超过 10 秒，已终止校验进程")
		return
	}
	if runErr != nil {
		detail := strings.TrimSpace(string(output))
		if len(detail) > 3000 {
			detail = detail[:3000]
		}
		if detail == "" {
			detail = runErr.Error()
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":        "Mihomo 内核拒绝此配置",
			"detail":       detail,
			"validated_by": "local-mihomo-binary",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message":      "Mihomo 内核配置校验通过；未重启或修改正在运行的服务",
		"validated_by": "local-mihomo-binary",
		"output":       strings.TrimSpace(string(output)),
	})
}
