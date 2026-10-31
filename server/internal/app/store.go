package app

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"`
	Enabled      bool   `json:"enabled"`
}

type Instance struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	MachineCode string `json:"machine_code"`
	APIURL      string `json:"api_url"`
}

type Proxy struct {
	ID          int64          `json:"id"`
	Name        string         `json:"name"`
	Mode        string         `json:"mode"`
	Type        string         `json:"type"`
	Server      string         `json:"server"`
	Port        int            `json:"port"`
	SourceCIDR  string         `json:"source_cidr"`
	MachineCode string         `json:"machine_code"`
	Extra       map[string]any `json:"extra"`
	Enabled     bool           `json:"enabled"`
}

type ConfigVersion struct {
	ID        int64  `json:"id"`
	Version   int    `json:"version"`
	SHA256    string `json:"sha256"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'admin',
 enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS instances(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL UNIQUE,
 machine_code TEXT NOT NULL DEFAULT '',
 api_url TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS proxies(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL UNIQUE,
 mode TEXT NOT NULL DEFAULT 'proxy',
 type TEXT NOT NULL,
 server TEXT NOT NULL,
 port INTEGER NOT NULL,
 source_cidr TEXT NOT NULL DEFAULT '0.0.0.0/0',
 machine_code TEXT NOT NULL DEFAULT '',
 config_json TEXT NOT NULL DEFAULT '{}',
 enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS config_versions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 version INTEGER NOT NULL UNIQUE,
 sha256 TEXT NOT NULL,
 yaml_text TEXT NOT NULL,
 status TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS node_configs(
    machine_code TEXT PRIMARY KEY,
    yaml_text TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings(
 key TEXT PRIMARY KEY,
 value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cv_version ON config_versions(version DESC);
`
	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}
	// Remove the obsolete table used only by the deleted container-management telemetry.
	if _, err := s.db.Exec(`DROP TABLE IF EXISTS agent_status`); err != nil {
		return fmt.Errorf("清理已废弃的 Agent 状态表失败: %w", err)
	}
	// 安全补全旧表字段
	var count int
	s.db.QueryRow("SELECT count(*) FROM pragma_table_info('proxies') WHERE name='machine_code'").Scan(&count)
	if count == 0 {
		s.db.Exec("ALTER TABLE proxies ADD COLUMN machine_code TEXT NOT NULL DEFAULT ''")
	}

	// TUN is disabled by default for new installations. Preserve an existing explicit operator choice.
	s.db.Exec(`INSERT OR IGNORE INTO settings (key, value) VALUES ('tun_enable', 'false')`)
	// 首次启动时自动生成随机 Agent 注册密钥（不再硬编码默认值）
	var atCount int
	s.db.QueryRow(`SELECT COUNT(*) FROM settings WHERE key='agent_token' AND value != ''`).Scan(&atCount)
	if atCount == 0 {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err == nil {
			token := fmt.Sprintf("s5m-%x", buf)
			s.db.Exec(`INSERT OR REPLACE INTO settings (key, value) VALUES ('agent_token', ?)`, token)
		}
	}
	return nil
}

func (s *Store) GetSetting(key string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	return value, err
}

func (s *Store) GetSettings() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("读取设置行失败: %w", err)
		}
		res[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历设置记录失败: %w", err)
	}
	return res, nil
}

// CreateSettingIfAbsent 原子创建配置项；若 key 已存在，不覆盖已有值。
func (s *Store) CreateSettingIfAbsent(key, value string) (bool, error) {
	result, err := s.db.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING`,
		key, value,
	)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// queueAuthorizedAgentCommand serializes authorization checks and command insertion
// with binding revocation, so a command cannot be queued for a just-revoked Agent.
func (s *Store) queueAuthorizedAgentCommand(machineCode, commandJSON string) error {
	tx, err := s.db.Begin()
	if err != nil { return err }
	defer tx.Rollback()
	var token, globalToken string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key=?`, "agent_machine_"+machineCode).Scan(&token)
	if err == sql.ErrNoRows {
		return fmt.Errorf("Agent binding is no longer authorized")
	}
	if err != nil {
		return fmt.Errorf("读取 Agent 绑定授权失败: %w", err)
	}
	err = tx.QueryRow(`SELECT value FROM settings WHERE key='agent_token'`).Scan(&globalToken)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("读取全局 Agent 授权配置失败: %w", err)
	}
	if token == "" || token == globalToken {
		return fmt.Errorf("Agent binding is no longer authorized")
	}
	result, err := tx.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO NOTHING`, "agent_command_"+machineCode, commandJSON)
	if err != nil { return err }
	created, err := result.RowsAffected()
	if err != nil { return err }
	if created != 1 { return fmt.Errorf("pending command already exists") }
	return tx.Commit()
}

// QueueAuthorizedAgentCommand atomically verifies the Agent binding and inserts
// any supported Agent command. It shares the same revocation-safe transaction as
// SmartDNS commands so all command types enforce the same authorization boundary.
func (s *Store) QueueAuthorizedAgentCommand(machineCode, commandJSON string) error {
	return s.queueAuthorizedAgentCommand(machineCode, commandJSON)
}

// QueueAgentSmartDNSCommand queues a config candidate without changing the
// last-known-good controller copy; ACK success performs that update.
func (s *Store) QueueAgentSmartDNSCommand(machineCode, commandJSON string) error {
	return s.queueAuthorizedAgentCommand(machineCode, commandJSON)
}

// QueueAgentSmartDNSReadCommand atomically verifies the binding and queues a read.
func (s *Store) QueueAgentSmartDNSReadCommand(machineCode, commandJSON string) error {
	return s.queueAuthorizedAgentCommand(machineCode, commandJSON)
}

func (s *Store) UpdateSettings(updates map[string]string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for k, v := range updates {
		if _, err := tx.Exec(
			`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			k, v,
		); err != nil {
			return fmt.Errorf("update setting %q: %w", k, err)
		}
	}

	return tx.Commit()
}

// AckAgentCommand atomically commits a command result and removes only the matching
// pending command. A retry is accepted only when the persisted result has the same ID.
// matched=false means the command was replaced or no longer exists.
func (s *Store) AckAgentCommand(machineCode, commandID, status, message string, updatedAt int64) (bool, bool, error) {
	return s.AckAgentCommandWithConfig(machineCode, commandID, status, message, "", updatedAt)
}

func (s *Store) AckAgentCommandWithConfig(machineCode, commandID, status, message, config string, updatedAt int64) (duplicate bool, matched bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, false, err
	}
	defer tx.Rollback()

	pendingKey := "agent_command_" + machineCode
	resultKey := "agent_command_result_" + machineCode
	var raw string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key=?`, pendingKey).Scan(&raw)
	pendingExists := err == nil
	if err == sql.ErrNoRows {
		raw = ""
	} else if err != nil {
		return false, false, err
	}
	var pending map[string]string
	if raw != "" && json.Unmarshal([]byte(raw), &pending) == nil && pending["id"] == commandID {
		result, marshalErr := json.Marshal(map[string]any{
			"id": commandID, "type": pending["type"], "status": status,
			"message": message, "updated_at": updatedAt,
		})
		if marshalErr != nil {
			return false, false, marshalErr
		}
		if (pending["type"] == "read_smartdns_config" || pending["type"] == "configure_smartdns") && status == "success" {
			// Read commands return the on-disk config; configure commands carry
			// the exact candidate in the pending record. Persist only after success.
			savedConfig := config
			if pending["type"] == "configure_smartdns" {
				savedConfig = pending["config"]
			}
			if len(savedConfig) == 0 || len(savedConfig) > 8<<10 {
				return false, false, fmt.Errorf("invalid SmartDNS config payload")
			}
			if _, err := tx.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, "smartdns_config_"+machineCode, savedConfig); err != nil {
				return false, false, err
			}
		}
		if _, err := tx.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`, resultKey, string(result)); err != nil {
			return false, false, err
		}
		if _, err := tx.Exec(`DELETE FROM settings WHERE key=? AND value=?`, pendingKey, raw); err != nil {
			return false, false, err
		}
		if err := tx.Commit(); err != nil {
			return false, false, err
		}
		return false, true, nil
	}

	// A different or malformed pending command takes precedence over an old
	// result: an ACK for that old ID must not be accepted as a duplicate while
	// a replacement command is waiting for acknowledgement.
	if pendingExists {
		return false, false, nil
	}

	var previous string
	err = tx.QueryRow(`SELECT value FROM settings WHERE key=?`, resultKey).Scan(&previous)
	if err != nil && err != sql.ErrNoRows {
		return false, false, err
	}
	var previousResult map[string]any
	if err == nil && json.Unmarshal([]byte(previous), &previousResult) == nil && previousResult["id"] == commandID {
		return true, true, nil
	}
	return false, false, nil
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) CreateUser(username, hash, role string) error {
	_, err := s.db.Exec(`INSERT INTO users(username,password_hash,role) VALUES(?,?,?)`, username, hash, role)
	return err
}

func (s *Store) UserByUsername(name string) (*User, error) {
	u := &User{}
	var en int
	err := s.db.QueryRow(`SELECT id,username,password_hash,role,enabled FROM users WHERE username=?`, name).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &en)
	if err != nil {
		return nil, err
	}
	u.Enabled = en == 1
	return u, nil
}

func (s *Store) UpdatePassword(id int64, hash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash=? WHERE id=?`, hash, id)
	return err
}

func (s *Store) ListInstances() ([]Instance, error) {
	rows, err := s.db.Query(`SELECT id,name,machine_code,api_url FROM instances ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Instance
	for rows.Next() {
		var i Instance
		if err := rows.Scan(&i.ID, &i.Name, &i.MachineCode, &i.APIURL); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, nil
}

func (s *Store) CreateInstance(i *Instance) error {
	res, err := s.db.Exec(`INSERT INTO instances(name,machine_code,api_url) VALUES(?,?,?)`, i.Name, i.MachineCode, i.APIURL)
	if err != nil {
		return err
	}
	i.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) DeleteInstance(id int64) error {
	_, err := s.db.Exec(`DELETE FROM instances WHERE id=?`, id)
	return err
}

func (s *Store) ListProxies() ([]Proxy, error) {
	rows, err := s.db.Query(`SELECT id,name,mode,type,server,port,source_cidr,machine_code,config_json,enabled FROM proxies ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Proxy
	for rows.Next() {
		var p Proxy
		var extra string
		var en int
		if err := rows.Scan(&p.ID, &p.Name, &p.Mode, &p.Type, &p.Server, &p.Port, &p.SourceCIDR, &p.MachineCode, &extra, &en); err != nil {
			return nil, err
		}
		p.Enabled = en == 1
		p.Extra = map[string]any{}
		_ = json.Unmarshal([]byte(extra), &p.Extra)
		out = append(out, p)
	}
	return out, nil
}

func (s *Store) GetProxy(id int64) (*Proxy, error) {
	var p Proxy
	var extra string
	var en int
	err := s.db.QueryRow(`SELECT id,name,mode,type,server,port,source_cidr,machine_code,config_json,enabled FROM proxies WHERE id=?`, id).
		Scan(&p.ID, &p.Name, &p.Mode, &p.Type, &p.Server, &p.Port, &p.SourceCIDR, &p.MachineCode, &extra, &en)
	if err != nil {
		return nil, err
	}
	p.Enabled = en == 1
	p.Extra = map[string]any{}
	_ = json.Unmarshal([]byte(extra), &p.Extra)
	return &p, nil
}

func (s *Store) CreateProxy(p *Proxy) error {
	extra, _ := json.Marshal(p.Extra)
	res, err := s.db.Exec(`INSERT INTO proxies(name,mode,type,server,port,source_cidr,machine_code,config_json,enabled) VALUES(?,?,?,?,?,?,?,?,?)`, p.Name, p.Mode, p.Type, p.Server, p.Port, p.SourceCIDR, p.MachineCode, string(extra), b2i(p.Enabled))
	if err != nil {
		return err
	}
	p.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) UpdateProxy(p *Proxy) error {
	extra, _ := json.Marshal(p.Extra)
	_, err := s.db.Exec(`UPDATE proxies SET name=?,mode=?,type=?,server=?,port=?,source_cidr=?,machine_code=?,config_json=?,enabled=? WHERE id=?`, p.Name, p.Mode, p.Type, p.Server, p.Port, p.SourceCIDR, p.MachineCode, string(extra), b2i(p.Enabled), p.ID)
	return err
}

func (s *Store) DeleteProxy(id int64) error {
	_, err := s.db.Exec(`DELETE FROM proxies WHERE id=?`, id)
	return err
}

func (s *Store) NextVersion() (int, error) {
	var v int
	err := s.db.QueryRow(`SELECT COALESCE(MAX(version),0)+1 FROM config_versions`).Scan(&v)
	return v, err
}

func (s *Store) InsertVersion(v int, sha, yml, status string) error {
	_, err := s.db.Exec(`INSERT INTO config_versions(version,sha256,yaml_text,status,created_at) VALUES(?,?,?,?,?)`, v, sha, yml, status, time.Now().Format(time.RFC3339))
	return err
}

func (s *Store) UpdateVersionStatus(version int, status string) error {
	_, err := s.db.Exec(
		`UPDATE config_versions SET status=? WHERE version=?`,
		status, version,
	)
	if err != nil {
		return err
	}
	return nil
}

func (s *Store) ListVersions(limit int) ([]ConfigVersion, error) {
	rows, err := s.db.Query(`SELECT id,version,sha256,status,created_at FROM config_versions ORDER BY version DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConfigVersion
	for rows.Next() {
		var v ConfigVersion
		if err := rows.Scan(&v.ID, &v.Version, &v.SHA256, &v.Status, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Store) VersionYAML(version int) (string, error) {
	var y string
	err := s.db.QueryRow(`SELECT yaml_text FROM config_versions WHERE version=?`, version).Scan(&y)
	return y, err
}

func (s *Store) DeleteSettings(keys []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, k := range keys {
		if _, err := tx.Exec("DELETE FROM settings WHERE key=?", k); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteAgentBinding atomically revokes a machine credential and clears live node status.
// The node's YAML is retained for audit/re-registration.
func (s *Store) DeleteAgentBinding(machineCode string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, key := range []string{"agent_machine_" + machineCode, "agent_lastseen_" + machineCode, "agent_status_" + machineCode, "agent_command_" + machineCode, "agent_command_result_" + machineCode, "smartdns_config_" + machineCode, "agent_secret_" + machineCode, "agent_mihomo_secret_" + machineCode} {
		if _, err := tx.Exec(`DELETE FROM settings WHERE key=?`, key); err != nil {
			return err
		}
	}
	// Remove the live template binding in the same transaction as revoking the
	// machine credential. Keep node_configs and node_template_history for audit
	// and possible re-registration; only the active binding must disappear.
	var hasTemplateBindings int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='node_template_bindings'`).Scan(&hasTemplateBindings); err != nil {
		return err
	}
	if hasTemplateBindings > 0 {
		if _, err := tx.Exec(`DELETE FROM node_template_bindings WHERE machine_code=?`, machineCode); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type NodeConfig struct {
	MachineCode string `json:"machine_code"`
	YAML        string `json:"config_yaml"`
	UpdatedAt   string `json:"updated_at"`
}

func (s *Store) GetNodeConfig(machineCode string) (*NodeConfig, error) {
	c := &NodeConfig{}
	err := s.db.QueryRow(
		`SELECT machine_code, yaml_text, updated_at
         FROM node_configs WHERE machine_code=?`,
		machineCode,
	).Scan(&c.MachineCode, &c.YAML, &c.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Store) SaveNodeConfig(machineCode, yamlText string) error {
	_, err := s.db.Exec(`INSERT INTO node_configs(machine_code,yaml_text,updated_at) VALUES(?,?,?) ON CONFLICT(machine_code) DO UPDATE SET yaml_text=excluded.yaml_text, updated_at=excluded.updated_at`, machineCode, yamlText, time.Now().Format(time.RFC3339))
	return err
}

// SaveNodeConfigIfUnchanged performs an optimistic write. It updates an existing
// row only when the YAML still matches the caller's snapshot; an absent row may
// be initialized only when expectedYAML is empty. This prevents background
// normalization from overwriting a newer manual edit.
func (s *Store) SaveNodeConfigIfUnchanged(machineCode, expectedYAML, yamlText string) (bool, error) {
	result, err := s.db.Exec(`INSERT INTO node_configs(machine_code,yaml_text,updated_at) VALUES(?,?,?)
		ON CONFLICT(machine_code) DO UPDATE SET yaml_text=excluded.yaml_text, updated_at=excluded.updated_at
		WHERE node_configs.yaml_text=?`,
		machineCode, yamlText, time.Now().Format(time.RFC3339), expectedYAML)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

// SaveNodeConfigIfEmpty 只初始化不存在或内容为空的节点配置。
// 已存在的非空 YAML 不会被自动同步覆盖。
// SaveNodeConfigs atomically replaces a batch of node configurations.
// If any write fails, the transaction rolls back so nodes cannot be left on a
// partially synchronized generation.
func (s *Store) SaveNodeConfigs(configs map[string]string) error {
	if len(configs) == 0 {
		return nil
	}
	keys := make([]string, 0, len(configs))
	for machineCode := range configs {
		if strings.TrimSpace(machineCode) == "" {
			return fmt.Errorf("机器码不能为空")
		}
		keys = append(keys, machineCode)
	}
	sort.Strings(keys)

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO node_configs(machine_code,yaml_text,updated_at) VALUES(?,?,?) ON CONFLICT(machine_code) DO UPDATE SET yaml_text=excluded.yaml_text, updated_at=excluded.updated_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := time.Now().Format(time.RFC3339)
	for _, machineCode := range keys {
		if _, err := stmt.Exec(machineCode, configs[machineCode], now); err != nil {
			return fmt.Errorf("保存机器 %s 的配置失败: %w", machineCode, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *Store) SaveNodeConfigIfEmpty(machineCode, yamlText string) error {
	_, err := s.db.Exec(`INSERT INTO node_configs(machine_code,yaml_text,updated_at)
                VALUES(?,?,?)
                ON CONFLICT(machine_code) DO UPDATE SET
                        yaml_text=excluded.yaml_text,
                        updated_at=excluded.updated_at
                WHERE trim(node_configs.yaml_text) = ''`,
		machineCode, yamlText, time.Now().Format(time.RFC3339))
	return err
}
