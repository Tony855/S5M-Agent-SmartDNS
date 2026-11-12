package app

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"strings"
	"testing"
)

func TestSaveNodeConfigIfEmptyPreservesExistingYAML(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "node-config-test.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	_, err = store.db.Exec(`CREATE TABLE IF NOT EXISTS node_configs(
                machine_code TEXT PRIMARY KEY,
                yaml_text TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
        )`)
	if err != nil {
		t.Fatalf("创建测试表: %v", err)
	}

	original := "proxies:\n  - name: custom-node\n    type: socks5\n"
	generated := "proxies:\n  - name: generated-node\n    type: socks5\n"

	if err := store.SaveNodeConfigIfEmpty("machine-test", original); err != nil {
		t.Fatalf("首次初始化: %v", err)
	}

	if err := store.SaveNodeConfigIfEmpty("machine-test", generated); err != nil {
		t.Fatalf("重复初始化: %v", err)
	}

	got, err := store.GetNodeConfig("machine-test")
	if err != nil {
		t.Fatalf("读取配置: %v", err)
	}
	if got == nil || got.YAML != original {
		t.Fatalf("已有配置被覆盖：期望原始 YAML，实际 %#v", got)
	}

	if err := store.SaveNodeConfig("machine-empty", ""); err != nil {
		t.Fatalf("建立空配置: %v", err)
	}
	if err := store.SaveNodeConfigIfEmpty("machine-empty", generated); err != nil {
		t.Fatalf("初始化空配置: %v", err)
	}

	got, err = store.GetNodeConfig("machine-empty")
	if err != nil {
		t.Fatalf("读取初始化配置: %v", err)
	}
	if got == nil || got.YAML != generated {
		t.Fatalf("空配置未被初始化：实际 %#v", got)
	}
}

func TestSaveNodeConfigsRollsBackWholeBatchOnFailure(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "atomic-node-config-test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.SaveNodeConfigs(map[string]string{
		"node-a": "proxies: [old-a]",
		"node-b": "proxies: [old-b]",
	}); err != nil {
		t.Fatalf("seed node configs: %v", err)
	}
	if _, err := store.db.Exec(`CREATE TRIGGER fail_node_b_update BEFORE UPDATE ON node_configs
		WHEN OLD.machine_code = 'node-b'
		BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}

	err = store.SaveNodeConfigs(map[string]string{
		"node-a": "proxies: [new-a]",
		"node-b": "proxies: [new-b]",
	})
	if err == nil {
		t.Fatal("SaveNodeConfigs() expected simulated write failure")
	}

	for machineCode, want := range map[string]string{
		"node-a": "proxies: [old-a]",
		"node-b": "proxies: [old-b]",
	} {
		got, err := store.GetNodeConfig(machineCode)
		if err != nil {
			t.Fatalf("GetNodeConfig(%q): %v", machineCode, err)
		}
		if got == nil || got.YAML != want {
			t.Errorf("node %q YAML = %#v, want %q; batch should roll back completely", machineCode, got, want)
		}
	}
}

func TestSaveNodeConfigsRejectsBlankMachineCode(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "blank-machine-config-test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.SaveNodeConfigs(map[string]string{"  ": "proxies: []"}); err == nil {
		t.Fatal("SaveNodeConfigs() should reject a blank machine code")
	}
}

func TestDeleteAgentBindingRemovesLiveTemplateBindingAndAgentSettings(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "delete-agent-binding.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if _, err := store.db.Exec(`CREATE TABLE node_template_bindings (
		machine_code TEXT PRIMARY KEY,
		template_version INTEGER NOT NULL DEFAULT 0,
		config_sha256 TEXT NOT NULL DEFAULT '',
		source TEXT NOT NULL DEFAULT 'template',
		updated_at TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		t.Fatalf("create template binding table: %v", err)
	}
	if err := store.UpdateSettings(map[string]string{
		"agent_machine_node-a":        "dedicated-token",
		"agent_lastseen_node-a":       "123",
		"agent_status_node-a":         "online",
		"agent_secret_node-a":         "secret",
		"agent_mihomo_secret_node-a":  "mihomo-secret",
		"agent_command_node-a":        `{"id":"cmd"}`,
		"agent_command_result_node-a": `{"id":"cmd","status":"ok"}`,
		"smartdns_config_node-a": "bind 127.0.0.1:6053",
		"smartdns_enabled_node-a": "false",
		"agent_machine_node-b":        "keep-token",
	}); err != nil {
		t.Fatalf("seed Agent settings: %v", err)
	}
	if _, err := store.db.Exec(`INSERT INTO node_template_bindings(machine_code,template_version) VALUES('node-a',3),('node-b',3)`); err != nil {
		t.Fatalf("seed template bindings: %v", err)
	}

	if err := store.DeleteAgentBinding("node-a"); err != nil {
		t.Fatalf("DeleteAgentBinding: %v", err)
	}

	for _, key := range []string{"agent_machine_node-a", "agent_lastseen_node-a", "agent_status_node-a", "agent_secret_node-a", "agent_mihomo_secret_node-a", "agent_command_node-a", "agent_command_result_node-a", "smartdns_config_node-a", "smartdns_enabled_node-a"} {
		value, err := store.GetSetting(key)
		if err == nil && value != "" {
			t.Errorf("setting %q = %q, want deleted or empty after deletion", key, value)
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("GetSetting(%q): %v", key, err)
		}
	}
	if value, err := store.GetSetting("agent_machine_node-b"); err != nil || value != "keep-token" {
		t.Errorf("other Agent credential = %q, err=%v; want preserved", value, err)
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM node_template_bindings WHERE machine_code='node-a'`).Scan(&count); err != nil {
		t.Fatalf("count deleted Agent bindings: %v", err)
	}
	if count != 0 {
		t.Fatalf("deleted Agent still has %d live template bindings", count)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM node_template_bindings WHERE machine_code='node-b'`).Scan(&count); err != nil {
		t.Fatalf("count other Agent bindings: %v", err)
	}
	if count != 1 {
		t.Fatalf("other Agent binding count = %d, want 1", count)
	}
}

func TestCreateSettingIfAbsentDoesNotOverwritePendingCommand(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "atomic-setting-test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	created, err := store.CreateSettingIfAbsent("agent_command_node-a", `{"id":"first","type":"update_mihomo"}`)
	if err != nil || !created {
		t.Fatalf("first CreateSettingIfAbsent() = %v, %v; want true, nil", created, err)
	}
	created, err = store.CreateSettingIfAbsent("agent_command_node-a", `{"id":"second","type":"update_mihomo"}`)
	if err != nil {
		t.Fatalf("second CreateSettingIfAbsent() error = %v", err)
	}
	if created {
		t.Fatal("second CreateSettingIfAbsent() overwrote an existing pending command")
	}
	value, err := store.GetSetting("agent_command_node-a")
	if err != nil {
		t.Fatalf("GetSetting(): %v", err)
	}
	if value != `{"id":"first","type":"update_mihomo"}` {
		t.Fatalf("pending command = %q, want the original command", value)
	}
}

func TestGetSettingsReturnsAllStoredValues(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "get-settings-test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	want := map[string]string{
		"agent_token": "token-value",
		"mihomo_api":  "http://127.0.0.1:9090",
	}
	if err := store.UpdateSettings(want); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	got, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("GetSettings()[%q] = %q, want %q", key, got[key], value)
		}
	}
}

func TestFreshStoreDoesNotCreateLegacyAgentTasksTable(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "fresh-store.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'agent_tasks'`).Scan(&count); err != nil {
		t.Fatalf("check legacy table: %v", err)
	}
	if count != 0 {
		t.Fatal("fresh database unexpectedly created retired agent_tasks table")
	}
}

func TestStoreMigrationPreservesExistingLegacyAgentTasksTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy-store.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("initial OpenStore: %v", err)
	}
	if _, err := store.db.Exec(`CREATE TABLE agent_tasks (id TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'pending')`); err != nil {
		store.db.Close()
		t.Fatalf("create legacy table fixture: %v", err)
	}
	if err := store.db.Close(); err != nil {
		t.Fatalf("close initial store: %v", err)
	}

	reopened, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("reopen legacy database: %v", err)
	}
	defer reopened.db.Close()

	var count int
	if err := reopened.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'agent_tasks'`).Scan(&count); err != nil {
		t.Fatalf("check legacy table after migration: %v", err)
	}
	if count != 1 {
		t.Fatal("migration removed the existing legacy agent_tasks table")
	}
}

func TestSaveNodeConfigIfUnchangedRejectsStaleSnapshot(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-cas.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	const machine = "node-cas"
	original := "secret: old\ntun:\n  enable: false\ndns:\n  enable: false\n"
	manual := "secret: new\ntun:\n  enable: true\ndns:\n  enable: false\n"
	staleNormalized := "secret: old\nmixed-port: 7890\ntun:\n  enable: false\ndns:\n  enable: false\n"

	if err := store.SaveNodeConfig(machine, original); err != nil {
		t.Fatalf("initial save: %v", err)
	}
	if ok, err := store.SaveNodeConfigIfUnchanged(machine, original, manual); err != nil || !ok {
		t.Fatalf("manual update = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := store.SaveNodeConfigIfUnchanged(machine, original, staleNormalized); err != nil || ok {
		t.Fatalf("stale update = (%v, %v), want (false, nil)", ok, err)
	}
	got, err := store.GetNodeConfig(machine)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if got == nil || got.YAML != manual {
		t.Fatalf("stale normalization overwrote newer config: %#v", got)
	}
}

func TestSaveNodeConfigIfUnchangedCanInitializeMissingNode(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-cas-init.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	want := "secret: init\ntun:\n  enable: false\ndns:\n  enable: false\n"
	if ok, err := store.SaveNodeConfigIfUnchanged("node-new", "", want); err != nil || !ok {
		t.Fatalf("initialize = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := store.SaveNodeConfigIfUnchanged("node-new", "", "secret: stale\n"); err != nil || ok {
		t.Fatalf("duplicate initialization = (%v, %v), want (false, nil)", ok, err)
	}
	got, err := store.GetNodeConfig("node-new")
	if err != nil || got == nil || got.YAML != want {
		t.Fatalf("initialized config = %#v, err=%v", got, err)
	}
}

func TestSaveNodeConfigsIfUnchangedRejectsConcurrentManualEditAndRollsBackBatch(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-batch-cas.db"))
	if err != nil { t.Fatalf("OpenStore: %v", err) }
	defer store.db.Close()

	originalA := "secret: old-a\n"
	originalB := "secret: old-b\n"
	manualB := "secret: manual-b\n"
	if err := store.SaveNodeConfigs(map[string]string{"node-a": originalA, "node-b": originalB}); err != nil {
		t.Fatalf("seed configs: %v", err)
	}
	// Simulate a manual save after sync read its snapshots but before batch commit.
	if err := store.SaveNodeConfig("node-b", manualB); err != nil { t.Fatalf("manual save: %v", err) }

	err = store.SaveNodeConfigsIfUnchanged(
		map[string]string{"node-a": originalA, "node-b": originalB},
		map[string]string{"node-a": "secret: generated-a\n", "node-b": "secret: generated-b\n"},
	)
	if err == nil || !strings.Contains(err.Error(), "同步期间已被修改") {
		t.Fatalf("stale batch error = %v, want concurrent-edit conflict", err)
	}
	for code, want := range map[string]string{"node-a": originalA, "node-b": manualB} {
		got, err := store.GetNodeConfig(code)
		if err != nil { t.Fatalf("GetNodeConfig(%s): %v", code, err) }
		if got == nil || got.YAML != want {
			t.Errorf("%s YAML = %#v, want unchanged %q", code, got, want)
		}
	}
}

func TestSaveNodeConfigsIfUnchangedInitializesMissingRowsAndRejectsRacingInsert(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "node-config-batch-cas-init.db"))
	if err != nil { t.Fatalf("OpenStore: %v", err) }
	defer store.db.Close()

	if err := store.SaveNodeConfig("node-a", "secret: manual\n"); err != nil { t.Fatalf("racing insert: %v", err) }
	err = store.SaveNodeConfigsIfUnchanged(
		map[string]string{"node-a": "", "node-b": ""},
		map[string]string{"node-a": "secret: stale\n", "node-b": "secret: generated\n"},
	)
	if err == nil { t.Fatal("batch should reject row inserted after empty snapshot") }
	for code, want := range map[string]string{"node-a": "secret: manual\n"} {
		got, err := store.GetNodeConfig(code)
		if err != nil { t.Fatalf("GetNodeConfig(%s): %v", code, err) }
		if got == nil || got.YAML != want { t.Errorf("%s was overwritten: %#v", code, got) }
	}
	if got, err := store.GetNodeConfig("node-b"); err != nil || got != nil {
		t.Errorf("batch should roll back newly initialized node-b; got=%#v err=%v", got, err)
	}
}


func TestStoreMigrationAddsMissingProxyMachineCodeColumn(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy-proxies.db")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil { t.Fatalf("open legacy database: %v", err) }
	_, err = db.Exec(`CREATE TABLE proxies(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		mode TEXT NOT NULL DEFAULT 'rule',
		type TEXT NOT NULL,
		server TEXT NOT NULL,
		port INTEGER NOT NULL,
		source_cidr TEXT NOT NULL DEFAULT '0.0.0.0/0',
		config_json TEXT NOT NULL DEFAULT '{}',
		enabled INTEGER NOT NULL DEFAULT 1
	)`)
	if err != nil { db.Close(); t.Fatalf("create legacy proxies table: %v", err) }
	if _, err := db.Exec(`INSERT INTO proxies(name,type,server,port) VALUES('legacy','socks5','127.0.0.1',1080)`); err != nil {
		db.Close(); t.Fatalf("seed legacy proxy: %v", err)
	}
	if err := db.Close(); err != nil { t.Fatalf("close legacy database: %v", err) }

	store, err := OpenStore(dbPath)
	if err != nil { t.Fatalf("OpenStore should migrate legacy proxies table: %v", err) }
	defer store.db.Close()

	var machineCode string
	if err := store.db.QueryRow(`SELECT machine_code FROM proxies WHERE name='legacy'`).Scan(&machineCode); err != nil {
		t.Fatalf("read migrated machine_code: %v", err)
	}
	if machineCode != "" { t.Fatalf("legacy machine_code = %q, want empty default", machineCode) }
}

func TestStoreMigrationRepairsBlankAgentTokenWithoutOverwritingExistingToken(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "agent-token-migration.db"))
	if err != nil { t.Fatalf("OpenStore: %v", err) }
	defer store.db.Close()

	if _, err := store.db.Exec(`UPDATE settings SET value='' WHERE key='agent_token'`); err != nil {
		t.Fatalf("blank agent token: %v", err)
	}
	if err := store.migrate(); err != nil { t.Fatalf("migrate blank agent token: %v", err) }
	repaired, err := store.GetSetting("agent_token")
	if err != nil { t.Fatalf("read repaired token: %v", err) }
	if strings.TrimSpace(repaired) == "" { t.Fatal("migration left Agent registration token blank") }

	const operatorToken = "operator-managed-token"
	if _, err := store.db.Exec(`UPDATE settings SET value=? WHERE key='agent_token'`, operatorToken); err != nil {
		t.Fatalf("set operator token: %v", err)
	}
	if err := store.migrate(); err != nil { t.Fatalf("migrate existing operator token: %v", err) }
	got, err := store.GetSetting("agent_token")
	if err != nil { t.Fatalf("read operator token: %v", err) }
	if got != operatorToken { t.Fatalf("migration overwrote operator token: got %q", got) }
}

func TestProxyReadsRejectCorruptExtensionJSON(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "corrupt-proxy-extra.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	result, err := store.db.Exec(`INSERT INTO proxies(name,mode,type,server,port,config_json,enabled) VALUES('broken','rule','socks5','127.0.0.1',1080,'{invalid-json',1)`)
	if err != nil {
		t.Fatalf("insert corrupt proxy fixture: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read proxy fixture ID: %v", err)
	}
	if _, err := store.ListProxies(); err == nil || !strings.Contains(err.Error(), "扩展配置") {
		t.Fatalf("ListProxies error = %v, want extension JSON error", err)
	}
	if _, err := store.GetProxy(id); err == nil || !strings.Contains(err.Error(), "扩展配置") {
		t.Fatalf("GetProxy error = %v, want extension JSON error", err)
	}
}

func TestCreateProxyRejectsUnserializableExtensionConfig(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "proxy-json-marshal.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	proxy := &Proxy{
		Name: "invalid-extra",
		Type: "socks5",
		Server: "127.0.0.1",
		Port: 1080,
		Enabled: true,
		Extra: map[string]any{"unsupported": make(chan int)},
	}
	if err := store.CreateProxy(proxy); err == nil || !strings.Contains(err.Error(), "序列化") {
		t.Fatalf("CreateProxy error = %v, want serialization error", err)
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM proxies WHERE name='invalid-extra'`).Scan(&count); err != nil {
		t.Fatalf("count proxy rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("invalid proxy rows = %d, want 0", count)
	}
}


func TestStoreMutationsReturnNoRowsForMissingRecords(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "missing-row-mutations.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.DeleteInstance(999); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("DeleteInstance(missing) = %v, want sql.ErrNoRows", err)
	}
	if err := store.UpdatePassword(999, "new-hash"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("UpdatePassword(missing) = %v, want sql.ErrNoRows", err)
	}
	if err := store.UpdateVersionStatus(999, "published"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("UpdateVersionStatus(missing) = %v, want sql.ErrNoRows", err)
	}

	if err := store.CreateInstance(&Instance{Name: "existing", MachineCode: "node-a", APIURL: "http://127.0.0.1"}); err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	if err := store.DeleteInstance(1); err != nil {
		t.Errorf("DeleteInstance(existing) = %v, want nil", err)
	}

	if err := store.InsertVersion(1, "sha", "yaml", "draft"); err != nil {
		t.Fatalf("InsertVersion: %v", err)
	}
	if err := store.UpdateVersionStatus(1, "published"); err != nil {
		t.Errorf("UpdateVersionStatus(existing) = %v, want nil", err)
	}
}

func TestDeleteAgentBindingRejectsMissingCredential(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "missing-agent-binding.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.DeleteAgentBinding("unknown-node"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("DeleteAgentBinding(missing) = %v, want sql.ErrNoRows", err)
	}
	if _, err := store.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)`, "agent_status_unknown-node", "{}"); err != nil {
		t.Fatalf("seed orphan status: %v", err)
	}
	if err := store.DeleteAgentBinding("unknown-node"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("DeleteAgentBinding(orphan status only) = %v, want sql.ErrNoRows", err)
	}
	var status string
	if err := store.db.QueryRow(`SELECT value FROM settings WHERE key=?`, "agent_status_unknown-node").Scan(&status); err != nil {
		t.Fatalf("missing-binding cleanup should roll back: %v", err)
	}
	if status != "{}" {
		t.Fatalf("orphan status = %q, want unchanged because transaction rolled back", status)
	}

	if _, err := store.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)`, "agent_machine_known-node", "node-token"); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	if _, err := store.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)`, "agent_status_known-node", "{}"); err != nil {
		t.Fatalf("seed status: %v", err)
	}
	if err := store.DeleteAgentBinding("known-node"); err != nil {
		t.Fatalf("DeleteAgentBinding(existing) = %v, want nil", err)
	}
	if _, err := store.GetSetting("agent_machine_known-node"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("credential after revoke error = %v, want sql.ErrNoRows", err)
	}
	if _, err := store.GetSetting("agent_status_known-node"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("status after revoke error = %v, want sql.ErrNoRows", err)
	}
}


func TestQueueAuthorizedAgentCommandSerializesConcurrentSameNodeCommands(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "same-node-command-race.db"))
	if err != nil { t.Fatalf("OpenStore: %v", err) }
	defer store.db.Close()
	if err := store.UpdateSettings(map[string]string{
		"agent_token": "global-token",
		"agent_machine_node-race": "dedicated-token",
	}); err != nil { t.Fatalf("seed Agent binding: %v", err) }

	const contenders = 64
	start := make(chan struct{})
	var wg sync.WaitGroup
	var accepted atomic.Int32
	var rejected atomic.Int32
	errs := make(chan error, contenders)
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			command := fmt.Sprintf(`{"id":"same-node-%d","type":"restart"}`, i)
			err := store.QueueAuthorizedAgentCommand("node-race", command)
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, ErrAgentCommandPending):
				rejected.Add(1)
			default:
				errs <- fmt.Errorf("queue contender %d: %w", i, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs { t.Error(err) }
	if accepted.Load() != 1 || rejected.Load() != contenders-1 {
		t.Fatalf("same-node queue accepted=%d rejected=%d; want 1 and %d", accepted.Load(), rejected.Load(), contenders-1)
	}
	settings, err := store.GetSettings()
	if err != nil { t.Fatal(err) }
	if strings.TrimSpace(settings["agent_command_node-race"]) == "" {
		t.Fatal("the single accepted command was not persisted")
	}
}

func TestQueueAuthorizedAgentCommandScalesAcross500Nodes(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "500-node-command-queue.db"))
	if err != nil { t.Fatalf("OpenStore: %v", err) }
	defer store.db.Close()
	seed := map[string]string{"agent_token": "global-token"}
	const nodes = 500
	for i := 0; i < nodes; i++ {
		seed[fmt.Sprintf("agent_machine_node-%03d", i)] = fmt.Sprintf("dedicated-token-%03d", i)
	}
	if err := store.UpdateSettings(seed); err != nil { t.Fatalf("seed 500 Agent bindings: %v", err) }

	var wg sync.WaitGroup
	var accepted atomic.Int32
	errs := make(chan error, nodes)
	for i := 0; i < nodes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			code := fmt.Sprintf("node-%03d", i)
			command := fmt.Sprintf(`{"id":"cmd-%03d","type":"restart"}`, i)
			if err := store.QueueAuthorizedAgentCommand(code, command); err != nil {
				errs <- fmt.Errorf("queue %s: %w", code, err)
				return
			}
			accepted.Add(1)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs { t.Error(err) }
	if accepted.Load() != nodes {
		t.Fatalf("queued commands for %d nodes; want %d", accepted.Load(), nodes)
	}
	settings, err := store.GetSettings()
	if err != nil { t.Fatal(err) }
	for i := 0; i < nodes; i++ {
		code := fmt.Sprintf("node-%03d", i)
		if got := settings["agent_command_"+code]; got == "" {
			t.Errorf("node %s has no persisted pending command", code)
		}
	}
}

func TestQueueAuthorizedAgentCommandCannotSurviveConcurrentBindingRevocation(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "revoke-command-race.db"))
	if err != nil { t.Fatalf("OpenStore: %v", err) }
	defer store.db.Close()
	if err := store.UpdateSettings(map[string]string{
		"agent_token": "global-token",
		"agent_machine_node-revoke-race": "dedicated-token",
	}); err != nil { t.Fatalf("seed Agent binding: %v", err) }

	start := make(chan struct{})
	var wg sync.WaitGroup
	var queueErr, revokeErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		queueErr = store.QueueAuthorizedAgentCommand("node-revoke-race", `{"id":"race-command","type":"restart"}`)
	}()
	go func() {
		defer wg.Done()
		<-start
		revokeErr = store.DeleteAgentBinding("node-revoke-race")
	}()
	close(start)
	wg.Wait()
	if revokeErr != nil { t.Fatalf("revoke Agent binding: %v", revokeErr) }
	if queueErr != nil && !strings.Contains(queueErr.Error(), "no longer authorized") {
		t.Fatalf("unexpected queue error during revoke: %v", queueErr)
	}
	settings, err := store.GetSettings()
	if err != nil { t.Fatal(err) }
	if settings["agent_machine_node-revoke-race"] != "" {
		t.Fatal("Agent credential survived revocation")
	}
	if settings["agent_command_node-revoke-race"] != "" {
		t.Fatal("pending command survived concurrent Agent revocation")
	}
}
