package app

import (
	"database/sql"
	"errors"
	"path/filepath"
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

	for _, key := range []string{"agent_machine_node-a", "agent_lastseen_node-a", "agent_status_node-a", "agent_secret_node-a", "agent_mihomo_secret_node-a", "agent_command_node-a", "agent_command_result_node-a"} {
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
