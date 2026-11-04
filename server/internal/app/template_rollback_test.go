package app

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"\n\t"strings"
	"testing"
)

func newTemplateRollbackTestApp(t *testing.T) (*App, func()) {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "template-rollback.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	a := &App{store: store}
	if err := a.ensureTemplateSchema(); err != nil {
		store.db.Close()
		t.Fatalf("ensureTemplateSchema: %v", err)
	}
	if _, err := store.db.Exec(`INSERT INTO settings(key,value) VALUES('agent_token','global'),('agent_machine_node-a','dedicated')`); err != nil {
		store.db.Close()
		t.Fatalf("seed credentials: %v", err)
	}
	return a, func() { _ = store.db.Close() }
}

func seedTemplateRollback(t *testing.T, a *App, withCurrent bool) {
	t.Helper()
	if withCurrent {
		if _, err := a.store.db.Exec(`INSERT INTO node_configs(machine_code,yaml_text,updated_at) VALUES('node-a','current-yaml','now')`); err != nil {
			t.Fatalf("seed current config: %v", err)
		}
	}
	if _, err := a.store.db.Exec(`INSERT INTO node_template_history(machine_code,previous_yaml,previous_template_version,previous_source,created_at) VALUES('node-a','previous-yaml',7,'template','then')`); err != nil {
		t.Fatalf("seed history: %v", err)
	}
}

func callRollbackNodeTemplate(a *App) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mihomo/template/rollback", strings.NewReader(`{"machine_code":"node-a","confirm":true}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.handleRollbackNodeTemplate(rec, req)
	return rec
}

func TestRollbackNodeTemplateRestoresConfigAndAllowsMissingBinding(t *testing.T) {
	a, cleanup := newTemplateRollbackTestApp(t)
	defer cleanup()
	seedTemplateRollback(t, a, true)

	rec := callRollbackNodeTemplate(a)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var yaml string
	if err := a.store.db.QueryRow(`SELECT yaml_text FROM node_configs WHERE machine_code='node-a'`).Scan(&yaml); err != nil {
		t.Fatalf("read restored config: %v", err)
	}
	if yaml != "previous-yaml" {
		t.Fatalf("yaml = %q, want previous-yaml", yaml)
	}
	var version int
	var source string
	if err := a.store.db.QueryRow(`SELECT template_version,source FROM node_template_bindings WHERE machine_code='node-a'`).Scan(&version, &source); err != nil {
		t.Fatalf("read restored binding: %v", err)
	}
	if version != 7 || source != "template" {
		t.Fatalf("binding = (%d,%q), want (7,template)", version, source)
	}
}

func TestRollbackNodeTemplateRejectsMissingCurrentConfigWithoutMutation(t *testing.T) {
	a, cleanup := newTemplateRollbackTestApp(t)
	defer cleanup()
	seedTemplateRollback(t, a, false)

	rec := callRollbackNodeTemplate(a)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	var count int
	if err := a.store.db.QueryRow(`SELECT COUNT(*) FROM node_template_history WHERE machine_code='node-a'`).Scan(&count); err != nil {
		t.Fatalf("count history: %v", err)
	}
	if count != 1 {
		t.Fatalf("history count = %d, want 1", count)
	}
}

func TestRollbackNodeTemplateFailsClosedOnBindingReadError(t *testing.T) {
	a, cleanup := newTemplateRollbackTestApp(t)
	defer cleanup()
	seedTemplateRollback(t, a, true)
	if _, err := a.store.db.Exec(`DROP TABLE node_template_bindings`); err != nil {
		t.Fatalf("drop binding table: %v", err)
	}

	rec := callRollbackNodeTemplate(a)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	var yaml string
	if err := a.store.db.QueryRow(`SELECT yaml_text FROM node_configs WHERE machine_code='node-a'`).Scan(&yaml); err != nil {
		t.Fatalf("read current config: %v", err)
	}
	if yaml != "current-yaml" {
		t.Fatalf("config changed after failed rollback: %q", yaml)
	}
	var count int
	if err := a.store.db.QueryRow(`SELECT COUNT(*) FROM node_template_history WHERE machine_code='node-a'`).Scan(&count); err != nil {
		t.Fatalf("count history: %v", err)
	}
	if count != 1 {
		t.Fatalf("history count = %d, want 1 after rollback", count)
	}
}
