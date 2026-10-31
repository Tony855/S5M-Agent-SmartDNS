package app

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func newTemplateDeleteTestApp(t *testing.T) (*App, func()) {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "template-delete.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	for _, schema := range []string{
		`CREATE TABLE IF NOT EXISTS mihomo_template_versions (
			version INTEGER PRIMARY KEY,
			yaml_text TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS node_template_bindings (
			machine_code TEXT PRIMARY KEY,
			template_version INTEGER NOT NULL DEFAULT 0,
			config_sha256 TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL DEFAULT 'template',
			updated_at TEXT NOT NULL DEFAULT ''
		)`,
	} {
		if _, err := store.db.Exec(schema); err != nil {
			store.db.Close()
			t.Fatalf("create test schema: %v", err)
		}
	}
	return &App{store: store}, func() { _ = store.db.Close() }
}

func seedTemplateDeleteTest(t *testing.T, a *App, current int, versions ...int) {
	t.Helper()
	if _, err := a.store.db.Exec(`INSERT OR REPLACE INTO settings(key,value) VALUES('mihomo_template_current_version',?)`, current); err != nil {
		t.Fatalf("seed current version: %v", err)
	}
	for _, version := range versions {
		if _, err := a.store.db.Exec(`INSERT OR REPLACE INTO mihomo_template_versions(version,yaml_text) VALUES(?,?)`, version, "mixed-port: 7890"); err != nil {
			t.Fatalf("seed template version %d: %v", version, err)
		}
	}
}

func callDeleteTemplateVersion(a *App, version string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/mihomo/template/"+version, nil)
	req.SetPathValue("version", version)
	rec := httptest.NewRecorder()
	a.handleDeleteMihomoTemplateVersion(rec, req)
	return rec
}

func templateVersionExists(t *testing.T, a *App, version int) bool {
	t.Helper()
	var count int
	if err := a.store.db.QueryRow(`SELECT COUNT(*) FROM mihomo_template_versions WHERE version=?`, version).Scan(&count); err != nil {
		t.Fatalf("count template version: %v", err)
	}
	return count > 0
}

func TestDeleteMihomoTemplateVersionRejectsInvalidVersion(t *testing.T) {
	a, cleanup := newTemplateDeleteTestApp(t)
	defer cleanup()
	for _, value := range []string{"0", "-1", "abc"} {
		t.Run(value, func(t *testing.T) {
			rec := callDeleteTemplateVersion(a, value)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}

func TestDeleteMihomoTemplateVersionNotFound(t *testing.T) {
	a, cleanup := newTemplateDeleteTestApp(t)
	defer cleanup()
	seedTemplateDeleteTest(t, a, 4, 3, 4)
	rec := callDeleteTemplateVersion(a, "99")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestDeleteMihomoTemplateVersionRejectsCurrentVersion(t *testing.T) {
	a, cleanup := newTemplateDeleteTestApp(t)
	defer cleanup()
	seedTemplateDeleteTest(t, a, 4, 3, 4)
	rec := callDeleteTemplateVersion(a, "4")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if !templateVersionExists(t, a, 4) {
		t.Fatal("current template version was deleted despite conflict")
	}
}

func TestDeleteMihomoTemplateVersionRejectsBoundVersionWithoutMutation(t *testing.T) {
	a, cleanup := newTemplateDeleteTestApp(t)
	defer cleanup()
	seedTemplateDeleteTest(t, a, 4, 3, 4)
	// Model a still-registered Agent: a dedicated credential means this
	// binding must block deletion even when the global fallback token exists.
	if _, err := a.store.db.Exec(`INSERT OR REPLACE INTO settings(key,value) VALUES('agent_token','global-token'),('agent_machine_node-a','dedicated-token')`); err != nil {
		t.Fatalf("seed Agent credentials: %v", err)
	}
	if _, err := a.store.db.Exec(`INSERT INTO node_template_bindings(machine_code,template_version,source) VALUES('node-a',3,'template')`); err != nil {
		t.Fatalf("seed node binding: %v", err)
	}
	rec := callDeleteTemplateVersion(a, "3")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if !templateVersionExists(t, a, 3) {
		t.Fatal("bound template version was deleted despite conflict")
	}
}

func TestDeleteMihomoTemplateVersionDeletesUnboundHistory(t *testing.T) {
	a, cleanup := newTemplateDeleteTestApp(t)
	defer cleanup()
	seedTemplateDeleteTest(t, a, 4, 2, 4)
	rec := callDeleteTemplateVersion(a, "2")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if templateVersionExists(t, a, 2) {
		t.Fatal("historical template version still exists after successful delete")
	}
	if !templateVersionExists(t, a, 4) {
		t.Fatal("current template version was unexpectedly changed")
	}
}

func TestDeleteMihomoTemplateVersionFailsClosedOnInvalidCurrentVersion(t *testing.T) {
	a, cleanup := newTemplateDeleteTestApp(t)
	defer cleanup()
	seedTemplateDeleteTest(t, a, 4, 3, 4)
	if _, err := a.store.db.Exec(`UPDATE settings SET value='invalid' WHERE key='mihomo_template_current_version'`); err != nil {
		t.Fatalf("corrupt current version setting: %v", err)
	}

	rec := callDeleteTemplateVersion(a, "3")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if !templateVersionExists(t, a, 3) {
		t.Fatal("template version was deleted despite invalid current-version setting")
	}
}

func TestDeleteMihomoTemplateVersionFailsClosedWhenCurrentVersionMissing(t *testing.T) {
	a, cleanup := newTemplateDeleteTestApp(t)
	defer cleanup()
	seedTemplateDeleteTest(t, a, 4, 3, 4)
	if _, err := a.store.db.Exec(`DELETE FROM settings WHERE key='mihomo_template_current_version'`); err != nil {
		t.Fatalf("remove current version setting: %v", err)
	}

	rec := callDeleteTemplateVersion(a, "3")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if !templateVersionExists(t, a, 3) {
		t.Fatal("template version was deleted despite missing current-version setting")
	}
}
