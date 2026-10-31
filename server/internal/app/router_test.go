package app

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestEnsureAdminRequiresExplicitPassword(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "admin-init.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	a := &App{cfg: Config{AdminUser: "admin"}, store: store}
	if err := a.ensureAdmin(); err == nil {
		t.Fatal("expected first startup without an administrator password to fail")
	}
	count, err := store.CountUsers()
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	if count != 0 {
		t.Fatalf("unexpected administrator account created without a password: %d", count)
	}

	a.cfg.AdminPass = "test-only-strong-password"
	if err := a.ensureAdmin(); err != nil {
		t.Fatalf("ensureAdmin with configured password: %v", err)
	}
	count, err = store.CountUsers()
	if err != nil {
		t.Fatalf("CountUsers after initialization: %v", err)
	}
	if count != 1 {
		t.Fatalf("administrator count = %d, want 1", count)
	}
}

func TestHealthChecksDatabaseReadiness(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "health.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	a := &App{store: store}
	response := httptest.NewRecorder()
	a.handleHealth(response, httptest.NewRequest("GET", "/api/v1/health", nil))
	if response.Code != 200 {
		t.Fatalf("healthy database returned HTTP %d", response.Code)
	}
	if err := store.db.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	response = httptest.NewRecorder()
	a.handleHealth(response, httptest.NewRequest("GET", "/api/v1/health", nil))
	if response.Code != 503 {
		t.Fatalf("closed database returned HTTP %d, want 503", response.Code)
	}
}

func TestRetryNodeConfigSyncReturnsSuccessWhenNoAuthorizedNodes(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "config-sync.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	a := &App{store: store}
	response := httptest.NewRecorder()
	a.handleRetryNodeConfigSync(response, httptest.NewRequest("POST", "/api/v1/nodes/config-sync", nil))
	if response.Code != 200 {
		t.Fatalf("sync with no authorized nodes returned HTTP %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"ok":true`) {
		t.Fatalf("expected success response, got %s", response.Body.String())
	}
}

func TestBackupEndpointRequiresBearerAuthentication(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "backup-auth.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	a := &App{cfg: Config{DBPath: filepath.Join(t.TempDir(), "backup-auth.db")}, store: store, jwtKey: []byte("test-signing-key")}
	handler := a.Router(fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("test")}})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/backup", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated backup request returned HTTP %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestManagementEndpointsRequireAdminRole(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "role-auth.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.CreateUser("operator", "test-hash", "operator"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	operator, err := store.UserByUsername("operator")
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	a := &App{cfg: Config{DBPath: dbPath}, store: store, jwtKey: []byte("test-signing-key")}
	token, err := a.signToken(operator)
	if err != nil {
		t.Fatalf("signToken: %v", err)
	}

	handler := a.Router(fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("test")}})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("operator management request returned HTTP %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
	}
}

func TestOperatorCannotAccessAdministrativeRouteMatrix(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "role-matrix.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.CreateUser("operator", "test-hash", "operator"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	operator, err := store.UserByUsername("operator")
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	a := &App{cfg: Config{DBPath: dbPath}, store: store, jwtKey: []byte("test-signing-key")}
	token, err := a.signToken(operator)
	if err != nil {
		t.Fatalf("signToken: %v", err)
	}
	handler := a.Router(fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("test")}})

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/agents"},
		{http.MethodPut, "/api/v1/settings"},
		{http.MethodPost, "/api/v1/config/publish"},
		{http.MethodPost, "/api/v1/config/rollback"},
		{http.MethodGet, "/api/v1/logs"},
		{http.MethodPost, "/api/v1/restore"},
		{http.MethodDelete, "/api/v1/agents"},
		{http.MethodPost, "/api/v1/mihomo/update"},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusForbidden {
				t.Fatalf("operator request returned HTTP %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
			}
		})
	}
}

func TestSaveGlobalConfigRejectsInvalidDraftWithoutOverwriting(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "config-draft.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.UpdateSettings(map[string]string{"config_yaml": "mode: rule\nmixed-port: 7890\n"}); err != nil {
		t.Fatalf("seed config draft: %v", err)
	}
	a := &App{store: store}

	for name, body := range map[string]string{
		"empty":        `{"config_yaml":"  "}`,
		"invalid yaml": `{"config_yaml":"mode: [unterminated"}`,
		"empty map":    `{"config_yaml":"{}"}`,
		"non-object":   `{"config_yaml":"- one\n- two"}`,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/config/save", strings.NewReader(body))
			response := httptest.NewRecorder()
			a.handleSaveConfig(response, req)
			if response.Code < 400 || response.Code >= 500 {
				t.Fatalf("invalid draft returned HTTP %d: %s", response.Code, response.Body.String())
			}
			settings, err := store.GetSettings()
			if err != nil {
				t.Fatalf("GetSettings: %v", err)
			}
			if settings["config_yaml"] != "mode: rule\nmixed-port: 7890\n" {
				t.Fatalf("invalid draft overwrote saved configuration: %q", settings["config_yaml"])
			}
		})
	}
}

func TestSaveGlobalConfigRejectsOversizedRequest(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "config-size.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	a := &App{store: store}
	body := `{"config_yaml":"` + strings.Repeat("a", (2<<20)+1) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/save", strings.NewReader(body))
	response := httptest.NewRecorder()
	a.handleSaveConfig(response, req)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request returned HTTP %d, want %d: %s", response.Code, http.StatusRequestEntityTooLarge, response.Body.String())
	}
}

func TestSaveGlobalConfigAcceptsValidDraft(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "config-valid.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	a := &App{store: store}
	body := `{"config_yaml":"mode: rule\nmixed-port: 7890\ndns:\n  enable: true"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/save", strings.NewReader(body))
	response := httptest.NewRecorder()
	a.handleSaveConfig(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("valid draft returned HTTP %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "尚未发布") || !strings.Contains(response.Body.String(), "不会自动更新节点独立 YAML") {
		t.Fatalf("save response must clarify this only saves a draft: %s", response.Body.String())
	}
	settings, err := store.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if !strings.Contains(settings["config_yaml"], "mixed-port: 7890") {
		t.Fatalf("saved draft missing expected setting: %q", settings["config_yaml"])
	}
}

func TestRemovedContainerManagementEndpointsReturnNotFound(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "removed-container-api.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	a := &App{store: store, jwtKey: []byte("test-signing-key")}
	handler := a.Router(fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("test")}})
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/container/nodes"},
		{http.MethodPost, "/api/v1/agent/container/status"},
		{http.MethodGet, "/api/v1/agent/container/tasks/next"},
		{http.MethodPost, "/api/v1/agents/routeros-command"},
		{http.MethodGet, "/api/v1/agents/routeros-command-result"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusNotFound {
				t.Fatalf("removed endpoint returned HTTP %d, want 404", response.Code)
			}
		})
	}
}

func TestDeleteMihomoTemplateVersionRequiresAdminRole(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "template-delete-auth.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	if err := store.CreateUser("operator", "test-hash", "operator"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	operator, err := store.UserByUsername("operator")
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	a := &App{cfg: Config{DBPath: dbPath}, store: store, jwtKey: []byte("test-signing-key")}
	token, err := a.signToken(operator)
	if err != nil {
		t.Fatalf("signToken: %v", err)
	}

	handler := a.Router(fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("test")}})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/mihomo/template/2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusForbidden {
		t.Fatalf("operator template deletion returned HTTP %d, want %d; body=%s", response.Code, http.StatusForbidden, response.Body.String())
	}
}

func TestFaviconReturnsNoContentInsteadOfNotFound(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "favicon.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	a := &App{store: store}
	handler := a.Router(fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("test")}})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("favicon returned HTTP %d, want %d", response.Code, http.StatusNoContent)
	}
}

func TestAgentRuntimeEndpointsUseWebSocketOnly(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "runtime-routes.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.db.Close()

	a := &App{store: store, jwtKey: []byte("test-signing-key")}
	handler := a.Router(fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("test")}})
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/agent/config"},
		{http.MethodPost, "/api/v1/agent/heartbeat"},
		{http.MethodGet, "/api/v1/agent/command"},
		{http.MethodPost, "/api/v1/agent/command/ack"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code == http.StatusOK || response.Code == http.StatusAccepted {
				t.Fatalf("legacy HTTP runtime endpoint unexpectedly available: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}

	// Registration and the authenticated WebSocket runtime endpoint remain
	// registered; only legacy runtime config/heartbeat/command HTTP routes go.
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/agent/register"},
		{http.MethodGet, "/api/v1/agent/ws"},
	} {
		t.Run("retained "+tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code == http.StatusNotFound {
				t.Fatalf("required Agent endpoint missing: %s", tc.path)
			}
		})
	}
}
