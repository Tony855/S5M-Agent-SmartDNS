package app

import (
	"bufio"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type App struct {
	cfg    Config
	store  *Store
	jwtKey []byte

	agentWSMu          sync.Mutex
	agentWSGeneration  map[string]uint64
	agentWSConnections map[string]*agentWSConnection
	agentHeartbeatAt   map[string]int64
	agentTelemetryPersistAt map[string]time.Time
	browserWSMu        sync.Mutex
	browserWSClients   map[*browserEventClient]struct{}
	browserTicketMu    sync.Mutex
	browserTickets     map[string]browserWSTicket
	mihomoUpdateMu     sync.Mutex
	mihomoUpdateTask   *mihomoUpdateTask
	mihomoUpdateTasks  map[string]*mihomoUpdateTask
	mihomoUpdateOrder  []string
}

func New(cfg Config) (*App, error) {
	st, err := OpenStore(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	a := &App{cfg: cfg, store: st, jwtKey: []byte(cfg.JWTSecret)}
	if err := a.ensureTemplateSchema(); err != nil {
		_ = st.db.Close()
		return nil, fmt.Errorf("初始化 Mihomo 模板版本表失败: %w", err)
	}
	if err := a.ensureAdmin(); err != nil {
		_ = st.db.Close()
		return nil, err
	}
	return a, nil
}

func (a *App) ensureAdmin() error {
	n, err := a.store.CountUsers()
	if err != nil {
		return fmt.Errorf("检查管理员账户失败: %w", err)
	}
	if n > 0 {
		return nil
	}
	pass := strings.TrimSpace(a.cfg.AdminPass)
	if pass == "" {
		return fmt.Errorf("首次启动必须设置 S5M_ADMIN_PASSWORD；拒绝使用默认管理员密码")
	}
	if strings.TrimSpace(a.cfg.AdminUser) == "" {
		return fmt.Errorf("首次启动必须设置有效的 S5M_ADMIN_USER")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("生成管理员密码哈希失败: %w", err)
	}
	return a.store.CreateUser(a.cfg.AdminUser, string(h), "admin")
}

func (a *App) handleHealth(w http.ResponseWriter, _ *http.Request) {
	if err := a.store.db.Ping(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "error", "database": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": "ok"})
}
func (a *App) Router(static fs.FS) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", a.handleHealth)
	mux.HandleFunc("POST /api/v1/auth/login", a.handleLogin)
	mux.HandleFunc("GET /api/v1/subscribe", a.handleSubscribe)
	mux.HandleFunc("POST /api/v1/agent/register", a.handleAgentRegister)
	mux.HandleFunc("GET /api/v1/agent/ws", a.handleAgentWebSocket)
	mux.HandleFunc("GET /api/v1/events/ws", a.handleBrowserEventsWebSocket)

	authed := map[string]http.HandlerFunc{
		"GET /api/v1/backup":                       a.handleDownloadBackup,
		"GET /api/v1/auth/me":                      a.handleMe,
		"POST /api/v1/events/ticket":               a.handleCreateBrowserEventsTicket,
		"GET /api/v1/agents":                       a.handleGetAgents,
		"POST /api/v1/agents/generate":             a.handleGenerateAgentToken,
		"GET /api/v1/agents/kernel-update-info":    a.handleAgentMihomoUpdateInfo,
		"POST /api/v1/agents/kernel-update":        a.handleQueueMihomoUpdate,
		"DELETE /api/v1/agents":                    a.handleDeleteAgent,
		"PUT /api/v1/auth/password":                a.handlePassword,
		"GET /api/v1/settings":                     a.handleGetSettings,
		"GET /api/v1/mihomo/template":              a.handleGetMihomoTemplate,
		"PUT /api/v1/mihomo/template":              a.handleSaveMihomoTemplateDraft,
		"POST /api/v1/mihomo/template/validate":    a.handleValidateMihomoTemplate,
		"POST /api/v1/mihomo/template/publish":     a.handlePublishMihomoTemplate,
		"DELETE /api/v1/mihomo/template/{version}": a.handleDeleteMihomoTemplateVersion,
		"GET /api/v1/mihomo/template/nodes":        a.handleGetNodeTemplateStatus,
		"POST /api/v1/mihomo/template/apply":       a.handleApplyMihomoTemplate,
		"POST /api/v1/mihomo/template/rollback":    a.handleRollbackNodeTemplate,
		"PUT /api/v1/settings":                     a.handleUpdateSettings,
		"GET /api/v1/nodes/{code}/config":          a.handleGetNodeConfig,
		"PUT /api/v1/nodes/{code}/config":          a.handleSaveNodeConfig,
		"POST /api/v1/nodes/config-sync":           a.handleRetryNodeConfigSync,
		"GET /api/v1/instances":                    a.handleListInstances,
		"POST /api/v1/instances":                   a.handleCreateInstance,
		"DELETE /api/v1/instances/{id}":            a.handleDeleteInstance,
		"GET /api/v1/proxies":                      a.handleListProxies,
		"POST /api/v1/proxies":                     a.handleCreateProxy,
		"POST /api/v1/proxies/import":              a.handleImportProxies,
		"PUT /api/v1/proxies/{id}":                 a.handleUpdateProxy,
		"DELETE /api/v1/proxies/{id}":              a.handleDeleteProxy,
		"GET /api/v1/config/preview":               a.handlePreview,
		"POST /api/v1/config/save":                 a.handleSaveConfig,
		"POST /api/v1/config/publish":              a.handlePublish,
		"GET /api/v1/config/versions":              a.handleVersions,
		"POST /api/v1/config/rollback":             a.handleRollback,
		"GET /api/v1/monitor/overview":             a.handleOverview,
		"GET /api/v1/monitor/traffic":              a.handleMonitorTraffic,
		"GET /api/v1/mihomo/status":                a.handleMihomoStatus,
		"POST /api/v1/mihomo/update":               a.handleUpdateMihomo,
		"GET /api/v1/logs":                         a.handleGetLogs,
		"POST /api/v1/restore":                     a.handleRestoreBackup,
	}
	// Only explicitly read-only/user-scoped endpoints are available to any
	// authenticated account. Mutating and infrastructure-wide endpoints require admin.
	userScoped := map[string]bool{
		"GET /api/v1/auth/me": true,
	}
	for pat, h := range authed {
		handler := a.auth(h)
		if !userScoped[pat] {
			handler = a.auth(a.requireAdmin(h))
		}
		mux.HandleFunc(pat, handler)
	}

	// Browsers request this conventional icon path automatically. Return 204 when no icon is bundled.
	// This avoids treating a harmless browser request as an application/API warning.
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.Handle("/", http.FileServer(http.FS(static)))
	return withRecover(mux)
}

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Hijack preserves WebSocket upgrade support through the HTTP status logger.
// Gorilla WebSocket requires http.Hijacker to take ownership of the connection.
func (w *statusResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("底层 ResponseWriter 不支持 HTTP Hijacker")
	}
	return hijacker.Hijack()
}

var _ http.Hijacker = (*statusResponseWriter)(nil)

func withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if e := recover(); e != nil {
				slog.Error("系统发生 Panic 崩溃", "error", e, "path", r.URL.Path)
				writeErr(w, 500, "服务器内部错误")
			}
		}()
		sw := &statusResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		if sw.status >= 400 {
			slog.Warn("HTTP 请求异常", "method", r.Method, "path", r.URL.Path, "status", sw.status, "ip", r.RemoteAddr)
		}
	})
}
