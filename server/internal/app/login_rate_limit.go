package app

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	loginAttemptWindow = time.Minute
	loginAttemptLimit = 10
	loginAttemptMaxKeys = 4096
	loginAttemptRetention = 10 * time.Minute
)

type loginAttempt struct {
	windowStart time.Time
	lastSeen time.Time
	count int
}

type loginAttemptLimiter struct {
	mu sync.Mutex
	entries map[string]loginAttempt
}

// loginClientKey trusts proxy-supplied addresses only when the immediate peer
// is loopback. The bundled nginx installer proxies from 127.0.0.1 and sets
// X-Real-IP; direct clients cannot spoof these headers.
func loginClientKey(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil { remoteHost = strings.TrimSpace(r.RemoteAddr) }
	remoteIP := net.ParseIP(remoteHost)
	if remoteIP != nil && remoteIP.IsLoopback() {
		for _, candidate := range []string{r.Header.Get("X-Real-IP"), firstForwardedFor(r.Header.Get("X-Forwarded-For"))} {
			if ip := net.ParseIP(strings.TrimSpace(candidate)); ip != nil {
				return ip.String()
			}
		}
	}
	if remoteIP != nil { return remoteIP.String() }
	if remoteHost == "" { return "unknown" }
	return remoteHost
}

func firstForwardedFor(value string) string {
	if i := strings.IndexByte(value, ','); i >= 0 { return strings.TrimSpace(value[:i]) }
	return strings.TrimSpace(value)
}

func (l *loginAttemptLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	key = strings.TrimSpace(key)
	if key == "" { key = "unknown" }
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil { l.entries = make(map[string]loginAttempt) }
	for existing, entry := range l.entries {
		if now.Sub(entry.lastSeen) > loginAttemptRetention { delete(l.entries, existing) }
	}
	entry, exists := l.entries[key]
	if !exists && len(l.entries) >= loginAttemptMaxKeys {
		oldestKey := ""
		var oldest time.Time
		for existing, candidate := range l.entries {
			if oldestKey == "" || candidate.lastSeen.Before(oldest) {
				oldestKey, oldest = existing, candidate.lastSeen
			}
		}
		if oldestKey != "" { delete(l.entries, oldestKey) }
	}
	if !exists || entry.windowStart.IsZero() || now.Sub(entry.windowStart) >= loginAttemptWindow {
		entry = loginAttempt{windowStart: now}
	}
	entry.lastSeen = now
	if entry.count >= loginAttemptLimit {
		l.entries[key] = entry
		return false, entry.windowStart.Add(loginAttemptWindow).Sub(now)
	}
	entry.count++
	l.entries[key] = entry
	return true, 0
}

func (l *loginAttemptLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.entries, strings.TrimSpace(key))
	l.mu.Unlock()
}

var dummyLoginPasswordHash = func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("s5m-invalid-login-dummy-password"), bcrypt.DefaultCost)
	if err != nil {
		panic("initialize dummy login password hash: " + err.Error())
	}
	return hash
}()
