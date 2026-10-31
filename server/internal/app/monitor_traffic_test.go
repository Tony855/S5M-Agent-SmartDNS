package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestMonitorTrafficReturnsBadGatewayOnUpstreamFailure(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
	}))
	defer upstream.Close()
	a := &App{cfg: Config{MihomoAPI: upstream.URL}}
	response := httptest.NewRecorder()
	a.handleMonitorTraffic(response, httptest.NewRequest(http.MethodGet, "/api/v1/monitor/traffic", nil))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadGateway)
	}
}

func TestMonitorTrafficConcurrentRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"downloadTotal":1000,"uploadTotal":2000,"connections":[]}`))
	}))
	defer upstream.Close()
	a := &App{cfg: Config{MihomoAPI: upstream.URL}}
	const requests = 32
	var wg sync.WaitGroup
	errCh := make(chan string, requests)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response := httptest.NewRecorder()
			a.handleMonitorTraffic(response, httptest.NewRequest(http.MethodGet, "/api/v1/monitor/traffic", nil))
			if response.Code != http.StatusOK {
				errCh <- "unexpected HTTP status"
				return
			}
			if !strings.Contains(response.Body.String(), `"conns":0`) {
				errCh <- response.Body.String()
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent traffic request failed: %s", err)
	}
}

func TestMonitorTrafficIncludesUpstreamStatusAndBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "authentication required", http.StatusUnauthorized)
	}))
	defer upstream.Close()
	a := &App{cfg: Config{MihomoAPI: upstream.URL}}
	response := httptest.NewRecorder()
	a.handleMonitorTraffic(response, httptest.NewRequest(http.MethodGet, "/api/v1/monitor/traffic", nil))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadGateway)
	}
	if !strings.Contains(response.Body.String(), "HTTP 401") || !strings.Contains(response.Body.String(), "authentication required") {
		t.Fatalf("response should include safe upstream diagnostic, got %s", response.Body.String())
	}
}

func TestMonitorTrafficIncludesConnectionError(t *testing.T) {
	a := &App{cfg: Config{MihomoAPI: "http://127.0.0.1:1"}}
	response := httptest.NewRecorder()
	a.handleMonitorTraffic(response, httptest.NewRequest(http.MethodGet, "/api/v1/monitor/traffic", nil))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadGateway)
	}
	if !strings.Contains(response.Body.String(), "连接主控 Mihomo API 失败") {
		t.Fatalf("response should explain connection failure, got %s", response.Body.String())
	}
}
