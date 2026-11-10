package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadMihomoAPIResponseEnforcesLimitWithoutContentLength(t *testing.T) {
	got, err := readMihomoAPIResponse(strings.NewReader("1234"), 4)
	if err != nil || string(got) != "1234" {
		t.Fatalf("readMihomoAPIResponse() = %q, %v; want exact-limit body", got, err)
	}
	if _, err := readMihomoAPIResponse(strings.NewReader("12345"), 4); err == nil {
		t.Fatal("response larger than configured limit was accepted")
	}
}

func TestMihomoInfoRejectsOversizedStreamingResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"version":"v1.19.33","extra":"`+strings.Repeat("x", maxMihomoAPIResponseBytes)+`"}`)
	}))
	defer server.Close()

	app := &App{cfg: Config{MihomoAPI: server.URL}}
	info := app.MihomoInfo()
	if info["online"] != false {
		t.Fatalf("oversized response marked Mihomo online: %#v", info)
	}
	if _, ok := info["error"]; !ok {
		t.Fatalf("oversized response did not expose a bounded diagnostic: %#v", info)
	}
}

func TestMihomoInfoAcceptsValidVersionResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"version":"v1.19.33","meta":true}`)
	}))
	defer server.Close()

	app := &App{cfg: Config{MihomoAPI: server.URL}}
	info := app.MihomoInfo()
	if info["online"] != true {
		t.Fatalf("valid version response was rejected: %#v", info)
	}
	version, ok := info["version"].(map[string]any)
	if !ok || version["version"] != "v1.19.33" {
		t.Fatalf("unexpected version payload: %#v", info["version"])
	}
}

func TestReloadMihomoBoundsErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, strings.Repeat("x", maxMihomoAPIErrorResponseBytes+1))
	}))
	defer server.Close()

	app := &App{cfg: Config{MihomoAPI: server.URL, MihomoConfigPath: "/tmp/config.yaml"}}
	err := app.ReloadMihomo()
	if err == nil {
		t.Fatal("ReloadMihomo accepted an error response")
	}
	if !strings.Contains(err.Error(), "超过") {
		t.Fatalf("oversized error response was not reported as bounded: %v", err)
	}
	if len(err.Error()) > 256 {
		t.Fatalf("error message grew with upstream response size: %d bytes", len(err.Error()))
	}
}

func TestRunningMihomoAPIVersionRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"version":"v1.19.33","extra":"`+strings.Repeat("x", 16<<10)+`"}`)
	}))
	defer server.Close()

	app := &App{cfg: Config{MihomoAPI: server.URL}}
	if _, err := app.runningMihomoAPIVersion(); err == nil {
		t.Fatal("runningMihomoAPIVersion accepted an oversized response")
	}
}
