package app

import "testing"

func TestParseMihomoVersion(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want string
	}{
		{name: "standard", out: "Mihomo Meta v1.19.10 linux amd64 with go1.24", want: "v1.19.10"},
		{name: "unknown output", out: "unexpected version output", want: "unknown"},
		{name: "incomplete version", out: "Mihomo Meta v1.19 linux amd64", want: "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseMihomoVersion([]byte(tt.out)); got != tt.want {
				t.Fatalf("parseMihomoVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindMihomoCompatibleAsset(t *testing.T) {
	assets := []mihomoReleaseAsset{
		{Name: "mihomo-linux-amd64-compatible.tar.gz", BrowserDownloadURL: "https://example.com/wrong.tar.gz"},
		{Name: "mihomo-linux-amd64-compatible-v1.gz", BrowserDownloadURL: "http://example.com/insecure.gz"},
		{Name: "mihomo-linux-amd64-compatible-v1.gz", BrowserDownloadURL: "https://example.com/mihomo.gz"},
		{Name: "mihomo-linux-arm64-compatible-v1.gz", BrowserDownloadURL: "https://example.com/arm.gz"},
	}
	if got := findMihomoCompatibleAsset(assets); got != "https://example.com/mihomo.gz" {
		t.Fatalf("findMihomoCompatibleAsset() = %q", got)
	}
	if got := findMihomoCompatibleAsset(nil); got != "" {
		t.Fatalf("findMihomoCompatibleAsset(nil) = %q, want empty", got)
	}
}

func TestIsGzipHeader(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "gzip magic", data: []byte{0x1f, 0x8b, 0x08}, want: true},
		{name: "HTML proxy error page", data: []byte("<h"), want: false},
		{name: "short response", data: []byte{0x1f}, want: false},
		{name: "empty response", data: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isGzipHeader(tt.data); got != tt.want {
				t.Fatalf("isGzipHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}
