package app

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestFindMihomoCompatibleAssetRequiresOfficialDigestAndURL(t *testing.T) {
	const version = "v1.19.33"
	const digest = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	asset := mihomoReleaseAsset{
		Name: "mihomo-linux-amd64-compatible-" + version + ".gz",
		BrowserDownloadURL: "https://github.com/MetaCubeX/mihomo/releases/download/" + version + "/mihomo-linux-amd64-compatible-" + version + ".gz",
		Size: 3,
		Digest: digest,
	}
	got, err := findMihomoCompatibleAsset([]mihomoReleaseAsset{asset}, version)
	if err != nil || got != asset {
		t.Fatalf("findMihomoCompatibleAsset() = %+v, %v; want %+v", got, err, asset)
	}
	if _, err := findMihomoCompatibleAsset(nil, version); err == nil {
		t.Fatal("missing release asset must be rejected")
	}

	tests := []struct {
		name string
		mutate func(*mihomoReleaseAsset)
	}{
		{name: "missing digest", mutate: func(a *mihomoReleaseAsset) { a.Digest = "" }},
		{name: "invalid digest", mutate: func(a *mihomoReleaseAsset) { a.Digest = "sha256:bad" }},
		{name: "wrong host", mutate: func(a *mihomoReleaseAsset) { a.BrowserDownloadURL = strings.Replace(a.BrowserDownloadURL, "github.com", "example.com", 1) }},
		{name: "wrong repository path", mutate: func(a *mihomoReleaseAsset) { a.BrowserDownloadURL = strings.Replace(a.BrowserDownloadURL, "MetaCubeX/mihomo", "attacker/mihomo", 1) }},
		{name: "query string", mutate: func(a *mihomoReleaseAsset) { a.BrowserDownloadURL += "?redirect=1" }},
		{name: "version mismatch", mutate: func(a *mihomoReleaseAsset) { a.Name = "mihomo-linux-amd64-compatible-v1.19.32.gz" }},
		{name: "oversized compressed asset", mutate: func(a *mihomoReleaseAsset) { a.Size = maxMihomoCompressedAssetBytes + 1 }},
		{name: "empty compressed asset", mutate: func(a *mihomoReleaseAsset) { a.Size = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := asset
			tt.mutate(&candidate)
			if err := validateMihomoReleaseAsset(candidate, version); err == nil {
				t.Fatal("invalid release asset was accepted")
			}
		})
	}
}

func TestVerifyMihomoDownloadedAssetChecksSizeAndDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mihomo.gz")
	data := []byte("abc")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	asset := mihomoReleaseAsset{Size: int64(len(data)), Digest: "sha256:" + hex.EncodeToString(sum[:])}
	if err := verifyMihomoDownloadedAsset(path, asset); err != nil {
		t.Fatalf("valid downloaded asset rejected: %v", err)
	}
	asset.Digest = "sha256:" + strings.Repeat("0", sha256.Size*2)
	if err := verifyMihomoDownloadedAsset(path, asset); err == nil {
		t.Fatal("digest mismatch was accepted")
	}
	asset.Size++
	if err := verifyMihomoDownloadedAsset(path, asset); err == nil {
		t.Fatal("size mismatch was accepted")
	}
}

func TestDecompressMihomoAssetValidatesGzipAndOutput(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte("mihomo-binary")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := decompressMihomoAsset(bytes.NewReader(compressed.Bytes()), &output); err != nil {
		t.Fatalf("valid gzip asset rejected: %v", err)
	}
	if output.String() != "mihomo-binary" {
		t.Fatalf("decompressed output = %q", output.String())
	}
	if err := decompressMihomoAsset(strings.NewReader("not gzip"), io.Discard); err == nil {
		t.Fatal("invalid gzip stream was accepted")
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


func TestDecompressMihomoAssetEnforcesOutputLimitAndChecksum(t *testing.T) {
	makeGzip := func(data []byte) []byte {
		var compressed bytes.Buffer
		writer := gzip.NewWriter(&compressed)
		if _, err := writer.Write(data); err != nil { t.Fatal(err) }
		if err := writer.Close(); err != nil { t.Fatal(err) }
		return compressed.Bytes()
	}
	var limited bytes.Buffer
	if err := decompressMihomoAssetWithLimit(bytes.NewReader(makeGzip([]byte("12345"))), &limited, 4); err == nil {
		t.Fatal("decompressed output exceeding the configured limit was accepted")
	}
	valid := makeGzip([]byte("checksum"))
	valid[len(valid)-1] ^= 0xff
	if err := decompressMihomoAsset(bytes.NewReader(valid), io.Discard); err == nil {
		t.Fatal("gzip checksum mismatch was accepted")
	}
}
