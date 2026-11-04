package app

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type failingRandomSource struct{}

func (failingRandomSource) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func TestRandomHexFromReadsFullEntropy(t *testing.T) {
	got, err := randomHexFrom(bytes.NewReader([]byte{0x00, 0x01, 0xfe, 0xff}), 4)
	if err != nil {
		t.Fatalf("randomHexFrom returned error: %v", err)
	}
	if got != "0001feff" {
		t.Fatalf("randomHexFrom = %q, want %q", got, "0001feff")
	}
}

func TestRandomHexFromRejectsEntropyFailure(t *testing.T) {
	got, err := randomHexFrom(failingRandomSource{}, 32)
	if err == nil {
		t.Fatal("randomHexFrom accepted an entropy source failure")
	}
	if got != "" {
		t.Fatalf("randomHexFrom returned partial secret %q", got)
	}
	if !strings.Contains(err.Error(), "entropy unavailable") {
		t.Fatalf("error does not preserve entropy failure: %v", err)
	}
}

func TestRandomHexFromRejectsShortRead(t *testing.T) {
	got, err := randomHexFrom(bytes.NewReader([]byte{0x01, 0x02}), 4)
	if err == nil {
		t.Fatal("randomHexFrom accepted a short entropy read")
	}
	if got != "" {
		t.Fatalf("randomHexFrom returned partial secret %q", got)
	}
}

func TestRandomHexFromRejectsNonPositiveLength(t *testing.T) {
	for _, n := range []int{0, -1} {
		if got, err := randomHexFrom(bytes.NewReader(nil), n); err == nil || got != "" {
			t.Fatalf("randomHexFrom(%d) = (%q, %v), want empty value and error", n, got, err)
		}
	}
}

func TestJWTSecretPreservesConfiguredValue(t *testing.T) {
	const configured = "operator-managed-secret"
	if got := jwtSecret(configured); got != configured {
		t.Fatalf("jwtSecret(%q) = %q, want configured value unchanged", configured, got)
	}
}

func TestJWTSecretGeneratesStrongFallback(t *testing.T) {
	got := jwtSecret("")
	if len(got) != 64 {
		t.Fatalf("generated JWT secret has %d hex characters, want 64", len(got))
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("generated JWT secret is not hexadecimal: %v", err)
	}
}
