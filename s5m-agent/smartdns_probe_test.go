package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBoundedDiagnosticBufferCapsOutput(t *testing.T) {
	var output boundedDiagnosticBuffer
	large := bytes.Repeat([]byte("x"), smartDNSPreflightOutputLimit+1024)
	written, err := output.Write(large)
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if written != len(large) {
		t.Fatalf("Write consumed %d bytes, want %d", written, len(large))
	}
	if got := len(output.String()); got != smartDNSPreflightOutputLimit {
		t.Fatalf("buffer length = %d, want %d", got, smartDNSPreflightOutputLimit)
	}
	if !output.Truncated() {
		t.Fatal("buffer did not report truncated output")
	}
}

func TestBoundedDiagnosticBufferAcceptsExactLimit(t *testing.T) {
	var output boundedDiagnosticBuffer
	data := bytes.Repeat([]byte("a"), smartDNSPreflightOutputLimit)
	if _, err := output.Write(data); err != nil {
		t.Fatal(err)
	}
	if output.Truncated() {
		t.Fatal("exact-limit output must not be marked truncated")
	}
	if output.String() != string(data) {
		t.Fatal("buffer content differs from input")
	}
}

func TestProbeSmartDNSDNSAtRequiresSuccessfulAnswer(t *testing.T) {
	tests := []struct {
		name        string
		flags       uint16
		answerCount uint16
		want        bool
	}{
		{name: "successful A answer", flags: 0x8180, answerCount: 1, want: true},
		{name: "NOERROR without answers", flags: 0x8180, answerCount: 0, want: false},
		{name: "NXDOMAIN", flags: 0x8183, answerCount: 0, want: false},
		{name: "SERVFAIL", flags: 0x8182, answerCount: 0, want: false},
		{name: "REFUSED", flags: 0x8185, answerCount: 0, want: false},
		{name: "not a DNS response", flags: 0x0100, answerCount: 1, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
			if err != nil {
				t.Fatalf("listen UDP: %v", err)
			}
			defer conn.Close()

			done := make(chan error, 1)
			go func() {
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				query := make([]byte, 1500)
				n, client, err := conn.ReadFromUDP(query)
				if err != nil {
					done <- err
					return
				}
				response := append([]byte(nil), query[:n]...)
				binary.BigEndian.PutUint16(response[2:4], tt.flags)
				binary.BigEndian.PutUint16(response[6:8], tt.answerCount)
				if tt.answerCount > 0 {
					// Compressed owner name (pointer to QNAME), A/IN, TTL 60, 1.2.3.4.
					response = append(response, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
						0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 2, 3, 4)
				}
				_, err = conn.WriteToUDP(response, client)
				done <- err
			}()

			got := probeSmartDNSDNSAt(conn.LocalAddr().String())
			if got != tt.want {
				t.Errorf("probeSmartDNSDNSAt() = %v, want %v", got, tt.want)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("DNS test server: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("DNS test server did not finish")
			}
		})
	}
}

func TestProbeSmartDNSDNSAtRejectsMismatchedTransactionID(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	done := make(chan error, 1)
	go func() {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		query := make([]byte, 1500)
		n, client, err := conn.ReadFromUDP(query)
		if err != nil {
			done <- err
			return
		}
		response := append([]byte(nil), query[:n]...)
		binary.BigEndian.PutUint16(response[:2], 0xffff)
		binary.BigEndian.PutUint16(response[2:4], 0x8180)
		binary.BigEndian.PutUint16(response[6:8], 1)
		response = append(response, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 2, 3, 4)
		_, err = conn.WriteToUDP(response, client)
		done <- err
	}()

	if probeSmartDNSDNSAt(conn.LocalAddr().String()) {
		t.Fatal("probe accepted a response with a mismatched transaction ID")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProbeSmartDNSDNSTCPAt(t *testing.T) {
	for _, answerCount := range []uint16{0, 1} {
		t.Run(map[bool]string{true: "answer", false: "empty"}[answerCount > 0], func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				var size [2]byte
				if _, err = io.ReadFull(conn, size[:]); err != nil {
					done <- err
					return
				}
				query := make([]byte, int(binary.BigEndian.Uint16(size[:])))
				if _, err = io.ReadFull(conn, query); err != nil {
					done <- err
					return
				}
				binary.BigEndian.PutUint16(query[2:4], 0x8180)
				binary.BigEndian.PutUint16(query[6:8], answerCount)
				if answerCount > 0 {
					query = append(query, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 2, 3, 4)
				}
				binary.BigEndian.PutUint16(size[:], uint16(len(query)))
				if _, err = conn.Write(size[:]); err == nil {
					_, err = conn.Write(query)
				}
				done <- err
			}()
			got := probeSmartDNSDNSTCPAt(listener.Addr().String())
			if got != (answerCount > 0) {
				t.Fatalf("probe = %v, want %v", got, answerCount > 0)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRestoreSmartDNSConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "smartdns.conf")
	if err := os.WriteFile(path, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreSmartDNSConfig(path, []byte("old"), true); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "old" {
		t.Fatalf("restored config = %q, err=%v", got, err)
	}
	if err := restoreSmartDNSConfig(path, nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected removed config, stat err=%v", err)
	}
}

func TestRestoreSmartDNSConfigReportsDirectorySyncFailureAfterRestore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "smartdns.conf")
	if err := os.WriteFile(path, []byte("new config"), 0600); err != nil {
		t.Fatal(err)
	}
	originalSync := smartDNSDirectorySync
	smartDNSDirectorySync = func(string) error { return os.ErrInvalid }
	defer func() { smartDNSDirectorySync = originalSync }()

	err := restoreSmartDNSConfig(path, []byte("old config"), true)
	if err == nil {
		t.Fatal("expected directory sync failure")
	}
	if !smartDNSConfigMatches(path, []byte("old config"), true) {
		t.Fatal("rollback did not restore the old file despite sync failure")
	}
}

func TestRestoreSmartDNSConfigVerifiedContinuesAfterDirectorySyncFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "smartdns.conf")
	if err := os.WriteFile(path, []byte("new config"), 0600); err != nil {
		t.Fatal(err)
	}
	originalSync := smartDNSDirectorySync
	smartDNSDirectorySync = func(string) error { return os.ErrInvalid }
	defer func() { smartDNSDirectorySync = originalSync }()

	restored, err := restoreSmartDNSConfigVerified(path, []byte("old config"), true)
	if !restored {
		t.Fatalf("expected restored content to be recoverable, err=%v", err)
	}
	if err == nil {
		t.Fatal("expected directory sync warning to be preserved")
	}
	if !smartDNSConfigMatches(path, []byte("old config"), true) {
		t.Fatal("old config content was not restored")
	}
}

func TestRestoreSmartDNSConfigVerifiedRejectsUnrestoredContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "smartdns.conf")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	restored, err := restoreSmartDNSConfigVerified(path, []byte("old config"), true)
	if restored {
		t.Fatal("directory target must not be considered restored")
	}
	if err == nil {
		t.Fatal("expected restore error")
	}
}

func TestValidateSmartDNSConfigRequiresEncryptedUpstream(t *testing.T) {
	secure := []byte("bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nserver-tls 1.1.1.1:853 -host-name cloudflare-dns.com\n")
	if err := validateSmartDNSConfig(secure); err != nil {
		t.Fatalf("valid encrypted upstream rejected: %v", err)
	}
	plain := []byte("bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nserver 223.5.5.5\n")
	if err := validateSmartDNSConfig(plain); err == nil {
		t.Fatal("plaintext DNS upstream must be rejected")
	}
	missing := []byte("bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\n")
	if err := validateSmartDNSConfig(missing); err == nil {
		t.Fatal("config without encrypted upstream must be rejected")
	}
}

func TestBackupSmartDNSConfigPreservesLiveFileOnBackupFailure(t *testing.T) {
	t.Run("existing live config remains unchanged", func(t *testing.T) {
		root := t.TempDir()
		livePath := filepath.Join(root, "smartdns.conf")
		if err := os.WriteFile(livePath, []byte("old live config"), 0600); err != nil {
			t.Fatal(err)
		}
		blocker := filepath.Join(root, "not-a-directory")
		if err := os.WriteFile(blocker, []byte("blocker"), 0600); err != nil {
			t.Fatal(err)
		}
		_, _, err := backupSmartDNSConfig(livePath, filepath.Join(blocker, "backup.conf"))
		if err == nil {
			t.Fatal("expected backup failure")
		}
		got, readErr := os.ReadFile(livePath)
		if readErr != nil {
			t.Fatalf("live config became unreadable: %v", readErr)
		}
		if string(got) != "old live config" {
			t.Fatalf("live config changed after backup failure: %q", got)
		}
	})

	t.Run("missing live config needs no backup", func(t *testing.T) {
		livePath := filepath.Join(t.TempDir(), "missing.conf")
		data, hadOld, err := backupSmartDNSConfig(livePath, livePath+".previous")
		if err != nil {
			t.Fatalf("backup missing config: %v", err)
		}
		if hadOld || data != nil {
			t.Fatalf("expected no previous config, got hadOld=%v data=%q", hadOld, data)
		}
	})
}

func TestBackupSmartDNSConfigRemovesStaleBackupWhenLiveConfigMissing(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "smartdns.conf")
	backupPath := livePath + ".previous"
	if err := os.WriteFile(backupPath, []byte("stale backup"), 0600); err != nil {
		t.Fatal(err)
	}
	data, hadOld, err := backupSmartDNSConfig(livePath, backupPath)
	if err != nil {
		t.Fatalf("backup missing live config: %v", err)
	}
	if hadOld || data != nil {
		t.Fatalf("expected no previous live config, hadOld=%v data=%q", hadOld, data)
	}
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("stale backup still exists, stat err=%v", err)
	}
}

func TestBackupSmartDNSConfigDoesNotProceedWhenStaleBackupCleanupCannotSync(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "smartdns.conf")
	backupPath := livePath + ".previous"
	if err := os.WriteFile(backupPath, []byte("stale backup"), 0600); err != nil {
		t.Fatal(err)
	}
	originalSync := smartDNSDirectorySync
	smartDNSDirectorySync = func(string) error { return os.ErrInvalid }
	defer func() { smartDNSDirectorySync = originalSync }()

	_, hadOld, err := backupSmartDNSConfig(livePath, backupPath)
	if err == nil {
		t.Fatal("expected stale backup cleanup directory sync failure")
	}
	if hadOld {
		t.Fatal("missing live config must not be reported as having an old config")
	}
	if _, statErr := os.Stat(backupPath); !os.IsNotExist(statErr) {
		t.Fatalf("stale backup unexpectedly remains, stat err=%v", statErr)
	}
}

func TestWriteSmartDNSFileAtomicallyFailureModes(t *testing.T) {
	t.Run("backup directory unavailable", func(t *testing.T) {
		root := t.TempDir()
		blocker := filepath.Join(root, "not-a-directory")
		if err := os.WriteFile(blocker, []byte("blocker"), 0600); err != nil {
			t.Fatal(err)
		}
		backupPath := filepath.Join(blocker, "smartdns.conf.previous")
		if err := writeSmartDNSFileAtomically(backupPath, []byte("old config"), 0600); err == nil {
			t.Fatal("expected backup write to fail when parent is not a directory")
		}
	})

	t.Run("atomic replacement target is a directory", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "smartdns.conf")
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatal(err)
		}
		if err := writeSmartDNSFileAtomically(target, []byte("new config"), 0600); err == nil {
			t.Fatal("expected atomic replacement of a directory to fail")
		}
		info, err := os.Stat(target)
		if err != nil {
			t.Fatalf("original target disappeared after failed replacement: %v", err)
		}
		if !info.IsDir() {
			t.Fatal("failed replacement unexpectedly changed the original target")
		}
	})
}

func TestRestoreSmartDNSConfigWhenPreviousConfigDoesNotExist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "smartdns.conf")
	if err := os.WriteFile(path, []byte("new config"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreSmartDNSConfig(path, nil, false); err != nil {
		t.Fatalf("rollback without previous config: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("new config should be removed on rollback, stat err=%v", err)
	}
}

func TestProbeSmartDNSDNSTCPAtRejectsInvalidDNSResponses(t *testing.T) {
	tests := []struct {
		name  string
		flags uint16
		qd    uint16
		an    uint16
	}{
		{name: "not a response", flags: 0x0100, qd: 1, an: 1},
		{name: "truncated", flags: 0x8380, qd: 1, an: 1},
		{name: "NXDOMAIN", flags: 0x8183, qd: 1, an: 0},
		{name: "SERVFAIL", flags: 0x8182, qd: 1, an: 0},
		{name: "empty question", flags: 0x8180, qd: 0, an: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil { t.Fatal(err) }
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil { done <- err; return }
				defer conn.Close()
				var size [2]byte
				if _, err = io.ReadFull(conn, size[:]); err != nil { done <- err; return }
				query := make([]byte, int(binary.BigEndian.Uint16(size[:])))
				if _, err = io.ReadFull(conn, query); err != nil { done <- err; return }
				binary.BigEndian.PutUint16(query[2:4], tt.flags)
				binary.BigEndian.PutUint16(query[4:6], tt.qd)
				binary.BigEndian.PutUint16(query[6:8], tt.an)
				if tt.an > 0 {
					query = append(query, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 2, 3, 4)
				}
				binary.BigEndian.PutUint16(size[:], uint16(len(query)))
				if _, err = conn.Write(size[:]); err == nil { _, err = conn.Write(query) }
				done <- err
			}()
			if probeSmartDNSDNSTCPAt(listener.Addr().String()) {
				t.Fatal("probe accepted an invalid DNS response")
			}
			if err := <-done; err != nil { t.Fatal(err) }
		})
	}
}

func TestProbeSmartDNSDNSTCPAtRejectsMismatchedTransactionID(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		var size [2]byte
		if _, err = io.ReadFull(conn, size[:]); err != nil {
			done <- err
			return
		}
		query := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if _, err = io.ReadFull(conn, query); err != nil {
			done <- err
			return
		}
		binary.BigEndian.PutUint16(query[:2], 0xffff)
		binary.BigEndian.PutUint16(query[2:4], 0x8180)
		binary.BigEndian.PutUint16(query[6:8], 1)
		query = append(query, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 2, 3, 4)
		binary.BigEndian.PutUint16(size[:], uint16(len(query)))
		if _, err = conn.Write(size[:]); err == nil {
			_, err = conn.Write(query)
		}
		done <- err
	}()

	if probeSmartDNSDNSTCPAt(listener.Addr().String()) {
		t.Fatal("probe accepted a response with a mismatched transaction ID")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}


func TestAppendSmartDNSStatusErrorPreservesFirstDiagnostic(t *testing.T) {
	status := map[string]any{"smartdns_last_error": ""}
	appendSmartDNSStatusError(status, "")
	if got := status["smartdns_last_error"]; got != "" {
		t.Fatalf("empty diagnostic changed status: %#v", got)
	}
	appendSmartDNSStatusError(status, "读取版本失败")
	appendSmartDNSStatusError(status, "进程未运行")
	if got := status["smartdns_last_error"]; got != "读取版本失败" {
		t.Fatalf("first actionable diagnostic was not preserved: %#v", got)
	}
}

func TestSmartDNSBinaryInfoAvailability(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "smartdns-executable")
	if err := os.WriteFile(executable, []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	nonExecutable := filepath.Join(dir, "smartdns-non-executable")
	if err := os.WriteFile(nonExecutable, []byte("binary"), 0600); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(dir, "smartdns-directory")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		path string
		want bool
	}{
		{name: "executable", path: executable, want: true},
		{name: "non executable", path: nonExecutable, want: false},
		{name: "directory", path: directory, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			info, err := os.Stat(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			if got := smartDNSBinaryInfoAvailable(info); got != tt.want {
				t.Fatalf("smartDNSBinaryInfoAvailable() = %v, want %v", got, tt.want)
			}
		})
	}
	if smartDNSBinaryInfoAvailable(nil) {
		t.Fatal("nil file info must not be considered an available binary")
	}
}


func TestCollectSmartDNSStatusWithDependencies(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "smartdns")
	if err := os.WriteFile(binary, []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	binaryInfo, err := os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	config := []byte("bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nserver-tls 1.1.1.1:853 -host-name cloudflare-dns.com\n")
	configHash := sha256.Sum256(bytes.TrimSpace(config))
	good := smartDNSStatusDependencies{
		binaryInfo: func() (os.FileInfo, error) { return binaryInfo, nil },
		readConfig: func(string) ([]byte, error) { return config, nil },
		version:    func() ([]byte, error) { return []byte("SmartDNS 1.2026"), nil },
		process:    func() ([]byte, error) { return []byte("1234"), nil },
		probe:      func() bool { return true },
	}
	assert := func(t *testing.T, status map[string]any, key string, want any) {
		t.Helper()
		if got := status[key]; got != want {
			t.Fatalf("%s = %#v, want %#v", key, got, want)
		}
	}

	t.Run("healthy", func(t *testing.T) {
		status := map[string]any{}
		collectSmartDNSStatusWithDependencies(status, good)
		assert(t, status, "smartdns_available", true)
		assert(t, status, "smartdns_running", true)
		assert(t, status, "smartdns_dns_healthy", true)
		assert(t, status, "smartdns_version", "SmartDNS 1.2026")
		assert(t, status, "smartdns_config_sha256", hex.EncodeToString(configHash[:]))
		assert(t, status, "smartdns_last_error", "")
	})

	t.Run("missing binary", func(t *testing.T) {
		deps := good
		deps.binaryInfo = func() (os.FileInfo, error) { return nil, os.ErrNotExist }
		status := map[string]any{}
		collectSmartDNSStatusWithDependencies(status, deps)
		assert(t, status, "smartdns_available", false)
		assert(t, status, "smartdns_running", false)
		assert(t, status, "smartdns_dns_healthy", false)
		assert(t, status, "smartdns_last_error", "SmartDNS 二进制不存在、不可执行或文件类型无效")
	})

	t.Run("config read failure still collects runtime state", func(t *testing.T) {
		deps := good
		deps.readConfig = func(string) ([]byte, error) { return nil, os.ErrPermission }
		status := map[string]any{}
		collectSmartDNSStatusWithDependencies(status, deps)
		assert(t, status, "smartdns_available", true)
		assert(t, status, "smartdns_running", true)
		assert(t, status, "smartdns_dns_healthy", true)
		if got, _ := status["smartdns_last_error"].(string); !strings.Contains(got, "读取 SmartDNS 配置失败") {
			t.Fatalf("config diagnostic missing: %q", got)
		}
	})

	t.Run("version command failure", func(t *testing.T) {
		deps := good
		deps.version = func() ([]byte, error) { return []byte("version unavailable"), os.ErrPermission }
		status := map[string]any{}
		collectSmartDNSStatusWithDependencies(status, deps)
		assert(t, status, "smartdns_running", true)
		assert(t, status, "smartdns_dns_healthy", true)
		if got, _ := status["smartdns_last_error"].(string); !strings.Contains(got, "读取 SmartDNS 版本失败") {
			t.Fatalf("version diagnostic missing: %q", got)
		}
	})

	t.Run("empty version output", func(t *testing.T) {
		deps := good
		deps.version = func() ([]byte, error) { return nil, nil }
		status := map[string]any{}
		collectSmartDNSStatusWithDependencies(status, deps)
		assert(t, status, "smartdns_version", "")
		assert(t, status, "smartdns_last_error", "SmartDNS 版本命令返回空结果")
	})

	t.Run("process detection failure", func(t *testing.T) {
		deps := good
		deps.process = func() ([]byte, error) { return nil, os.ErrNotExist }
		status := map[string]any{}
		collectSmartDNSStatusWithDependencies(status, deps)
		assert(t, status, "smartdns_available", true)
		assert(t, status, "smartdns_running", false)
		assert(t, status, "smartdns_dns_healthy", false)
		assert(t, status, "smartdns_last_error", "SmartDNS 进程未运行或进程检测失败")
	})

	t.Run("DNS probe failure", func(t *testing.T) {
		deps := good
		deps.probe = func() bool { return false }
		status := map[string]any{}
		collectSmartDNSStatusWithDependencies(status, deps)
		assert(t, status, "smartdns_running", true)
		assert(t, status, "smartdns_dns_healthy", false)
		assert(t, status, "smartdns_last_error", "SmartDNS UDP/TCP DNS 查询探测失败")
	})

	t.Run("restart recovers unhealthy resolver before fallback", func(t *testing.T) {
		deps := good
		probeCalls, restartCalls := 0, 0
		deps.probe = func() bool { probeCalls++; return probeCalls > 1 }
		deps.restart = func() error { restartCalls++; return nil }
		deps.waitHealthy = func(timeout time.Duration) bool { return true }
		status := map[string]any{}
		collectSmartDNSStatusWithDependencies(status, deps)
		assert(t, status, "smartdns_running", true)
		assert(t, status, "smartdns_dns_healthy", true)
		assert(t, status, "smartdns_recovery", "restarted")
		if restartCalls != 1 { t.Fatalf("restart calls = %d, want 1", restartCalls) }
	})

	t.Run("failed restart reports unhealthy for controller DNS fallback", func(t *testing.T) {
		deps := good
		deps.probe = func() bool { return false }
		restartCalls := 0
		deps.restart = func() error { restartCalls++; return os.ErrPermission }
		deps.waitHealthy = func(time.Duration) bool { t.Fatal("must not wait after restart command failure"); return false }
		status := map[string]any{}
		collectSmartDNSStatusWithDependencies(status, deps)
		assert(t, status, "smartdns_running", true)
		assert(t, status, "smartdns_dns_healthy", false)
		if restartCalls != 1 { t.Fatalf("restart calls = %d, want 1", restartCalls) }
		if got, _ := status["smartdns_last_error"].(string); !strings.Contains(got, "s6 重启失败") {
			t.Fatalf("restart failure diagnostic missing: %q", got)
		}
	})

	t.Run("restart command succeeds but DNS remains unhealthy", func(t *testing.T) {
		deps := good
		deps.probe = func() bool { return false }
		deps.restart = func() error { return nil }
		deps.waitHealthy = func(time.Duration) bool { return false }
		status := map[string]any{}
		collectSmartDNSStatusWithDependencies(status, deps)
		assert(t, status, "smartdns_dns_healthy", false)
		if got, _ := status["smartdns_last_error"].(string); !strings.Contains(got, "主控应切换备用 DNS") {
			t.Fatalf("fallback diagnostic missing: %q", got)
		}
	})

	t.Run("first failure diagnostic wins", func(t *testing.T) {
		deps := good
		deps.readConfig = func(string) ([]byte, error) { return nil, os.ErrPermission }
		deps.version = func() ([]byte, error) { return nil, os.ErrPermission }
		deps.process = func() ([]byte, error) { return nil, os.ErrNotExist }
		status := map[string]any{}
		collectSmartDNSStatusWithDependencies(status, deps)
		if got, _ := status["smartdns_last_error"].(string); !strings.Contains(got, "读取 SmartDNS 配置失败") {
			t.Fatalf("first diagnostic was not preserved: %q", got)
		}
	})
}

func TestSafeSmartDNSDiagnosticRedactsCredentials(t *testing.T) {
	input := "fetch https://admin:supersecret@example.com/config Bearer abc.def.ghi password=hunter2 token=secret123 api_key=key123"
	got := safeSmartDNSDiagnostic(input)
	for _, secret := range []string{"supersecret", "abc.def.ghi", "hunter2", "secret123", "key123", "admin:"} {
		if strings.Contains(got, secret) {
			t.Fatalf("diagnostic leaked %q: %s", secret, got)
		}
	}
	for _, marker := range []string{"[REDACTED]"} {
		if !strings.Contains(got, marker) {
			t.Fatalf("redaction marker %q missing: %s", marker, got)
		}
	}
}

func TestSafeSmartDNSDiagnosticNormalizesAndBoundsOutput(t *testing.T) {
	got := safeSmartDNSDiagnostic("  first\n\tsecond  " + strings.Repeat("x", 600))
	if strings.ContainsAny(got, "\n\t") {
		t.Fatalf("diagnostic whitespace was not normalized: %q", got)
	}
	if len(got) > 504 {
		t.Fatalf("diagnostic exceeds bounded length: %d", len(got))
	}
}

func TestSafeSmartDNSDiagnosticTruncatesAtUTF8Boundary(t *testing.T) {
	input := strings.Repeat("a", 499) + "中" + strings.Repeat("b", 20)
	got := safeSmartDNSDiagnostic(input)
	if !strings.Contains(got, "…") {
		t.Fatalf("expected truncation marker: %q", got)
	}
	if strings.ToValidUTF8(got, "") != got {
		t.Fatalf("diagnostic is not valid UTF-8: %q", got)
	}
	if !strings.HasPrefix(got, strings.Repeat("a", 499)) {
		t.Fatalf("valid prefix was not preserved: %q", got)
	}
}

func TestReadSmartDNSConfigAtRejectsSymlinksAndInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	valid := []byte("bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nserver-tls 1.1.1.1:853 -host-name cloudflare-dns.com\n")
	target := filepath.Join(dir, "target.conf")
	if err := os.WriteFile(target, valid, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readSmartDNSConfigAt(link); err == nil {
		t.Fatal("symlink configuration must be rejected")
	}
	if got, err := readSmartDNSConfigAt(target); err != nil || !bytes.Equal(got, valid) {
		t.Fatalf("valid regular config read = %q, err=%v", got, err)
	}
	empty := filepath.Join(dir, "empty.conf")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSmartDNSConfigAt(empty); err == nil {
		t.Fatal("empty config must be rejected")
	}
	large := filepath.Join(dir, "large.conf")
	if err := os.WriteFile(large, bytes.Repeat([]byte("x"), (8<<10)+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSmartDNSConfigAt(large); err == nil {
		t.Fatal("oversized config must be rejected")
	}
	if _, err := readSmartDNSConfigAt(dir); err == nil {
		t.Fatal("directory must be rejected")
	}
}


func TestReadSmartDNSFileNoFollowRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.conf")
	link := filepath.Join(dir, "smartdns.conf")
	if err := os.WriteFile(target, []byte("bind 127.0.0.1:6053\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readSmartDNSFileNoFollow(link, 8<<10); err == nil {
		t.Fatal("expected symlink read to be rejected")
	}
	if _, _, err := backupSmartDNSConfig(link, link+".previous"); err == nil {
		t.Fatal("expected symlink rollback snapshot to be rejected")
	}
}

func TestBoundedDiagnosticBufferConcurrentWrites(t *testing.T) {
	var output boundedDiagnosticBuffer
	const writers = 8
	const each = smartDNSPreflightOutputLimit
	var wg sync.WaitGroup
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			_, _ = output.Write(bytes.Repeat([]byte("z"), each))
		}()
	}
	wg.Wait()
	if got := len(output.String()); got != smartDNSPreflightOutputLimit {
		t.Fatalf("concurrent buffer length = %d, want %d", got, smartDNSPreflightOutputLimit)
	}
	if !output.Truncated() {
		t.Fatal("concurrent writes should mark output truncated")
	}
}


func TestSmartDNSConfigAlreadyApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "smartdns.conf")
	candidate := []byte("bind 127.0.0.1:6053\n")
	if err := os.WriteFile(path, candidate, 0600); err != nil {
		t.Fatal(err)
	}
	applied, err := smartDNSConfigAlreadyApplied(path, candidate)
	if err != nil || !applied {
		t.Fatalf("identical config: applied=%v err=%v", applied, err)
	}
	applied, err = smartDNSConfigAlreadyApplied(path, []byte("different config"))
	if err != nil || applied {
		t.Fatalf("different config: applied=%v err=%v", applied, err)
	}
	missing, err := smartDNSConfigAlreadyApplied(filepath.Join(dir, "missing.conf"), candidate)
	if err != nil || missing {
		t.Fatalf("missing config: applied=%v err=%v", missing, err)
	}
}


func TestSmartDNSReplayRequiresHealthyUDPAndTCPProbe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "smartdns.conf")
	candidate := []byte("bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nserver 1.1.1.1\n")
	if err := os.WriteFile(path, candidate, 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	ok, err := smartDNSReplayIsHealthy(path, candidate, func() bool {
		called = true
		return true
	})
	if err != nil || !ok || !called {
		t.Fatalf("healthy replay = %v, err=%v, probe called=%v", ok, err, called)
	}
	called = false
	ok, err = smartDNSReplayIsHealthy(path, candidate, func() bool {
		called = true
		return false
	})
	if err != nil || ok || !called {
		t.Fatalf("unhealthy replay = %v, err=%v, probe called=%v", ok, err, called)
	}
	called = false
	ok, err = smartDNSReplayIsHealthy(path, []byte("different"), func() bool {
		called = true
		return true
	})
	if err != nil || ok || called {
		t.Fatalf("different config replay = %v, err=%v, probe called=%v", ok, err, called)
	}
}


func TestSmartDNSRestartGateEnforcesCooldownAndAllowsRetry(t *testing.T) {
	gate := &smartDNSRestartGate{}
	start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	if ok, remaining := gate.TryAcquire(start, 30*time.Second); !ok || remaining != 0 {
		t.Fatalf("first restart acquire = %v, remaining=%v; want true, 0", ok, remaining)
	}
	if ok, remaining := gate.TryAcquire(start.Add(10*time.Second), 30*time.Second); ok || remaining != 20*time.Second {
		t.Fatalf("cooldown acquire = %v, remaining=%v; want false, 20s", ok, remaining)
	}
	if ok, remaining := gate.TryAcquire(start.Add(30*time.Second), 30*time.Second); !ok || remaining != 0 {
		t.Fatalf("retry after cooldown = %v, remaining=%v; want true, 0", ok, remaining)
	}
}

func TestSmartDNSRestartGateSerializesConcurrentAttempts(t *testing.T) {
	gate := &smartDNSRestartGate{}
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	const callers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	acquired := 0
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			if ok, _ := gate.TryAcquire(now, smartDNSRestartCooldown); ok {
				mu.Lock()
				acquired++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if acquired != 1 {
		t.Fatalf("concurrent restart acquisitions = %d, want exactly 1", acquired)
	}
}


func TestCollectSmartDNSStatusReportsFallbackDuringRestartCooldown(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "smartdns")
	if err := os.WriteFile(binary, []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	restartCalls := 0
	deps := smartDNSStatusDependencies{
		binaryInfo: func() (os.FileInfo, error) { return info, nil },
		readConfig: func(string) ([]byte, error) { return []byte("bind 127.0.0.1:6053\nbind-tcp 127.0.0.1:6053\nserver-tls 1.1.1.1:853 -host-name cloudflare-dns.com\n"), nil },
		version: func() ([]byte, error) { return []byte("SmartDNS test"), nil },
		process: func() ([]byte, error) { return []byte("1234"), nil },
		probe: func() bool { return false },
		restart: func() error { restartCalls++; return errSmartDNSRestartCooldown },
		waitHealthy: func(time.Duration) bool { t.Fatal("must not wait when restart is rate-limited"); return false },
	}
	status := map[string]any{}
	collectSmartDNSStatusWithDependencies(status, deps)
	if status["smartdns_running"] != true || status["smartdns_dns_healthy"] != false {
		t.Fatalf("cooldown must retain running-but-unhealthy state: %#v", status)
	}
	if restartCalls != 1 {
		t.Fatalf("restart attempts = %d, want 1", restartCalls)
	}
	message, _ := status["smartdns_last_error"].(string)
	if !strings.Contains(message, "备用 DNS") || !strings.Contains(message, "冷却期") {
		t.Fatalf("fallback/cooldown diagnostic missing: %q", message)
	}
}
