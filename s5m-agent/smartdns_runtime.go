package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const smartDNSConfigPath = "/data/smartdns.conf"
const smartDNSPreflightOutputLimit = 8 << 10
const smartDNSRestartCooldown = 30 * time.Second

var errSmartDNSRestartCooldown = errors.New("SmartDNS restart is cooling down")

type smartDNSRestartGate struct {
	mu          sync.Mutex
	lastAttempt time.Time
}

func (g *smartDNSRestartGate) TryAcquire(now time.Time, cooldown time.Duration) (bool, time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.lastAttempt.IsZero() {
		remaining := cooldown - now.Sub(g.lastAttempt)
		if remaining > 0 {
			return false, remaining
		}
	}
	g.lastAttempt = now
	return true, 0
}

var smartDNSRestartLimiter smartDNSRestartGate

func restartSmartDNSService() error {
	allowed, _ := smartDNSRestartLimiter.TryAcquire(time.Now(), smartDNSRestartCooldown)
	if !allowed {
		return errSmartDNSRestartCooldown
	}
	return exec.Command("/command/s6-svc", "-r", "/run/service/smartdns").Run()
}

type boundedDiagnosticBuffer struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	truncated bool
}

func (b *boundedDiagnosticBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := smartDNSPreflightOutputLimit - b.buffer.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buffer.Write(p[:remaining])
			b.truncated = true
		} else {
			_, _ = b.buffer.Write(p)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	// Report the full write as consumed: the child process must not fail just
	// because diagnostic output is capped.
	return len(p), nil
}

func (b *boundedDiagnosticBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func (b *boundedDiagnosticBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

var smartDNSConfigMu sync.Mutex

func readSmartDNSConfig() ([]byte, error) {
	smartDNSConfigMu.Lock()
	defer smartDNSConfigMu.Unlock()
	return readSmartDNSConfigAt(smartDNSConfigPath)
}

// readSmartDNSConfigAt opens the file without following symlinks, then validates
// the opened descriptor rather than trusting a path-level Lstat that can race
// with replacement of the file.
func readSmartDNSConfigAt(path string) ([]byte, error) {
	data, err := readSmartDNSFileNoFollow(path, 8<<10)
	if err != nil {
		return nil, fmt.Errorf("读取 SmartDNS 配置失败: %w", err)
	}
	if err := validateSmartDNSConfig(data); err != nil {
		return nil, fmt.Errorf("当前 SmartDNS 配置不符合安全策略: %w", err)
	}
	return data, nil
}

// readSmartDNSFileNoFollow reads a bounded regular file without following a
// symlink. It is also used for rollback snapshots, which must preserve bytes
// even when an older configuration no longer passes the current policy.
func readSmartDNSFileNoFollow(path string, maxBytes int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("SmartDNS 配置路径不是普通文件")
	}
	if info.Size() <= 0 || info.Size() > maxBytes {
		return nil, fmt.Errorf("SmartDNS 配置文件为空或超过 %d 字节", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("SmartDNS 配置文件为空或超过 %d 字节", maxBytes)
	}
	return data, nil
}

// Indirect directory sync so failure handling can be exercised deterministically.
var smartDNSDirectorySync = syncSmartDNSDirectory

var smartDNSDirectiveAllowlist = map[string]bool{
	"bind": true, "bind-tcp": true,
	"server": true, "server-tcp": true, "server-tls": true,
	"server-https": true, "server-quic": true,
	"cache-size": true, "prefetch-domain": true, "serve-expired": true,
	"log-level": true, "log-console": true, "log-syslog": true,
	"dualstack-ip-selection": true, "rr-ttl": true, "rr-ttl-min": true,
	"rr-ttl-max": true, "force-AAAA-SOA": true, "force-qtype-SOA": true,
	"speed-check-mode": true, "response-mode": true,
}

var smartDNSControlChars = regexp.MustCompile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]")

// validateSmartDNSConfig accepts only resolver-related directives. It deliberately
// rejects include/plugin/exec-style directives so a remote config cannot load
// arbitrary files or start unrelated processes inside the Agent container.
func validateSmartDNSConfig(data []byte) error {
	if len(data) == 0 || len(data) > 8<<10 {
		return fmt.Errorf("SmartDNS 配置不能为空且不得超过 8 KiB")
	}
	if smartDNSControlChars.Match(data) {
		return fmt.Errorf("SmartDNS 配置包含非法控制字符")
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	usable := 0
	bindUDP, bindTCP := false, false
	encryptedUpstream := false
	for lineNo, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return fmt.Errorf("第 %d 行配置格式无效", lineNo+1)
		}
		directive := fields[0]
		if !smartDNSDirectiveAllowlist[directive] {
			return fmt.Errorf("第 %d 行不允许配置指令 %q", lineNo+1, directive)
		}
		if strings.ContainsAny(line, "`$") {
			return fmt.Errorf("第 %d 行包含不允许的特殊内容", lineNo+1)
		}
		if directive == "bind" || directive == "bind-tcp" {
			if len(fields) != 2 || fields[1] != "127.0.0.1:6053" {
				return fmt.Errorf("第 %d 行监听地址必须保持在容器回环地址 127.0.0.1:6053", lineNo+1)
			}
			if directive == "bind" {
				bindUDP = true
			} else {
				bindTCP = true
			}
		}
		if directive == "server" || directive == "server-tcp" {
			return fmt.Errorf("第 %d 行必须使用加密 DNS 上游（server-tls/server-https/server-quic），禁止明文 DNS", lineNo+1)
		}
		if directive == "server-tls" || directive == "server-https" || directive == "server-quic" {
			encryptedUpstream = true
		}
		if strings.HasPrefix(directive, "server") && len(fields) < 2 {
			return fmt.Errorf("第 %d 行上游 DNS 地址不能为空", lineNo+1)
		}
		usable++
	}
	if usable == 0 {
		return fmt.Errorf("SmartDNS 配置没有有效指令")
	}
	if !bindUDP || !bindTCP {
		return fmt.Errorf("必须同时配置 bind 127.0.0.1:6053 和 bind-tcp 127.0.0.1:6053")
	}
	if !encryptedUpstream {
		return fmt.Errorf("SmartDNS 至少需要一个加密上游（server-tls/server-https/server-quic）")
	}
	return nil
}

func smartDNSBinaryInfoAvailable(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0
}

func smartDNSBinaryAvailable() bool {
	info, err := os.Stat("/usr/sbin/smartdns")
	return err == nil && smartDNSBinaryInfoAvailable(info)
}

// appendSmartDNSStatusError preserves the first actionable diagnostic while
// allowing status collection to report independent failures when no earlier
// failure has already been recorded.
func appendSmartDNSStatusError(status map[string]any, message string) {
	if strings.TrimSpace(message) == "" {
		return
	}
	previous, _ := status["smartdns_last_error"].(string)
	if strings.TrimSpace(previous) == "" {
		status["smartdns_last_error"] = message
	}
}

type smartDNSStatusDependencies struct {
	binaryInfo func() (os.FileInfo, error)
	readConfig func(string) ([]byte, error)
	version    func() ([]byte, error)
	process    func() ([]byte, error)
	probe      func() bool
	restart    func() error
	waitHealthy func(time.Duration) bool
}

func defaultSmartDNSStatusDependencies() smartDNSStatusDependencies {
	return smartDNSStatusDependencies{
		binaryInfo: func() (os.FileInfo, error) { return os.Stat("/usr/sbin/smartdns") },
		readConfig: os.ReadFile,
		version: func() ([]byte, error) {
			return exec.Command("/usr/sbin/smartdns", "-v").CombinedOutput()
		},
		process: func() ([]byte, error) {
			return exec.Command("pidof", "smartdns").CombinedOutput()
		},
		probe: probeSmartDNSDNS,
		restart: restartSmartDNSService,
		waitHealthy: waitForSmartDNSHealthy,
	}
}

func collectSmartDNSStatus(status map[string]any) {
	collectSmartDNSStatusWithDependencies(status, defaultSmartDNSStatusDependencies())
}

// collectSmartDNSStatusWithDependencies keeps host interactions injectable so
// every status and failure path can be tested without a live SmartDNS daemon.
func collectSmartDNSStatusWithDependencies(status map[string]any, deps smartDNSStatusDependencies) {
	status["smartdns_available"] = false
	status["smartdns_running"] = false
	status["smartdns_dns_healthy"] = false
	status["smartdns_version"] = ""
	status["smartdns_config_sha256"] = ""
	status["smartdns_last_error"] = ""

	info, statErr := deps.binaryInfo()
	if statErr != nil || !smartDNSBinaryInfoAvailable(info) {
		appendSmartDNSStatusError(status, "SmartDNS 二进制不存在、不可执行或文件类型无效")
		return
	}
	status["smartdns_available"] = true

	if data, err := deps.readConfig(smartDNSConfigPath); err == nil {
		sum := sha256.Sum256(bytes.TrimSpace(data))
		status["smartdns_config_sha256"] = hex.EncodeToString(sum[:])
		if configErr := validateSmartDNSConfig(data); configErr != nil {
			appendSmartDNSStatusError(status, "SmartDNS 配置未通过加密上游策略校验: "+safeSmartDNSDiagnostic(configErr.Error()))
		}
	} else {
		appendSmartDNSStatusError(status, "读取 SmartDNS 配置失败: "+safeSmartDNSDiagnostic(err.Error()))
	}

	if output, err := deps.version(); err == nil {
		version := strings.TrimSpace(string(output))
		if version == "" {
			appendSmartDNSStatusError(status, "SmartDNS 版本命令返回空结果")
		} else {
			if len(version) > 128 {
				version = version[:128]
			}
			status["smartdns_version"] = version
		}
	} else {
		appendSmartDNSStatusError(status, "读取 SmartDNS 版本失败: "+safeSmartDNSDiagnostic(strings.TrimSpace(string(output)+" "+err.Error())))
	}

	processOutput, processErr := deps.process()
	processHealthy := processErr == nil && len(bytes.TrimSpace(processOutput)) > 0
	dnsHealthy := processHealthy && deps.probe != nil && deps.probe()
	if processHealthy {
		status["smartdns_running"] = true
	}
	if dnsHealthy {
		status["smartdns_dns_healthy"] = true
		return
	}

	// s6 supervises SmartDNS when it exits, but a live yet unresponsive
	// resolver is not automatically restarted. Ask s6 to restart it once,
	// then require a real UDP+TCP DNS probe before reporting it healthy.
	if deps.restart == nil || deps.waitHealthy == nil {
		if !processHealthy {
			appendSmartDNSStatusError(status, "SmartDNS 进程未运行或进程检测失败")
		} else {
			appendSmartDNSStatusError(status, "SmartDNS UDP/TCP DNS 查询探测失败")
		}
		return
	}
	if err := deps.restart(); err != nil {
		if errors.Is(err, errSmartDNSRestartCooldown) {
			appendSmartDNSStatusError(status, "SmartDNS 仍未通过 DNS 健康检查；重启处于 30 秒冷却期，主控应继续使用备用 DNS")
			return
		}
		appendSmartDNSStatusError(status, "SmartDNS 异常，s6 重启失败: "+safeSmartDNSDiagnostic(err.Error()))
		return
	}
	if deps.waitHealthy(5 * time.Second) {
		status["smartdns_running"] = true
		status["smartdns_dns_healthy"] = true
		status["smartdns_recovery"] = "restarted"
		return
	}
	appendSmartDNSStatusError(status, "SmartDNS 已尝试由 s6 重启，但 UDP/TCP DNS 健康检查仍失败；主控应切换备用 DNS")
}

func smartDNSConfigAlreadyApplied(path string, candidate []byte) (bool, error) {
	current, err := readSmartDNSFileNoFollow(path, 8<<10)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return bytes.Equal(current, candidate), nil
}

func smartDNSReplayIsHealthy(path string, candidate []byte, probe func() bool) (bool, error) {
	applied, err := smartDNSConfigAlreadyApplied(path, candidate)
	if err != nil || !applied {
		return false, err
	}
	if probe == nil || !probe() {
		return false, nil
	}
	return true, nil
}

func writeSmartDNSConfig(data []byte) (string, error) {
	smartDNSConfigMu.Lock()
	defer smartDNSConfigMu.Unlock()
	if err := validateSmartDNSConfig(data); err != nil {
		return "", err
	}
	if !smartDNSBinaryAvailable() {
		return "", fmt.Errorf("当前 Agent 镜像未安装 SmartDNS")
	}
	if err := os.MkdirAll("/data", 0700); err != nil {
		return "", fmt.Errorf("创建 SmartDNS 数据目录失败")
	}

	// Commands are redelivered until the controller durably stores their ACK.
	// Treat an identical already-applied config as success without restarting
	// SmartDNS again, making configure_smartdns safe under ACK loss/replay.
	replayHealthy, readErr := smartDNSReplayIsHealthy(smartDNSConfigPath, data, probeSmartDNSDNS)
	if readErr != nil {
		return "", fmt.Errorf("读取现有 SmartDNS 配置失败，拒绝重复应用: %w", readErr)
	}
	if replayHealthy {
		sum := sha256.Sum256(bytes.TrimSpace(data))
		return hex.EncodeToString(sum[:]), nil
	}
	alreadyApplied, readErr := smartDNSConfigAlreadyApplied(smartDNSConfigPath, data)
	if readErr != nil {
		return "", fmt.Errorf("读取现有 SmartDNS 配置失败，拒绝重复应用: %w", readErr)
	}
	if alreadyApplied {
		return "", fmt.Errorf("SmartDNS 配置文件已是目标版本，但 UDP/TCP DNS 健康检查失败")
	}

	// Validate the candidate with the actual SmartDNS parser on a temporary
	// loopback port before replacing the live configuration.
	candidateLines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for i, line := range candidateLines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 2 && (fields[0] == "bind" || fields[0] == "bind-tcp") {
			candidateLines[i] = fields[0] + " 127.0.0.1:16053"
		}
	}
	candidate := strings.Join(candidateLines, "\n")
	tmp, err := os.CreateTemp("/data", ".smartdns-check-*.conf")
	if err != nil {
		return "", fmt.Errorf("创建 SmartDNS 校验文件失败")
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if _, err := tmp.WriteString(candidate); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/smartdns", "-f", "-x", "-p", "-", "-c", tmpPath)
	// Capture both streams so configuration parser errors are actionable rather
	// than being reduced to the generic "exit status 1" from cmd.Wait().
	var stdout, stderr boundedDiagnosticBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	output := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("SmartDNS 配置预检启动失败: %w", err)
	}
	go func() { output <- cmd.Wait() }()
	select {
	case err := <-output:
		if err != nil {
			diagnostic := strings.TrimSpace(stdout.String() + "\n" + stderr.String() + "\n" + err.Error())
			if stdout.Truncated() || stderr.Truncated() {
				diagnostic += "（预检输出已截断）"
			}
			return "", fmt.Errorf("SmartDNS 配置预检失败: %s", safeSmartDNSDiagnostic(diagnostic))
		}
		return "", fmt.Errorf("SmartDNS 配置预检进程意外退出")
	case <-time.After(350 * time.Millisecond):
		_ = cmd.Process.Kill()
		waitErr := <-output
		// A parser failure can race the 350 ms startup window. Do not treat
		// an already-exited nonzero process as a successful long-running check.
		// ExitCode -1 means the process was terminated by our kill signal.
		if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() != -1 {
			if waitErr != nil {
				diagnostic := strings.TrimSpace(stdout.String() + "\n" + stderr.String() + "\n" + waitErr.Error())
				if stdout.Truncated() || stderr.Truncated() {
					diagnostic += "（预检输出已截断）"
				}
				return "", fmt.Errorf("SmartDNS 配置预检失败: %s", safeSmartDNSDiagnostic(diagnostic))
			}
			return "", fmt.Errorf("SmartDNS 配置预检进程意外退出")
		}
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-output
		return "", fmt.Errorf("SmartDNS 配置预检超时")
	}

	livePath := smartDNSConfigPath
	backupPath := livePath + ".previous"
	oldData, hadOldConfig, err := backupSmartDNSConfig(livePath, backupPath)
	if err != nil {
		return "", fmt.Errorf("备份旧 SmartDNS 配置失败: %w", err)
	}
	liveTmp, err := os.CreateTemp(filepath.Dir(livePath), ".smartdns-live-*.conf")
	if err != nil {
		return "", err
	}
	liveTmpPath := liveTmp.Name()
	defer os.Remove(liveTmpPath)
	if err := liveTmp.Chmod(0600); err != nil {
		_ = liveTmp.Close()
		return "", err
	}
	if _, err := liveTmp.Write(data); err != nil {
		_ = liveTmp.Close()
		return "", err
	}
	if err := liveTmp.Sync(); err != nil {
		_ = liveTmp.Close()
		return "", err
	}
	if err := liveTmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(liveTmpPath, livePath); err != nil {
		return "", err
	}
	if err := smartDNSDirectorySync(filepath.Dir(livePath)); err != nil {
		restoreErr := restoreSmartDNSConfig(livePath, oldData, hadOldConfig)
		// A directory fsync can fail after rename has already taken effect.
		// Verify the actual file contents before deciding whether recovery is
		// possible; then restart and probe the restored service.
		if restoreErr != nil && !smartDNSConfigMatches(livePath, oldData, hadOldConfig) {
			return "", fmt.Errorf("提交配置目录失败，且旧配置恢复失败: %v (原始错误: %w)", restoreErr, err)
		}
		if restartErr := exec.Command("/command/s6-svc", "-r", "/run/service/smartdns").Run(); restartErr != nil {
			return "", fmt.Errorf("提交配置目录失败；配置已恢复，但重启旧服务失败: %w", restartErr)
		}
		if !waitForSmartDNSHealthy(5 * time.Second) {
			return "", fmt.Errorf("提交配置目录失败；旧配置已恢复，但 UDP/TCP DNS 未恢复: %w", err)
		}
		return "", fmt.Errorf("提交配置目录失败，已恢复旧配置且 UDP/TCP DNS 验证通过: %w", err)
	}
	oldPID, _ := exec.Command("pidof", "smartdns").Output()
	oldPID = bytes.TrimSpace(oldPID)
	if err := exec.Command("/command/s6-svc", "-r", "/run/service/smartdns").Run(); err != nil {
		restored, restoreErr := restoreSmartDNSConfigVerified(livePath, oldData, hadOldConfig)
		if !restored {
			return "", fmt.Errorf("重启 SmartDNS 失败且恢复旧配置失败: %w", restoreErr)
		}
		restartErr := exec.Command("/command/s6-svc", "-r", "/run/service/smartdns").Run()
		if restartErr != nil {
			return "", fmt.Errorf("重启 SmartDNS 失败；旧配置文件已恢复，但再次启动服务失败: %w", restartErr)
		}
		if !waitForSmartDNSHealthy(5 * time.Second) {
			if restoreErr != nil {
				return "", fmt.Errorf("重启新配置失败；旧配置内容已恢复（目录同步警告: %v），但旧服务未通过 UDP/TCP DNS 验证", restoreErr)
			}
			return "", fmt.Errorf("重启新配置失败；旧配置文件已恢复，但旧服务仍未通过 UDP/TCP DNS 验证")
		}
		if restoreErr != nil {
			return "", fmt.Errorf("重启新配置失败；旧配置已恢复且 UDP/TCP DNS 验证通过，但目录同步失败: %w", restoreErr)
		}
		return "", fmt.Errorf("重启新配置失败，已恢复旧配置且 UDP/TCP DNS 验证通过")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		newPID, pidErr := exec.Command("pidof", "smartdns").Output()
		if pidErr == nil && len(bytes.TrimSpace(newPID)) > 0 && !bytes.Equal(bytes.TrimSpace(newPID), oldPID) && probeSmartDNSDNS() {
			sum := sha256.Sum256(bytes.TrimSpace(data))
			if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
				// The new configuration is already proven healthy. Keep the backup
				// for manual recovery and do not report an applied config as failed.
				fmt.Printf("SmartDNS: 无法清理旧配置备份: %v\n", err)
			} else {
				_ = smartDNSDirectorySync(filepath.Dir(livePath))
			}
			return hex.EncodeToString(sum[:]), nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	restored, restoreErr := restoreSmartDNSConfigVerified(livePath, oldData, hadOldConfig)
	if !restored {
		return "", fmt.Errorf("SmartDNS 重载后未恢复运行，且回滚失败: %w", restoreErr)
	}
	if restartErr := exec.Command("/command/s6-svc", "-r", "/run/service/smartdns").Run(); restartErr != nil {
		return "", fmt.Errorf("SmartDNS 重载后 DNS 健康检查失败；旧配置内容已恢复，但再次启动服务失败: %w", restartErr)
	}
	if !waitForSmartDNSHealthy(5 * time.Second) {
		if restoreErr != nil {
			return "", fmt.Errorf("新配置 DNS 验证失败；旧配置内容已恢复（目录同步警告: %v），但旧服务未通过 UDP/TCP 验证", restoreErr)
		}
		return "", fmt.Errorf("新配置 DNS 验证失败；已恢复旧配置，但旧配置 DNS 仍未通过 UDP/TCP 验证")
	}
	if restoreErr != nil {
		return "", fmt.Errorf("新配置 DNS 验证失败；旧配置已恢复且 UDP/TCP DNS 已恢复，但目录同步失败: %w", restoreErr)
	}
	return "", fmt.Errorf("新配置 DNS 验证失败，已恢复旧配置且 UDP/TCP DNS 已恢复")
}

// restoreSmartDNSConfig restores the previous file atomically. If there was no
// previous config, it removes the newly installed file instead of leaving a
// configuration that the caller has already reported as failed.
// backupSmartDNSConfig snapshots the live configuration and durably writes
// its rollback copy before callers are allowed to replace the live file.
func backupSmartDNSConfig(livePath, backupPath string) ([]byte, bool, error) {
	oldData, err := readSmartDNSFileNoFollow(livePath, 8<<10)
	if os.IsNotExist(err) {
		// A backup from an earlier installation must never be mistaken for
		// the rollback point of this first-time configuration. Remove it and
		// durably record that no previous live config exists.
		if removeErr := os.Remove(backupPath); removeErr == nil {
			if syncErr := smartDNSDirectorySync(filepath.Dir(backupPath)); syncErr != nil {
				return nil, false, fmt.Errorf("同步 SmartDNS 备份目录失败: %w", syncErr)
			}
		} else if !os.IsNotExist(removeErr) {
			return nil, false, fmt.Errorf("清理过期 SmartDNS 备份失败: %w", removeErr)
		}
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := writeSmartDNSFileAtomically(backupPath, oldData, 0600); err != nil {
		return nil, false, err
	}
	return oldData, true, nil
}

func smartDNSConfigMatches(path string, expected []byte, shouldExist bool) bool {
	actual, err := readSmartDNSFileNoFollow(path, 8<<10)
	if !shouldExist {
		return os.IsNotExist(err)
	}
	return err == nil && bytes.Equal(actual, expected)
}

// restoreSmartDNSConfigVerified distinguishes a failed rollback from a
// directory-fsync error that happened after the rename already restored the
// expected bytes. Callers must still report the durability warning, but should
// restart and health-check the restored service whenever the file is correct.
func restoreSmartDNSConfigVerified(livePath string, oldData []byte, hadOld bool) (bool, error) {
	err := restoreSmartDNSConfig(livePath, oldData, hadOld)
	if err == nil {
		return true, nil
	}
	if smartDNSConfigMatches(livePath, oldData, hadOld) {
		return true, err
	}
	return false, err
}

func restoreSmartDNSConfig(livePath string, oldData []byte, hadOld bool) error {
	if !hadOld {
		if err := os.Remove(livePath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return smartDNSDirectorySync(filepath.Dir(livePath))
	}
	return writeSmartDNSFileAtomically(livePath, oldData, 0600)
}

func writeSmartDNSFileAtomically(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".smartdns-restore-*.conf")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return smartDNSDirectorySync(filepath.Dir(path))
}

func syncSmartDNSDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func waitForSmartDNSHealthy(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if exec.Command("pidof", "smartdns").Run() == nil && probeSmartDNSDNS() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

var (
	smartDNSURLUserInfoPattern = regexp.MustCompile(`(?i)(https?://)[^/@\s]+@`)
	smartDNSBearerPattern      = regexp.MustCompile(`(?i)(bearer\s+)[^\s,;]+`)
	smartDNSCredentialPattern  = regexp.MustCompile(`(?i)\b(password|passwd|token|secret|api[_-]?key)=([^\s&;]+)`)
)

func safeSmartDNSDiagnostic(message string) string {
	message = strings.Join(strings.Fields(message), " ")
	message = smartDNSURLUserInfoPattern.ReplaceAllString(message, "${1}[REDACTED]@")
	message = smartDNSBearerPattern.ReplaceAllString(message, "${1}[REDACTED]")
	message = smartDNSCredentialPattern.ReplaceAllString(message, "${1}=[REDACTED]")
	if len(message) > 500 {
		message = message[:500]
		// Byte-based truncation can split a multi-byte diagnostic character.
		// Trim to the last valid UTF-8 boundary before appending the ellipsis.
		for !utf8.ValidString(message) {
			message = message[:len(message)-1]
		}
		message += "…"
	}
	return message
}

func probeSmartDNSDNS() bool {
	return probeSmartDNSDNSAt("127.0.0.1:6053") &&
		probeSmartDNSDNSTCPAt("127.0.0.1:6053")
}

func probeSmartDNSDNSAt(address string) bool {
	conn, err := net.DialTimeout("udp", address, 800*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(800 * time.Millisecond))
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], 0x534d)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range []string{"example", "com"} {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1) // QNAME terminator, A, IN
	if _, err := conn.Write(query); err != nil {
		return false
	}
	response := make([]byte, 1500)
	n, err := conn.Read(response)
	if err != nil || n < 12 {
		return false
	}
	if binary.BigEndian.Uint16(response[0:2]) != binary.BigEndian.Uint16(query[0:2]) {
		return false
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	// A healthy A lookup must be a complete DNS response with NOERROR and
	// at least one answer. Reject mismatched IDs, truncated responses,
	// NXDOMAIN, REFUSED, SERVFAIL, and empty NOERROR responses.
	answerCount := binary.BigEndian.Uint16(response[6:8])
	questionCount := binary.BigEndian.Uint16(response[4:6])
	return flags&0x8000 != 0 && flags&0x0200 == 0 &&
		flags&0x7800 == 0 && flags&0x000f == 0 &&
		questionCount == 1 && answerCount > 0
}

// probeSmartDNSDNSTCPAt verifies a complete DNS-over-TCP response, including
// the two-byte message length and matching transaction ID.
func probeSmartDNSDNSTCPAt(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 800*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(800 * time.Millisecond))
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], 0x534d)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range []string{"example", "com"} {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err := conn.Write(frame); err != nil {
		return false
	}
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return false
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n < 12 || n > 4096 {
		return false
	}
	response := make([]byte, n)
	if _, err := io.ReadFull(conn, response); err != nil {
		return false
	}
	// Reject responses that do not belong to this query. A stray or
	// spoofed TCP DNS frame must not make the resolver look healthy.
	if binary.BigEndian.Uint16(response[:2]) != binary.BigEndian.Uint16(query[:2]) {
		return false
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	questionCount := binary.BigEndian.Uint16(response[4:6])
	answerCount := binary.BigEndian.Uint16(response[6:8])
	// Keep TCP health criteria aligned with the UDP probe: only a complete,
	// standard NOERROR response to our single question with an answer is healthy.
	return flags&0x8000 != 0 && flags&0x0200 == 0 &&
		flags&0x7800 == 0 && flags&0x000f == 0 &&
		questionCount == 1 && answerCount > 0
}
