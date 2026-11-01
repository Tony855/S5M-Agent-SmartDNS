package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

// 结构体定义
type Config struct {
	CentralURL string `json:"central_url"`
	Token      string `json:"token"`
}

// 解密函数 (与你原本的实现保持一致)
func decrypt(cryptoText string) (string, error) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return string(ciphertext), nil
}

// Mihomo 配置目录统一由 MIHOMO_HOME 控制，默认使用持久化挂载目录 /data。
func mihomoHome() string {
	home := strings.TrimSpace(os.Getenv("MIHOMO_HOME"))
	if home == "" {
		return "/data"
	}
	return strings.TrimRight(home, "/")
}

// normalizeCentralURLInput defaults bare hostnames and IP addresses to HTTPS.
// Plain HTTP is only accepted when an operator explicitly opts in on a trusted network.
// newAgentRegistrationHTTPClient deliberately refuses redirects. The
// registration secret is in the POST body, so following a 307/308 redirect
// could disclose it to a different origin even when Authorization headers are
// stripped by net/http.
func newAgentRegistrationHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func normalizeCentralURLInput(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\r\n") {
		return "", fmt.Errorf("主控地址格式无效")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	return validateCentralURL(raw)
}

// validateCentralURL rejects malformed URLs and requires TLS by default.
// Plain HTTP is permitted only when an operator explicitly opts in for a trusted
// private network using S5M_ALLOW_INSECURE_HTTP=1. Registration sends the
// dedicated Agent credential in the request body, so transport encryption matters.
func validateCentralURL(raw string) (string, error) {
	centralURL := strings.TrimRight(strings.TrimSpace(raw), "/")
	parsedURL, err := url.Parse(centralURL)
	if err != nil || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" ||
		strings.ContainsAny(centralURL, "\r\n") {
		return "", fmt.Errorf("主控地址格式无效")
	}
	switch strings.ToLower(parsedURL.Scheme) {
	case "https":
	case "http":
		if strings.TrimSpace(os.Getenv("S5M_ALLOW_INSECURE_HTTP")) != "1" {
			return "", fmt.Errorf("为保护 Agent 专属 Token，默认必须使用 HTTPS；仅可信内网可显式设置 S5M_ALLOW_INSECURE_HTTP=1")
		}
	default:
		return "", fmt.Errorf("主控地址必须使用 HTTPS")
	}
	return centralURL, nil
}

func mihomoBinaryPath() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("S5M_ROUTEROS")), "1") {
		return filepath.Join(mihomoHome(), "bin", "mihomo")
	}
	return "/usr/local/bin/mihomo"
}

func mihomoConfigPath() string {
	return mihomoHome() + "/config.yaml"
}

// 独立的重载函数，防止变量冲突

// preserveMihomoSecret keeps the local external-controller credential stable.
// Mihomo may continue authenticating with its startup secret after a config reload,
// so accepting a controller-provided replacement can lock the Agent out of its API.
func preserveMihomoSecret(current, incoming map[string]interface{}) error {
	secret, ok := current["secret"].(string)
	secret = strings.TrimSpace(secret)
	if !ok || secret == "" {
		return fmt.Errorf("本地 Mihomo 配置缺少有效 secret，拒绝热更新以避免 API 鉴权失联")
	}
	incoming["secret"] = secret
	return nil
}

// isGeoIPDownloadFailure identifies external GeoIP download failures, not YAML errors.
func isGeoIPDownloadFailure(output []byte) bool {
	message := strings.ToLower(string(output))
	return strings.Contains(message, "can't download mmdb") ||
		strings.Contains(message, "cannot download mmdb") ||
		strings.Contains(message, "can't initial geoip") ||
		strings.Contains(message, "geoip dns fallback filter error")
}

// disableGeoIPFallbackForValidation changes only the in-memory validation copy.
// The original normalized config is restored before it is written to disk.
func disableGeoIPFallbackForValidation(cfg map[string]interface{}) bool {
	fallback, ok := cfg["fallback-filter"].(map[string]interface{})
	if !ok {
		return false
	}
	geoip, exists := fallback["geoip"]
	if !exists {
		return false
	}
	enabled, ok := geoip.(bool)
	if !ok || !enabled {
		return false
	}
	fallback["geoip"] = false
	return true
}

// safeMihomoValidationDiagnostic keeps useful error context without exposing local paths or secrets.
func safeMihomoValidationDiagnostic(output []byte) string {
	message := strings.TrimSpace(string(output))
	if message == "" {
		return "Mihomo 未提供详细错误输出"
	}
	lines := strings.Split(message, "\n")
	if len(lines) > 6 {
		lines = lines[len(lines)-6:]
	}
	message = strings.Join(lines, " | ")
	message = regexp.MustCompile(`(?i)(["']?(?:secret|token|password|api[_-]?key)["']?\s*[:=]\s*)("[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*'|[^"'[:space:],;}{]+)`).ReplaceAllString(message, "$1\"[已隐藏]\"")
	message = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._~+/=-]+`).ReplaceAllString(message, "$1[已隐藏]")
	message = regexp.MustCompile(`([A-Za-z]:)?[/\\][^[:space:]\"']+`).ReplaceAllString(message, "[路径已隐藏]")
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > 700 {
		message = message[:700] + "…"
	}
	return message
}

// mergeConfig applies the complete controller-generated Mihomo YAML.
// The previous config is kept until Mihomo successfully reloads.
func validateMihomoConfigYAML(data []byte) (map[string]interface{}, error) {
	if len(data) == 0 || len(data) > 2*1024*1024 {
		return nil, fmt.Errorf("主控端配置为空或超过 2 MiB")
	}
	var cfg map[string]interface{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("主控端 Mihomo YAML 无效: %w", err)
	}
	if len(cfg) == 0 {
		return nil, fmt.Errorf("主控端 Mihomo 配置为空")
	}
	secret, ok := cfg["secret"].(string)
	if !ok || strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf("主控端配置缺少有效的 Mihomo secret，拒绝覆盖本地配置")
	}
	if _, ok := cfg["tun"].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("主控端配置缺少有效的 tun 配置块")
	}
	if _, ok := cfg["dns"].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("主控端配置缺少有效的 dns 配置块")
	}
	return cfg, nil
}

// controllerConfigPath stores the exact controller YAML separately from the
// Agent runtime config, which may contain dynamically resolved TUN exclusions.
func controllerConfigPath() string {
	return filepath.Join(mihomoHome(), "controller-config.yaml")
}

func configHashSource() ([]byte, error) {
	if data, err := os.ReadFile(controllerConfigPath()); err == nil && len(data) > 0 {
		return data, nil
	}
	return os.ReadFile(mihomoConfigPath())
}

// controllerConfigHash follows the WebSocket contract: hash exact payload bytes.
// Do not trim whitespace or re-serialize YAML before hashing.
// controllerConfigNeedsApply reports whether the exact controller payload has
// been committed as the last successfully reloaded configuration. A mismatch
// requires a reload even when config.yaml already contains identical YAML:
// the Agent may have restarted after the file rename but before Mihomo reload.
func controllerConfigNeedsApply(config []byte) bool {
	current, err := os.ReadFile(controllerConfigPath())
	return err != nil || len(current) == 0 || string(current) != string(config)
}

func controllerConfigHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// atomicWriteFile writes a complete file beside its destination, fsyncs it,
// atomically renames it into place, then fsyncs the containing directory.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".s5m-atomic-*")
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
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func writeControllerConfig(data []byte) error {
	return atomicWriteFile(controllerConfigPath(), data, 0600)
}

func centralHostname(centralURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(centralURL))
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSpace(parsed.Hostname()), ".")
}

func resolvedCentralRouteCIDRs(centralURL string) ([]string, error) {
	host := centralHostname(centralURL)
	if host == "" {
		return nil, fmt.Errorf("主控域名无效")
	}
	ips := []net.IP{}
	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
	} else {
		var err error
		ips, err = net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("解析主控域名 %s 失败: %w", host, err)
		}
	}
	seen := map[string]bool{}
	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		cidr := ""
		if v4 := ip.To4(); v4 != nil {
			cidr = v4.String() + "/32"
		} else if v6 := ip.To16(); v6 != nil {
			cidr = ip.String() + "/128"
		}
		if cidr != "" && !seen[cidr] {
			seen[cidr] = true
			result = append(result, cidr)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("主控域名 %s 没有可用的 A/AAAA 记录", host)
	}
	return result, nil
}

func managedRouteCIDRsPath() string {
	return filepath.Join(mihomoHome(), "controller-route-cidrs.json")
}

func readManagedRouteCIDRs() map[string]bool {
	data, err := os.ReadFile(managedRouteCIDRsPath())
	if err != nil {
		return map[string]bool{}
	}
	var values []string
	if json.Unmarshal(data, &values) != nil {
		return map[string]bool{}
	}
	result := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			result[value] = true
		}
	}
	return result
}

func writeManagedRouteCIDRs(values []string) error {
	data, err := json.Marshal(values)
	if err != nil {
		return err
	}
	return atomicWriteFile(managedRouteCIDRsPath(), data, 0600)
}

// ensureV2NetDirectRule keeps the S5M controller domain family out of proxy-node routing.
// TUN route-exclude-address is IP/CIDR-only; controller host IPs are separately excluded below.
func ensureV2NetDirectRule(cfg map[string]interface{}) bool {
	raw, ok := cfg["rules"].([]interface{})
	if !ok {
		raw = []interface{}{}
	}
	const rule = "DOMAIN-SUFFIX,v2net.cc,DIRECT"

	firstRuleAt := -1
	ruleCount := 0
	for i, item := range raw {
		if value, ok := item.(string); ok && strings.EqualFold(strings.TrimSpace(value), rule) {
			if firstRuleAt == -1 {
				firstRuleAt = i
			}
			ruleCount++
		}
	}

	// Remove existing copies first so a stale rule after MATCH cannot silently
	// leave controller traffic routed through the proxy.
	next := make([]interface{}, 0, len(raw)+1)
	for _, item := range raw {
		if value, ok := item.(string); ok && strings.EqualFold(strings.TrimSpace(value), rule) {
			continue
		}
		next = append(next, item)
	}

	insertAt := len(next)
	for i, item := range next {
		if value, ok := item.(string); ok {
			parts := strings.Split(strings.TrimSpace(value), ",")
			if len(parts) > 0 && strings.EqualFold(strings.TrimSpace(parts[0]), "MATCH") {
				insertAt = i
				break
			}
		}
	}
	if ruleCount == 1 && firstRuleAt >= 0 {
		matchBeforeRule := false
		for i := 0; i < firstRuleAt && i < len(raw); i++ {
			if value, ok := raw[i].(string); ok {
				parts := strings.Split(strings.TrimSpace(value), ",")
				if len(parts) > 0 && strings.EqualFold(strings.TrimSpace(parts[0]), "MATCH") {
					matchBeforeRule = true
					break
				}
			}
		}
		if !matchBeforeRule {
			return false
		}
	}
	next = append(next, nil)
	copy(next[insertAt+1:], next[insertAt:])
	next[insertAt] = rule
	cfg["rules"] = next
	return true
}

func setCentralRouteExclusions(cfg map[string]interface{}, centralURL string) ([]string, bool, error) {
	cidrs, err := resolvedCentralRouteCIDRs(centralURL)
	if err != nil {
		return nil, false, err
	}
	domainRuleChanged := ensureV2NetDirectRule(cfg)
	tun, ok := cfg["tun"].(map[string]interface{})
	if !ok {
		return nil, false, fmt.Errorf("Mihomo 配置缺少 tun 块")
	}
	managed := readManagedRouteCIDRs()
	values, _ := tun["route-exclude-address"].([]interface{})
	seen := map[string]bool{}
	next := make([]interface{}, 0, len(values)+len(cidrs))
	changed := domainRuleChanged
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			continue
		}
		text = strings.TrimSpace(text)
		if text == "" || seen[text] {
			continue
		}
		if managed[text] {
			isCurrent := false
			for _, cidr := range cidrs {
				if text == cidr {
					isCurrent = true
					break
				}
			}
			if !isCurrent {
				changed = true
				continue
			}
		}
		seen[text] = true
		next = append(next, text)
	}
	for _, cidr := range cidrs {
		if !seen[cidr] {
			seen[cidr] = true
			next = append(next, cidr)
			changed = true
		}
	}
	for oldCIDR := range managed {
		found := false
		for _, newCIDR := range cidrs {
			if oldCIDR == newCIDR {
				found = true
				break
			}
		}
		if !found {
			changed = true
		}
	}
	if changed {
		tun["route-exclude-address"] = next
	}
	return cidrs, changed, nil
}

func addCentralRouteExclusions(cfg map[string]interface{}, centralURL string) (bool, error) {
	_, changed, err := setCentralRouteExclusions(cfg, centralURL)
	return changed, err
}

func refreshCentralRouteExclusions(centralURL string) (bool, error) {
	path := mihomoConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var cfg map[string]interface{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return false, err
	}
	cidrs, changed, err := setCentralRouteExclusions(cfg, centralURL)
	if err != nil || !changed {
		return false, err
	}
	normalized, err := yaml.Marshal(cfg)
	if err != nil {
		return false, err
	}
	validationFile, err := os.CreateTemp(mihomoHome(), ".mihomo-route-validate-*")
	if err != nil {
		return false, err
	}
	validationPath := validationFile.Name()
	defer os.Remove(validationPath)
	if err := validationFile.Chmod(0600); err != nil {
		_ = validationFile.Close()
		return false, err
	}
	if _, err := validationFile.Write(normalized); err != nil {
		_ = validationFile.Close()
		return false, err
	}
	if err := validationFile.Close(); err != nil {
		return false, err
	}
	validationOutput, validationErr := exec.Command(
		mihomoBinaryPath(), "-t", "-d", mihomoHome(), "-f", validationPath,
	).CombinedOutput()
	if validationErr != nil {
		return false, fmt.Errorf("主控直连排除配置未通过 Mihomo 校验: %s", safeMihomoValidationDiagnostic(validationOutput))
	}
	tmp, err := os.CreateTemp(mihomoHome(), ".mihomo-route-*")
	if err != nil {
		return false, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if _, err := tmp.Write(normalized); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	// Keep a rollback copy until Mihomo confirms the reload succeeded.
	if err := atomicWriteFile(path+".previous", data, 0600); err != nil {
		return false, fmt.Errorf("备份旧 Mihomo 配置失败: %w", err)
	}
	if err := atomicWriteFile(path, normalized, 0600); err != nil {
		return false, err
	}
	_ = os.Remove(tmpPath)
	if err := writeManagedRouteCIDRs(cidrs); err != nil {
		return true, fmt.Errorf("已更新 TUN 排除地址，但保存动态地址记录失败: %w", err)
	}
	return true, nil
}

func refreshAndApplyCentralRouteExclusions(centralURL string) error {
	oldManaged := readManagedRouteCIDRs()
	oldManagedValues := make([]string, 0, len(oldManaged))
	for cidr := range oldManaged {
		oldManagedValues = append(oldManagedValues, cidr)
	}
	restoreManagedRoutes := func() error {
		return writeManagedRouteCIDRs(oldManagedValues)
	}

	changed, err := refreshCentralRouteExclusions(centralURL)
	if err != nil {
		// refreshCentralRouteExclusions may have committed the candidate config
		// before failing to persist its managed-CIDR bookkeeping.
		if changed {
			if rollbackErr := rollbackConfigAfterReloadFailure(); rollbackErr != nil {
				return fmt.Errorf("刷新路由后记录状态失败且回滚失败: %w", rollbackErr)
			}
			if stateErr := restoreManagedRoutes(); stateErr != nil {
				return fmt.Errorf("刷新路由失败，旧配置已恢复但管理地址记录恢复失败: %w", stateErr)
			}
			if retryErr := reloadMihomo(); retryErr != nil {
				return fmt.Errorf("刷新路由失败，旧配置和管理地址记录已恢复但重载失败: %w", retryErr)
			}
		}
		return err
	}
	if !changed {
		return nil
	}
	if err := reloadMihomo(); err != nil {
		fmt.Printf("Mihomo 重载动态主控路由失败，正在回滚配置: %s\n", safeMihomoValidationDiagnostic([]byte(err.Error())))
		if rollbackErr := rollbackConfigAfterReloadFailure(); rollbackErr != nil {
			return fmt.Errorf("动态路由重载失败且回滚失败: %w", rollbackErr)
		}
		if stateErr := restoreManagedRoutes(); stateErr != nil {
			return fmt.Errorf("动态路由已恢复旧配置，但恢复管理地址记录失败: %w", stateErr)
		}
		if retryErr := reloadMihomo(); retryErr != nil {
			return fmt.Errorf("动态路由已回滚配置和管理地址记录，但旧配置重载失败: %w", retryErr)
		}
		return fmt.Errorf("动态路由重载失败，已恢复旧配置及管理地址记录: %w", err)
	}
	_ = os.Remove(mihomoConfigPath() + ".previous")
	return nil
}

func mergeConfig(agentYml []byte) (bool, error) {
	return mergeConfigWithCentralURL(agentYml, "")
}

func mergeConfigWithCentralURL(agentYml []byte, centralURL string) (bool, error) {
	mainPath := mihomoConfigPath()
	previousPath := mainPath + ".previous"
	nextCfg, err := validateMihomoConfigYAML(agentYml)
	if err != nil {
		return false, err
	}
	oldData, err := os.ReadFile(mainPath)
	if err != nil {
		return false, fmt.Errorf("读取本地 Mihomo 配置失败")
	}
	var oldCfg map[string]interface{}
	if err := yaml.Unmarshal(oldData, &oldCfg); err != nil {
		return false, fmt.Errorf("本地 Mihomo YAML 无效: %w", err)
	}

	// Mihomo's external-controller authentication is established at core startup.
	// A normal /configs reload must not rotate the API secret behind the Agent's
	// back: keep the currently configured secret stable across controller updates.
	if err := preserveMihomoSecret(oldCfg, nextCfg); err != nil {
		return false, err
	}
	var managedCentralCIDRs []string
	if strings.TrimSpace(centralURL) != "" {
		var routeErr error
		managedCentralCIDRs, _, routeErr = setCentralRouteExclusions(nextCfg, centralURL)
		if routeErr != nil {
			fmt.Printf("主控直连排除地址暂未更新: %s\n", safeMihomoValidationDiagnostic([]byte(routeErr.Error())))
		}
	}

	oldNorm, err := yaml.Marshal(oldCfg)
	if err != nil {
		return false, err
	}
	newNorm, err := yaml.Marshal(nextCfg)
	if err != nil {
		return false, err
	}
	if string(oldNorm) == string(newNorm) {
		// A matching runtime YAML may still need a reload after an interrupted
		// apply. In that case create a fresh rollback point before returning
		// changed=true; never let the caller restore a stale .previous file.
		needsApply := controllerConfigNeedsApply(agentYml)
		if needsApply {
			if err := atomicWriteFile(previousPath, oldData, 0600); err != nil {
				return false, fmt.Errorf("备份待重载的 Mihomo 配置失败: %w", err)
			}
		}
		if strings.TrimSpace(centralURL) != "" && len(managedCentralCIDRs) > 0 {
			if err := writeManagedRouteCIDRs(managedCentralCIDRs); err != nil {
				return false, fmt.Errorf("保存动态主控地址记录失败: %w", err)
			}
		}
		// The controller hash is committed only after Mihomo reload succeeds.
		return needsApply, nil
	}
	if err := atomicWriteFile(previousPath, oldData, 0600); err != nil {
		return false, fmt.Errorf("备份旧 Mihomo 配置失败")
	}
	tmpPath := mainPath + ".tmp"
	// Write the normalized configuration so the preserved local secret is
	// actually persisted; writing agentYml here would undo the protection above.
	if err := atomicWriteFile(tmpPath, newNorm, 0600); err != nil {
		return false, err
	}
	validationOutput, validationErr := exec.Command(mihomoBinaryPath(), "-t", "-d", mihomoHome(), "-f", tmpPath).CombinedOutput()
	if validationErr != nil {
		// Mihomo may need to download GeoIP data just to validate fallback-filter.
		// A transient GitHub/network failure must not block a valid config forever.
		// Retry a validation-only copy with GeoIP filtering disabled; the saved
		// configuration below always retains the operator's original setting.
		if isGeoIPDownloadFailure(validationOutput) && disableGeoIPFallbackForValidation(nextCfg) {
			validationOnly, marshalErr := yaml.Marshal(nextCfg)
			if marshalErr == nil && atomicWriteFile(tmpPath, validationOnly, 0600) == nil {
				validationOutput, validationErr = exec.Command(mihomoBinaryPath(), "-t", "-d", mihomoHome(), "-f", tmpPath).CombinedOutput()
				if validationErr == nil {
					// Restore the exact original normalized config before committing it.
					if writeErr := atomicWriteFile(tmpPath, newNorm, 0600); writeErr != nil {
						_ = os.Remove(tmpPath)
						return false, fmt.Errorf("恢复待写入的 Mihomo 配置失败")
					}
				}
			}
		}
		if validationErr != nil {
			_ = os.Remove(tmpPath)
			return false, fmt.Errorf("新配置未通过 Mihomo 校验：%s", safeMihomoValidationDiagnostic(validationOutput))
		}
	}
	if err := atomicWriteFile(mainPath, newNorm, 0600); err != nil {
		_ = os.Remove(tmpPath)
		return false, err
	}
	_ = os.Remove(tmpPath)
	if strings.TrimSpace(centralURL) != "" {
		if len(managedCentralCIDRs) > 0 {
			if err := writeManagedRouteCIDRs(managedCentralCIDRs); err != nil {
				if rollbackErr := rollbackConfigAfterReloadFailure(); rollbackErr != nil {
					return false, fmt.Errorf("保存动态主控地址记录失败: %v；恢复旧运行配置失败: %w", err, rollbackErr)
				}
				return false, fmt.Errorf("保存动态主控地址记录失败，已恢复旧运行配置: %w", err)
			}
		}
		// The controller hash is committed only after Mihomo reload succeeds.
		// Keeping the old hash on reload failure makes the Agent retry the desired YAML.
	}
	return true, nil
}

// persistControllerConfigAfterReload keeps the desired-config hash aligned with
// the runtime config: never commit the controller hash before reload succeeds.
func persistControllerConfigAfterReload(config []byte, reload func() error, persist func([]byte) error) error {
	if err := reload(); err != nil {
		return err
	}
	return persist(config)
}

func rollbackConfigFromPaths(mainPath string) error {
	oldData, err := os.ReadFile(mainPath + ".previous")
	if err != nil {
		return fmt.Errorf("读取旧配置备份失败: %w", err)
	}
	if len(oldData) == 0 {
		return fmt.Errorf("旧配置备份为空，拒绝覆盖当前配置")
	}
	return atomicWriteFile(mainPath, oldData, 0600)
}

func rollbackConfigAfterReloadFailure() error {
	return rollbackConfigAtPath(mihomoConfigPath(), reloadMihomo)
}

// rollbackConfigAtPath keeps rollback behavior testable without a live Mihomo API.
func rollbackConfigAtPath(configPath string, reload func() error) error {
	return rollbackAndVerifyConfig(configPath, reload, func([]byte) error { return nil })
}

// rollbackAndVerifyConfig restores the previous file, reloads Mihomo and verifies it.
func rollbackAndVerifyConfig(mainPath string, reload func() error, verify func([]byte) error) error {
	if err := rollbackConfigFromPaths(mainPath); err != nil {
		return fmt.Errorf("旧配置文件恢复失败: %w", err)
	}
	oldData, err := os.ReadFile(mainPath)
	if err != nil {
		return fmt.Errorf("旧配置文件已恢复但读取失败: %w", err)
	}
	if reload == nil {
		return fmt.Errorf("旧配置文件已恢复但未提供 Mihomo 重载函数")
	}
	if err := reload(); err != nil {
		return fmt.Errorf("旧配置文件已恢复但 Mihomo 重载失败: %w", err)
	}
	if verify == nil {
		return fmt.Errorf("旧配置文件已恢复且已重载，但未提供运行规则验证函数")
	}
	if err := verify(oldData); err != nil {
		return fmt.Errorf("旧配置文件已恢复且已重载，但运行规则验证失败: %w", err)
	}
	return nil
}

type mihomoRuntimeRule struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
}

func expectedMihomoRules(config []byte) ([]mihomoRuntimeRule, error) {
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(config, &parsed); err != nil {
		return nil, fmt.Errorf("解析待验证 Mihomo 配置失败: %w", err)
	}
	raw, ok := parsed["rules"].([]interface{})
	if !ok || len(raw) == 0 {
		return nil, fmt.Errorf("待验证 Mihomo 配置缺少非空 rules")
	}
	rules := make([]mihomoRuntimeRule, 0, len(raw))
	for i, item := range raw {
		line, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("待验证规则第 %d 项不是字符串", i)
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			return nil, fmt.Errorf("待验证规则第 %d 项格式无效", i)
		}
		// Mihomo accepts no-resolve as a trailing IP-CIDR option after
		// the policy target. It is not the target proxy itself.
		end := len(parts)
		if end > 2 && strings.EqualFold(strings.TrimSpace(parts[end-1]), "no-resolve") {
			end--
		}
		if end < 2 {
			return nil, fmt.Errorf("待验证规则第 %d 项缺少目标策略", i)
		}
		rule := mihomoRuntimeRule{
			Type:    strings.TrimSpace(parts[0]),
			Proxy:   strings.TrimSpace(parts[end-1]),
			Payload: strings.TrimSpace(strings.Join(parts[1:end-1], ",")),
		}
		if rule.Type == "" || rule.Proxy == "" {
			return nil, fmt.Errorf("待验证规则第 %d 项缺少类型或目标策略", i)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// normalizeMihomoRuleType makes YAML and Mihomo API rule names comparable.
func normalizeMihomoRuleType(value string) string {
	value = strings.TrimSpace(value)
	value = strings.NewReplacer("-", "", "_", "", " ", "").Replace(value)
	return strings.ToLower(value)
}

// mihomoRulePayloadEqual applies case-insensitive comparison only where the
// rule grammar defines the payload as case-insensitive. GEOIP country codes are
// case-insensitive (for example CN and cn); domain matching, regexes, file
// paths, and other rule payloads retain their existing exact comparison.
func mihomoRulePayloadEqual(ruleType, expected, actual string) bool {
	expected = strings.TrimSpace(expected)
	actual = strings.TrimSpace(actual)
	if normalizeMihomoRuleType(ruleType) == "geoip" {
		return strings.EqualFold(expected, actual)
	}
	return expected == actual
}

func compareMihomoRuntimeRules(expected, actual []mihomoRuntimeRule) error {
	if len(expected) != len(actual) {
		return fmt.Errorf("Mihomo 生效规则数量不匹配: 期望 %d，实际 %d", len(expected), len(actual))
	}
	for i := range expected {
		want, got := expected[i], actual[i]
		if normalizeMihomoRuleType(want.Type) != normalizeMihomoRuleType(got.Type) ||
			!mihomoRulePayloadEqual(want.Type, want.Payload, got.Payload) ||
			strings.TrimSpace(want.Proxy) != strings.TrimSpace(got.Proxy) {
			return fmt.Errorf("Mihomo 第 %d 条生效规则不匹配: 期望 %s,%s,%s；实际 %s,%s,%s",
				i, want.Type, want.Payload, want.Proxy, got.Type, got.Payload, got.Proxy)
		}
	}
	return nil
}

func verifyMihomoRuntimeRules(client *http.Client, controllerURL, secret string, config []byte) error {
	expected, err := expectedMihomoRules(config)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(controllerURL, "/")+"/rules", nil)
	if err != nil {
		return fmt.Errorf("创建 Mihomo 规则读取请求失败: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("读取 Mihomo 当前生效规则失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return fmt.Errorf("读取 Mihomo 规则响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("读取 Mihomo 生效规则返回 HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Rules []mihomoRuntimeRule `json:"rules"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("解析 Mihomo 生效规则响应失败: %w", err)
	}
	if payload.Rules == nil {
		return fmt.Errorf("Mihomo 生效规则响应缺少 rules 数组")
	}
	return compareMihomoRuntimeRules(expected, payload.Rules)
}

// mihomoSecretCandidates returns unique secrets in previous-then-current order.
// During a config transition, the running core may still accept the old secret,
// or it may already have applied the new one despite a lost/ambiguous response.
func mihomoSecretCandidates(configPath string) ([]string, error) {
	seen := make(map[string]struct{}, 2)
	secrets := make([]string, 0, 2)
	for _, path := range []string{configPath + ".previous", configPath} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var candidate map[string]interface{}
		if err := yaml.Unmarshal(data, &candidate); err != nil {
			continue
		}
		value, ok := candidate["secret"].(string)
		secret := strings.TrimSpace(value)
		if !ok || secret == "" {
			continue
		}
		if _, exists := seen[secret]; exists {
			continue
		}
		seen[secret] = struct{}{}
		secrets = append(secrets, secret)
	}
	if len(secrets) == 0 {
		return nil, fmt.Errorf("当前 Mihomo 配置和备份均没有有效 secret")
	}
	return secrets, nil
}

func reloadMihomo() error {
	configPath := mihomoConfigPath()
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取待重载 Mihomo 配置失败: %w", err)
	}
	secrets, err := mihomoSecretCandidates(configPath)
	if err != nil {
		return fmt.Errorf("无法确定 Mihomo API 鉴权密钥: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var lastUnauthorized string
	for _, secret := range secrets {
		reloadBody := strings.NewReader(
			fmt.Sprintf(`{"path": %q}`, configPath),
		)
		reloadReq, err := http.NewRequest(
			http.MethodPut,
			"http://127.0.0.1:8088/configs?force=true",
			reloadBody,
		)
		if err != nil {
			return fmt.Errorf("创建 Mihomo 重载请求失败: %w", err)
		}
		reloadReq.Header.Set("Content-Type", "application/json")
		reloadReq.Header.Set("Authorization", "Bearer "+secret)

		reloadResp, err := client.Do(reloadReq)
		if err != nil {
			return fmt.Errorf("请求 Mihomo 重载失败: %w", err)
		}
		responseBody, _ := io.ReadAll(io.LimitReader(reloadResp.Body, 4096))
		statusCode := reloadResp.StatusCode
		_ = reloadResp.Body.Close()

		if statusCode == http.StatusOK || statusCode == http.StatusNoContent {
			if err := verifyMihomoRuntimeRules(client, "http://127.0.0.1:8088", secret, configData); err != nil {
				return fmt.Errorf("Mihomo 已接受重载请求，但运行规则回读校验失败: %w", err)
			}
			return nil
		}
		if statusCode == http.StatusUnauthorized {
			lastUnauthorized = strings.TrimSpace(string(responseBody))
			continue
		}
		return fmt.Errorf(
			"Mihomo 重载返回 HTTP %d: %s",
			statusCode,
			strings.TrimSpace(string(responseBody)),
		)
	}
	if lastUnauthorized == "" {
		lastUnauthorized = http.StatusText(http.StatusUnauthorized)
	}
	return fmt.Errorf("Mihomo 重载鉴权失败：已尝试旧配置和当前配置的有效密钥，最后返回 HTTP 401: %s", lastUnauthorized)
}

var mihomoSpeedMu sync.Mutex
var mihomoSpeedLastTime time.Time
var mihomoSpeedLastUpload uint64
var mihomoSpeedLastDownload uint64

func trafficCounter(value any) (uint64, bool) {
	n, ok := value.(float64)
	if !ok || n < 0 || n > 1.8e19 {
		return 0, false
	}
	return uint64(n), true
}

func calculateMihomoSpeeds(upload, download uint64, now time.Time) (uint64, uint64) {
	mihomoSpeedMu.Lock()
	defer mihomoSpeedMu.Unlock()
	var upSpeed, downSpeed uint64
	if !mihomoSpeedLastTime.IsZero() {
		seconds := now.Sub(mihomoSpeedLastTime).Seconds()
		if seconds > 0 {
			if upload >= mihomoSpeedLastUpload {
				upSpeed = uint64(float64(upload-mihomoSpeedLastUpload) / seconds)
			}
			if download >= mihomoSpeedLastDownload {
				downSpeed = uint64(float64(download-mihomoSpeedLastDownload) / seconds)
			}
		}
	}
	mihomoSpeedLastTime = now
	mihomoSpeedLastUpload = upload
	mihomoSpeedLastDownload = download
	return upSpeed, downSpeed
}

func collectMihomoStatus() map[string]any {
	status := map[string]any{
		"arch": runtime.GOARCH, "os": runtime.GOOS,
		"hostname": "", "mihomo_version": "", "mihomo_healthy": false,
		"upload_total": int64(0), "download_total": int64(0),
		"upload_speed": float64(0), "download_speed": float64(0),
		"connections": 0, "config_sha256": "", "last_error": "",
	}
	collectSmartDNSStatus(status)
	if hostname, err := agentHostname(); err == nil {
		status["hostname"] = hostname
	}
	configPath := mihomoConfigPath()
	data, err := os.ReadFile(configPath)
	if err != nil {
		status["last_error"] = "读取配置失败: " + err.Error()
		return status
	}
	hashData, hashErr := configHashSource()
	if hashErr != nil {
		hashData = data
	}
	status["config_sha256"] = controllerConfigHash(hashData)
	var cfg map[string]interface{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		status["last_error"] = "解析配置失败: " + err.Error()
		return status
	}
	secret, _ := cfg["secret"].(string)
	client := &http.Client{Timeout: 3 * time.Second}
	get := func(path string) (map[string]any, error) {
		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8088"+path, nil)
		if err != nil {
			return nil, err
		}
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		var result map[string]any
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
			return nil, err
		}
		return result, nil
	}
	version, err := get("/version")
	if err != nil {
		status["last_error"] = "读取 Mihomo 版本失败: " + err.Error()
		return status
	}
	versionText, ok := version["version"].(string)
	if !ok || strings.TrimSpace(versionText) == "" {
		status["last_error"] = "读取 Mihomo 版本失败: /version 响应缺少有效 version 字段"
		return status
	}
	status["mihomo_version"] = versionText
	status["mihomo_healthy"] = true
	connections, err := get("/connections")
	if err == nil {
		items, _ := connections["connections"].([]any)
		status["connections"] = len(items)
		status["upload_total"] = connections["uploadTotal"]
		status["download_total"] = connections["downloadTotal"]
		uploadTotal, uploadOK := trafficCounter(connections["uploadTotal"])
		downloadTotal, downloadOK := trafficCounter(connections["downloadTotal"])
		if uploadOK && downloadOK {
			upSpeed, downSpeed := calculateMihomoSpeeds(uploadTotal, downloadTotal, time.Now())
			status["upload_speed"] = upSpeed
			status["download_speed"] = downSpeed
		}
	} else if status["last_error"] == "" {
		status["last_error"] = "读取连接数失败: " + err.Error()
	}
	return status
}

// reportHeartbeat sends runtime telemetry exclusively over WebSocket.
// HTTP is intentionally not used as a fallback: a failed session is retried by the
// Agent reconnect loop so the controller has one authoritative runtime channel.
func reportHeartbeat(cfg Config, status map[string]any) error {
	return reportHeartbeatWebSocket(cfg, status)
}

// fetchAgentConfigWebSocket fetches this machine's configuration without HTTP polling.
// A config hash allows the controller to avoid retransmitting unchanged YAML.
func fetchAgentConfigWebSocket(cfg Config, localHash string) ([]byte, bool, error) {
	base, err := url.Parse(strings.TrimRight(cfg.CentralURL, "/"))
	if err != nil || base.Host == "" {
		return nil, false, fmt.Errorf("主控地址无效")
	}
	switch strings.ToLower(base.Scheme) {
	case "http":
		base.Scheme = "ws"
	case "https":
		base.Scheme = "wss"
	default:
		return nil, false, fmt.Errorf("主控地址协议不支持")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/agent/ws"
	base.RawPath = ""
	header := http.Header{}
	header.Set("Authorization", "Bearer "+cfg.Token)
	conn, response, err := (&websocket.Dialer{HandshakeTimeout: 8 * time.Second}).Dial(base.String(), header)
	if err != nil {
		if response != nil {
			return nil, false, fmt.Errorf("WebSocket 握手失败：HTTP %d：%w", response.StatusCode, err)
		}
		return nil, false, fmt.Errorf("WebSocket 连接失败：%w", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	_ = conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
	var welcome struct {
		Type string `json:"type"`
	}
	if err := conn.ReadJSON(&welcome); err != nil {
		return nil, false, fmt.Errorf("读取 WebSocket 欢迎消息失败：%w", err)
	}
	if welcome.Type != "welcome" {
		return nil, false, fmt.Errorf("WebSocket 欢迎消息类型无效")
	}
	requestID := fmt.Sprintf("cfg-%d", time.Now().UnixNano())
	if err := conn.WriteJSON(map[string]string{"type": "config.request", "id": requestID, "config_sha256": localHash}); err != nil {
		return nil, false, fmt.Errorf("发送配置请求失败：%w", err)
	}
	var result struct {
		Type    string `json:"type"`
		ID      string `json:"id"`
		SHA256  string `json:"sha256"`
		YAML    string `json:"yaml"`
		Message string `json:"message"`
	}
	if err := conn.ReadJSON(&result); err != nil {
		return nil, false, fmt.Errorf("读取 WebSocket 配置响应失败：%w", err)
	}
	if result.ID != requestID {
		return nil, false, fmt.Errorf("WebSocket 配置响应 ID 不匹配")
	}
	switch result.Type {
	case "config.unchanged":
		return nil, true, nil
	case "config.sync":
		if strings.TrimSpace(result.YAML) == "" {
			return nil, false, fmt.Errorf("主控端返回空配置")
		}
		sum := sha256.Sum256([]byte(result.YAML))
		if result.SHA256 != hex.EncodeToString(sum[:]) {
			return nil, false, fmt.Errorf("主控端配置 SHA-256 校验失败")
		}
		return []byte(result.YAML), false, nil
	case "error":
		return nil, false, fmt.Errorf("主控端拒绝配置请求：%s", result.Message)
	default:
		return nil, false, fmt.Errorf("未知的 WebSocket 配置响应类型: %s", result.Type)
	}
}

func reportHeartbeatWebSocket(cfg Config, status map[string]any) error {
	base, err := url.Parse(strings.TrimRight(cfg.CentralURL, "/"))
	if err != nil || base.Host == "" {
		return fmt.Errorf("主控地址无效")
	}
	switch strings.ToLower(base.Scheme) {
	case "http":
		base.Scheme = "ws"
	case "https":
		base.Scheme = "wss"
	default:
		return fmt.Errorf("主控地址协议不支持")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/agent/ws"
	base.RawPath = ""
	header := http.Header{}
	header.Set("Authorization", "Bearer "+cfg.Token)
	dialer := websocket.Dialer{HandshakeTimeout: 8 * time.Second}
	conn, response, err := dialer.Dial(base.String(), header)
	if err != nil {
		if response != nil {
			return fmt.Errorf("WebSocket 握手失败：HTTP %d：%w", response.StatusCode, err)
		}
		return fmt.Errorf("WebSocket 连接失败：%w", err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return err
	}
	if err := conn.SetWriteDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return err
	}
	var welcome struct {
		Type string `json:"type"`
	}
	if err := conn.ReadJSON(&welcome); err != nil {
		return fmt.Errorf("读取 WebSocket 欢迎消息失败：%w", err)
	}
	if welcome.Type != "welcome" {
		return fmt.Errorf("WebSocket 欢迎消息类型无效")
	}
	heartbeatID := fmt.Sprintf("hb-%d", time.Now().UnixNano())
	if err := conn.WriteJSON(map[string]any{
		"type":   "heartbeat",
		"id":     heartbeatID,
		"status": status,
	}); err != nil {
		return fmt.Errorf("发送 WebSocket 心跳失败：%w", err)
	}
	var ack struct {
		Type string `json:"type"`
		ID   string `json:"id"`
		OK   bool   `json:"ok"`
	}
	if err := conn.ReadJSON(&ack); err != nil {
		return fmt.Errorf("读取 WebSocket 心跳确认失败：%w", err)
	}
	if ack.Type != "heartbeat.ack" || ack.ID != heartbeatID || !ack.OK {
		return fmt.Errorf("主控端心跳确认无效")
	}
	return nil
}

func reportHeartbeatHTTP(cfg Config, status map[string]any) error {
	body, err := json.Marshal(status)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.CentralURL, "/")+"/api/v1/agent/heartbeat", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("主控端心跳返回 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

type agentCommand struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Config  string `json:"config"`
}

// processAgentCommandWebSocket polls and acknowledges commands through the authenticated WebSocket protocol.
func processAgentCommandWebSocket(cfg Config) error {
	base, err := url.Parse(strings.TrimRight(cfg.CentralURL, "/"))
	if err != nil || base.Host == "" {
		return fmt.Errorf("主控地址无效")
	}
	switch strings.ToLower(base.Scheme) {
	case "http":
		base.Scheme = "ws"
	case "https":
		base.Scheme = "wss"
	default:
		return fmt.Errorf("主控地址协议不支持")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/agent/ws"
	base.RawPath = ""
	header := http.Header{}
	header.Set("Authorization", "Bearer "+cfg.Token)
	conn, response, err := (&websocket.Dialer{HandshakeTimeout: 8 * time.Second}).Dial(base.String(), header)
	if err != nil {
		if response != nil {
			return fmt.Errorf("WebSocket 握手失败：HTTP %d：%w", response.StatusCode, err)
		}
		return fmt.Errorf("WebSocket 连接失败：%w", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(12 * time.Second))
	_ = conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
	var welcome struct {
		Type string `json:"type"`
	}
	if err := conn.ReadJSON(&welcome); err != nil {
		return fmt.Errorf("读取 WebSocket 欢迎消息失败：%w", err)
	}
	if welcome.Type != "welcome" {
		return fmt.Errorf("WebSocket 欢迎消息类型无效")
	}
	requestID := fmt.Sprintf("cmd-poll-%d", time.Now().UnixNano())
	if err := conn.WriteJSON(map[string]string{"type": "command.request", "id": requestID}); err != nil {
		return err
	}
	var envelope struct {
		Type    string        `json:"type"`
		ID      string        `json:"id"`
		Command *agentCommand `json:"command"`
		Message string        `json:"message"`
	}
	if err := conn.ReadJSON(&envelope); err != nil {
		return fmt.Errorf("读取 WebSocket 命令失败：%w", err)
	}
	if envelope.ID != requestID {
		return fmt.Errorf("WebSocket 命令响应 ID 不匹配")
	}
	if envelope.Type == "command.none" {
		return nil
	}
	if envelope.Type == "error" {
		return fmt.Errorf("主控命令查询失败：%s", envelope.Message)
	}
	if envelope.Type != "command.deliver" || envelope.Command == nil {
		return fmt.Errorf("主控端命令响应格式无效")
	}
	cmd := *envelope.Command
	var runErr error
	var data []byte
	message := ""
	switch cmd.Type {
	case "update_mihomo":
		message, runErr = updateMihomoKernel(cmd)
	case "read_smartdns_config":
		data, runErr = readSmartDNSConfig()
		if runErr == nil {
			message = "已读取 Agent 当前 SmartDNS 配置"
		}
	case "configure_smartdns":
		var configHash string
		configHash, runErr = writeSmartDNSConfig([]byte(cmd.Config))
		if runErr == nil {
			message = "SmartDNS 配置已校验并应用，SHA-256: " + configHash
		}
	default:
		runErr = fmt.Errorf("不支持的 Agent 命令类型: %s", cmd.Type)
	}
	status := "success"
	if runErr != nil {
		status = "failed"
		message = runErr.Error()
	}
	if len(message) > 2048 {
		message = message[:2048]
	}
	// The command may take longer than the initial connection deadlines (for
	// example, downloading and restarting Mihomo). Refresh the deadline for the
	// ACK write instead of reusing the deadline set before command execution.
	if err := writeAgentWSJSON(conn, map[string]any{"type": "command.ack", "id": cmd.ID, "command_status": status, "message": message, "config": string(data)}); err != nil {
		return fmt.Errorf("命令已执行但 WebSocket ACK 发送失败，主控端可能重新投递: %w", err)
	}
	var ack struct {
		Type    string `json:"type"`
		ID      string `json:"id"`
		OK      bool   `json:"ok"`
		Message string `json:"message"`
	}
	// Command execution may also outlive the original read deadline.
	if err := readAgentWSJSON(conn, &ack, 12*time.Second); err != nil {
		return fmt.Errorf("读取命令 ACK 确认失败：%w", err)
	}
	if ack.Type != "command.acknowledged" || ack.ID != cmd.ID || !ack.OK {
		return fmt.Errorf("主控端命令 ACK 确认无效: %s", ack.Message)
	}
	if runErr != nil {
		return runErr
	}
	fmt.Printf("Agent 命令 %s 执行成功: %s\n", cmd.ID, message)
	return nil
}

func processAgentCommand(cfg Config) error {
	request, err := http.NewRequest(http.MethodGet, strings.TrimRight(cfg.CentralURL, "/")+"/api/v1/agent/command", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+cfg.Token)
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("读取主控命令返回 HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var envelope struct {
		Command *agentCommand `json:"command"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&envelope); err != nil {
		return err
	}
	if envelope.Command == nil {
		return nil
	}
	cmd := envelope.Command
	var runErr error
	message := ""
	switch cmd.Type {
	case "update_mihomo":
		message, runErr = updateMihomoKernel(*cmd)
	default:
		runErr = fmt.Errorf("不支持的 Agent 命令类型: %s", cmd.Type)
	}
	status := "success"
	if runErr != nil {
		status = "failed"
		message = runErr.Error()
	}
	ackBody, _ := json.Marshal(map[string]string{"id": cmd.ID, "status": status, "message": message})
	ackReq, err := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.CentralURL, "/")+"/api/v1/agent/command/ack", bytes.NewReader(ackBody))
	if err != nil {
		return err
	}
	ackReq.Header.Set("Authorization", "Bearer "+cfg.Token)
	ackReq.Header.Set("Content-Type", "application/json")
	ackResp, err := (&http.Client{Timeout: 10 * time.Second}).Do(ackReq)
	if err != nil {
		return fmt.Errorf("执行命令后上报结果失败: %w", err)
	}
	defer ackResp.Body.Close()
	if ackResp.StatusCode < 200 || ackResp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(ackResp.Body, 2048))
		return fmt.Errorf("上报命令结果返回 HTTP %d: %s", ackResp.StatusCode, strings.TrimSpace(string(body)))
	}
	if runErr != nil {
		return runErr
	}
	fmt.Printf("Agent 命令 %s 执行成功: %s\n", cmd.ID, message)
	return nil
}

var mihomoVersionPattern = regexp.MustCompile("^v[0-9]+\\.[0-9]+\\.[0-9]+$")
var sha256Pattern = regexp.MustCompile("^[a-fA-F0-9]{64}$")

func validateKernelUpdateCommand(cmd agentCommand) error {
	if !mihomoVersionPattern.MatchString(strings.TrimSpace(cmd.Version)) {
		return fmt.Errorf("更新命令版本号无效")
	}
	if !sha256Pattern.MatchString(strings.TrimSpace(cmd.SHA256)) {
		return fmt.Errorf("更新命令 SHA-256 必须为 64 位十六进制")
	}
	return nil
}

func updateMihomoKernel(cmd agentCommand) (result string, retErr error) {
	started := time.Now()
	stage := "start"
	defer func() {
		if retErr != nil {
			fmt.Printf("mihomo_update: failed command_id=%q stage=%q duration_ms=%d error=%q\n", cmd.ID, stage, time.Since(started).Milliseconds(), safeMihomoValidationDiagnostic([]byte(retErr.Error())))
		}
	}()
	fmt.Printf("mihomo_update: started command_id=%q target_version=%q arch=%q\n", cmd.ID, cmd.Version, runtime.GOARCH)
	stage = "validate"
	if err := validateKernelUpdateCommand(cmd); err != nil {
		fmt.Printf("mihomo_update: rejected command_id=%q stage=validate error=%q\n", cmd.ID, safeMihomoValidationDiagnostic([]byte(err.Error())))
		return "", err
	}
	cmd.Version = strings.TrimSpace(cmd.Version)
	cmd.SHA256 = strings.TrimSpace(cmd.SHA256)

	// ACK delivery can fail after a successful update. If the same command is
	// delivered again, recognize the already-installed target version and avoid
	// downloading/replacing/restarting the kernel a second time.
	stage = "check-current-version"
	fmt.Printf("mihomo_update: checking current version command_id=%q\n", cmd.ID)
	if output, err := exec.Command(mihomoBinaryPath(), "-v").CombinedOutput(); err == nil {
		versionPattern := regexp.MustCompile(`\bv` + regexp.QuoteMeta(strings.TrimPrefix(cmd.Version, "v")) + `\b`)
		if versionPattern.Match(output) {
			fmt.Printf("mihomo_update: skipped command_id=%q reason=already-installed duration_ms=%d\n", cmd.ID, time.Since(started).Milliseconds())
			return "Mihomo 已是目标版本 " + cmd.Version + "，按幂等重试跳过重复安装", nil
		}
	}
	asset := ""
	switch runtime.GOARCH {
	case "amd64":
		asset = "mihomo-linux-amd64-compatible-" + cmd.Version + ".gz"
	case "arm64":
		asset = "mihomo-linux-arm64-" + cmd.Version + ".gz"
	default:
		return "", fmt.Errorf("当前架构 %s 暂不支持自动更新", runtime.GOARCH)
	}
	url := "https://github.com/MetaCubeX/mihomo/releases/download/" + cmd.Version + "/" + asset
	stage = "download"
	fmt.Printf("mihomo_update: downloading command_id=%q asset=%q\n", cmd.ID, asset)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 3 * time.Minute}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("下载官方 Mihomo 内核失败: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("官方 Mihomo 下载返回 HTTP %d", response.StatusCode)
	}
	fmt.Printf("mihomo_update: download complete command_id=%q http_status=%d\n", cmd.ID, response.StatusCode)
	stage = "read-download"
	compressed, err := io.ReadAll(io.LimitReader(response.Body, 200<<20))
	if err != nil {
		return "", err
	}
	if len(compressed) == 0 || len(compressed) >= 200<<20 {
		return "", fmt.Errorf("下载文件为空或超过 200 MiB 限制")
	}
	stage = "verify-sha256"
	sum := sha256.Sum256(compressed)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), cmd.SHA256) {
		fmt.Printf("mihomo_update: failed command_id=%q stage=sha256 error=mismatch\n", cmd.ID)
		return "", fmt.Errorf("Mihomo 下载文件 SHA-256 不匹配，已拒绝安装")
	}
	fmt.Printf("mihomo_update: checksum verified command_id=%q bytes=%d\n", cmd.ID, len(compressed))
	stage = "decompress"
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return "", fmt.Errorf("Mihomo 压缩包损坏: %w", err)
	}
	defer gz.Close()
	newBinary, err := os.CreateTemp(filepath.Dir(mihomoBinaryPath()), ".mihomo-update-*")
	if err != nil {
		return "", fmt.Errorf("创建内核临时文件失败")
	}
	newPath := newBinary.Name()
	defer os.Remove(newPath)
	written, copyErr := io.Copy(newBinary, io.LimitReader(gz, 256<<20))
	closeErr := newBinary.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if written == 0 || written >= 256<<20 {
		return "", fmt.Errorf("解压后的内核为空或超过 256 MiB 限制")
	}
	if err := os.Chmod(newPath, 0755); err != nil {
		return "", err
	}
	stage = "binary-self-test"
	if _, err := exec.Command(newPath, "-v").CombinedOutput(); err != nil {
		return "", fmt.Errorf("新内核自检失败（已隐藏底层路径详情）")
	}
	stage = "config-validation"
	configPath := mihomoConfigPath()
	if _, err := exec.Command(newPath, "-t", "-d", mihomoHome(), "-f", configPath).CombinedOutput(); err != nil {
		fmt.Printf("mihomo_update: failed command_id=%q stage=config-validation error=%q\n", cmd.ID, safeMihomoValidationDiagnostic([]byte(err.Error())))
		return "", fmt.Errorf("新内核未通过当前配置校验（已隐藏底层路径详情）")
	}
	fmt.Printf("mihomo_update: config validated command_id=%q\n", cmd.ID)
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	var config map[string]any
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return "", err
	}
	secret, _ := config["secret"].(string)
	if strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("当前配置没有 Mihomo API secret")
	}
	stage = "install-binary"
	binaryPath := mihomoBinaryPath()
	backupPath := binaryPath + ".previous"
	_ = os.Remove(backupPath)
	if err := os.Rename(binaryPath, backupPath); err != nil {
		return "", fmt.Errorf("备份现有 Mihomo 内核失败")
	}
	if err := os.Rename(newPath, binaryPath); err != nil {
		_ = os.Rename(backupPath, binaryPath)
		return "", fmt.Errorf("安装新 Mihomo 内核失败")
	}
	stage = "restart-health-check-rollback"
	fmt.Printf("mihomo_update: binary installed command_id=%q stage=restart-and-health-check target_version=%q\n", cmd.ID, cmd.Version)
	expectedVersion := strings.TrimPrefix(cmd.Version, "v")
	upgradeErr := verifyKernelUpgrade(
		func() error { return restartMihomo(secret) },
		func() error { return waitForMihomoVersion(secret, expectedVersion, 30*time.Second) },
		func() error { return restoreMihomoKernel(binaryPath, backupPath, secret) },
	)
	if upgradeErr != nil {
		fmt.Printf("mihomo_update: failed command_id=%q stage=restart-health-rollback duration_ms=%d error=%q\n", cmd.ID, time.Since(started).Milliseconds(), safeMihomoValidationDiagnostic([]byte(upgradeErr.Error())))
		return "", upgradeErr
	}
	fmt.Printf("mihomo_update: health check passed command_id=%q version=%q\n", cmd.ID, cmd.Version)
	stage = "remove-backup"
	if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("新内核已通过健康检查，但删除旧内核备份失败")
	}
	fmt.Printf("mihomo_update: completed command_id=%q version=%q duration_ms=%d\n", cmd.ID, cmd.Version, time.Since(started).Milliseconds())
	return "Mihomo 内核已更新到 " + cmd.Version, nil
}

// verifyKernelUpgrade treats the running version as authoritative when a
// restart request fails because the controller connection may close on exec.
func verifyKernelUpgrade(restart, healthCheck, rollback func() error) error {
	restartErr := restart()
	if healthErr := healthCheck(); healthErr != nil {
		rollbackErr := rollback()
		if rollbackErr != nil {
			if restartErr != nil {
				return fmt.Errorf("重启请求返回错误: %v；新内核健康检查失败: %v；恢复旧内核失败: %w", restartErr, healthErr, rollbackErr)
			}
			return fmt.Errorf("新内核健康检查失败: %v；恢复旧内核失败: %w", healthErr, rollbackErr)
		}
		if restartErr != nil {
			return fmt.Errorf("重启请求返回错误且新内核未通过健康检查，已恢复旧内核: %v（健康检查：%v）", restartErr, healthErr)
		}
		return fmt.Errorf("新内核健康检查失败，已恢复旧内核: %w", healthErr)
	}
	return nil
}

// newMihomoRestartRequest builds the documented Mihomo restart request.
func newMihomoRestartRequest(secret string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8088/restart", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	return req, nil
}

// restartMihomo asks s6-supervise to restart only the Mihomo process from
// /usr/local/bin/mihomo. Do not take the service down through s6-rc: the Agent
// declares a dependency on Mihomo, so a dependency-aware down operation may also
// stop the Agent while it is processing this command and prevent its ACK.
func restartMihomo(secret string) error {
	_ = secret // Retained in the signature for compatibility with update flow.
	output, err := exec.Command("s6-svc", "-r", "/run/service/mihomo").CombinedOutput()
	if err != nil {
		return fmt.Errorf("请求 s6 重启 Mihomo 服务失败: %v: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func mihomoVersionMatches(actual, expected string) bool {
	actual = strings.TrimPrefix(strings.TrimSpace(actual), "v")
	expected = strings.TrimPrefix(strings.TrimSpace(expected), "v")
	return actual != "" && expected != "" && actual == expected
}

// waitForMihomoVersion waits until the API responds with the expected running version.
func waitForMihomoVersion(secret, expected string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 3 * time.Second}
	var lastErr error
	for {
		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8088/version", nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+secret)
			resp, requestErr := client.Do(req)
			if requestErr != nil {
				lastErr = requestErr
			} else {
				var payload map[string]any
				decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&payload)
				resp.Body.Close()
				version, _ := payload["version"].(string)
				if resp.StatusCode >= 200 && resp.StatusCode < 300 && decodeErr == nil && mihomoVersionMatches(version, expected) {
					return nil
				}
				if decodeErr != nil {
					lastErr = decodeErr
				} else {
					lastErr = fmt.Errorf("Mihomo API 返回 HTTP %d，版本为 %q，期望 %q", resp.StatusCode, version, expected)
				}
			}
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Second)
	}
	if lastErr == nil {
		return fmt.Errorf("Mihomo 在 %s 内未通过版本健康检查", timeout)
	}
	return fmt.Errorf("Mihomo 在 %s 内未通过版本健康检查: %w", timeout, lastErr)
}

func replaceFileAtomically(sourcePath, destinationPath string) error {
	// The source and destination must be on the same filesystem for rename to
	// replace the destination atomically. All Mihomo update files are created
	// beside the installed binary, so this holds for supported Linux targets.
	return os.Rename(sourcePath, destinationPath)
}

// restoreMihomoKernel reinstalls the backup and requests a restart.
func restoreMihomoKernel(binaryPath, backupPath, secret string) error {
	return restoreMihomoKernelWithRestart(binaryPath, backupPath, func() error {
		return restartMihomo(secret)
	})
}

// restoreMihomoKernelWithRestart separates file recovery from the controller
// request so both failure modes can be tested without a live Mihomo API.
func restoreMihomoKernelWithRestart(binaryPath, backupPath string, restart func() error) error {
	// Never remove the new binary before attempting replacement: if the rename
	// fails, keep the currently installed executable available for recovery.
	if err := replaceFileAtomically(backupPath, binaryPath); err != nil {
		return fmt.Errorf("恢复旧内核文件失败")
	}
	if err := restart(); err != nil {
		return fmt.Errorf("旧内核文件已恢复，但请求重启失败: %w", err)
	}
	return nil
}

func normalizeMachineID(data []byte) string {
	id := strings.ToLower(strings.TrimSpace(string(data)))
	if len(id) < 11 || len(id) > 32 {
		return ""
	}
	for _, ch := range id {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return ""
		}
	}
	if strings.Trim(id, "0") == "" {
		return ""
	}
	return id
}

func machineIDPath() string {
	return filepath.Join(mihomoHome(), "machine-id")
}

func validStoredFallbackMachineID(data []byte) string {
	id := strings.ToLower(strings.TrimSpace(string(data)))
	if len(id) != 32 {
		return ""
	}
	for _, ch := range id {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return ""
		}
	}
	if strings.Trim(id, "0") == "" {
		return ""
	}
	return id
}

func readSystemMachineID(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	id := normalizeMachineID(data)
	if id == "" {
		return "", fmt.Errorf("系统机器标识文件为空或格式无效")
	}
	return id[:11], nil
}

// loadOrCreateMachineID prefers /etc/machine-id. If unavailable, it generates
// a random ID and persists it under /data, which survives container recreation
// when the configured volume is retained. Storage errors are never ignored.
func loadOrCreateMachineID(systemPath, storagePath string) (string, error) {
	if id, err := readSystemMachineID(systemPath); err == nil {
		return id, nil
	}
	if err := os.MkdirAll(filepath.Dir(storagePath), 0700); err != nil {
		return "", fmt.Errorf("创建机器标识持久化目录失败")
	}
	if data, err := os.ReadFile(storagePath); err == nil {
		if id := validStoredFallbackMachineID(data); id != "" {
			return id[:11], nil
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("读取备用机器标识失败")
	}
	randomID := make([]byte, 16)
	if _, err := cryptorand.Read(randomID); err != nil {
		return "", fmt.Errorf("生成备用机器标识失败: %w", err)
	}
	fullID := hex.EncodeToString(randomID)
	tmp, err := os.CreateTemp(filepath.Dir(storagePath), ".machine-id-*")
	if err != nil {
		return "", fmt.Errorf("创建机器标识临时文件失败")
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("设置机器标识文件权限失败")
	}
	if _, err := tmp.WriteString(fullID + "\n"); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("写入备用机器标识失败: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("同步备用机器标识失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("关闭机器标识临时文件失败: %w", err)
	}
	if err := os.Rename(tmpPath, storagePath); err != nil {
		if data, readErr := os.ReadFile(storagePath); readErr == nil {
			if id := validStoredFallbackMachineID(data); id != "" {
				return id[:11], nil
			}
		}
		return "", fmt.Errorf("持久化备用机器标识失败")
	}
	return fullID[:11], nil
}

func getMachineID() (string, error) {
	return loadOrCreateMachineID("/etc/machine-id", machineIDPath())
}

func agentHostname() (string, error) {
	// Docker containers normally have their own hostname (often the container ID).
	// Deployments should pass the host OS hostname via S5M_HOSTNAME.
	if hostname := strings.TrimSpace(os.Getenv("S5M_HOSTNAME")); hostname != "" {
		return hostname, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return "", fmt.Errorf("hostname is empty")
	}
	return hostname, nil
}

func hostnameHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "仅允许 GET", http.StatusMethodNotAllowed)
		return
	}
	hostname, err := agentHostname()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		http.Error(w, "无法读取主机名", http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"hostname": hostname})
}

func machineIDHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "仅允许 GET", http.StatusMethodNotAllowed)
		return
	}
	id, err := getMachineID()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "无法生成或读取机器标识: " + err.Error(),
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"machine_id": id})
}

// probeControllerHTTP is deliberately limited to controller reachability.
// A received HTTP response proves network reachability; application data is never
// read from this endpoint and no HTTP fallback is used for Agent status/config/commands.
func probeControllerHTTP(cfg Config) error {
	base, err := url.Parse(strings.TrimRight(cfg.CentralURL, "/"))
	if err != nil || base.Host == "" {
		return fmt.Errorf("主控地址无效")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/health"
	base.RawPath = ""
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	// Even a 4xx/5xx response proves that the controller host is reachable.
	return nil
}

func nextReconnectDelay(current time.Duration) time.Duration {
	if current < 2*time.Second {
		return 2 * time.Second
	}
	current *= 2
	if current > 60*time.Second {
		return 60 * time.Second
	}
	return current
}

// reconnectDelayWithJitter spreads reconnect attempts across Agents after a
// controller outage. The returned delay is in [base, base+50% of base).
func reconnectDelayWithJitter(current time.Duration) time.Duration {
	base := current
	if base < 2*time.Second {
		base = 2 * time.Second
	}
	if base > 60*time.Second {
		base = 60 * time.Second
	}
	jitterMax := int64(base / 2)
	if jitterMax <= 0 {
		return base
	}
	return base + time.Duration(mathrand.Int63n(jitterMax))
}

// runAgentWebSocketSession owns one persistent connection for all Agent control-plane
// traffic. Every request/response is correlated by ID, and the existing safe config
// apply/rollback and idempotent kernel-upgrade paths are reused.
// applyAgentControlError exposes the most recent config-apply failure in the next
// heartbeat, while preserving any independent Mihomo health diagnostic.
var agentControlErrorMu sync.RWMutex
var agentLastConfigSyncError string
var agentLastRouteSyncError string

func setAgentConfigSyncError(message string) {
	agentControlErrorMu.Lock()
	agentLastConfigSyncError = strings.TrimSpace(message)
	agentControlErrorMu.Unlock()
}

func clearAgentConfigSyncError() {
	setAgentConfigSyncError("")
}

func setAgentRouteSyncError(message string) {
	agentControlErrorMu.Lock()
	agentLastRouteSyncError = strings.TrimSpace(message)
	agentControlErrorMu.Unlock()
}

func agentControlSyncErrors() (string, string) {
	agentControlErrorMu.RLock()
	defer agentControlErrorMu.RUnlock()
	return agentLastConfigSyncError, agentLastRouteSyncError
}

func applyAgentControlError(status map[string]any, controlErr string) {
	controlErr = strings.TrimSpace(controlErr)
	if controlErr == "" {
		return
	}
	controlErr = safeMihomoValidationDiagnostic([]byte(controlErr))
	if existing, ok := status["last_error"].(string); ok && strings.TrimSpace(existing) != "" {
		status["last_error"] = safeMihomoValidationDiagnostic([]byte(controlErr + "; Mihomo: " + existing))
		return
	}
	status["last_error"] = controlErr
}

func recordAgentConfigSyncFailure(err error) error {
	if err == nil {
		return nil
	}
	setAgentConfigSyncError("Agent 配置同步失败: " + err.Error())
	return err
}

func controllerWebSocketResponseError(operation, message string) error {
	message = strings.TrimSpace(message)
	if message == "" {
		message = "主控端未提供错误详情"
	}
	return fmt.Errorf("主控端%s失败: %s", operation, message)
}

func runAgentWebSocketSession(cfg Config, bindingGeneration uint64) error {
	base, err := url.Parse(strings.TrimRight(cfg.CentralURL, "/"))
	if err != nil || base.Host == "" {
		return fmt.Errorf("主控地址无效")
	}
	switch strings.ToLower(base.Scheme) {
	case "http":
		base.Scheme = "ws"
	case "https":
		base.Scheme = "wss"
	default:
		return fmt.Errorf("主控地址协议不支持")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/agent/ws"
	base.RawPath = ""
	header := http.Header{}
	header.Set("Authorization", "Bearer "+cfg.Token)
	dialer := websocket.Dialer{HandshakeTimeout: 8 * time.Second}
	conn, response, err := dialer.Dial(base.String(), header)
	if err != nil {
		if response != nil {
			return fmt.Errorf("WebSocket 握手失败：HTTP %d：%w", response.StatusCode, err)
		}
		return fmt.Errorf("WebSocket 连接失败：%w", err)
	}
	if !setAgentActiveWebSocket(conn, bindingGeneration) {
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Agent binding changed during connect"),
			time.Now().Add(time.Second))
		_ = conn.Close()
		return fmt.Errorf("绑定凭证已更新，取消旧 WebSocket 会话")
	}
	defer clearAgentActiveWebSocket(conn)
	defer conn.Close()
	conn.SetReadLimit(3 << 20)
	_ = conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var welcome struct {
		Type                 string `json:"type"`
		Protocol             int    `json:"protocol"`
		HeartbeatIntervalSec int    `json:"heartbeat_interval_sec"`
	}
	if err := conn.ReadJSON(&welcome); err != nil {
		return fmt.Errorf("读取 WebSocket 欢迎消息失败：%w", err)
	}
	if welcome.Type != "welcome" || welcome.Protocol != 1 {
		return fmt.Errorf("WebSocket 协议版本或欢迎消息无效")
	}
	// A rebind can close the socket while the welcome frame is being processed.
	// Publish connected only if this exact socket still owns the current binding.
	if !markAgentWebSocketConnected(conn, bindingGeneration) {
		return fmt.Errorf("绑定凭证已更新，拒绝激活旧 WebSocket 会话")
	}

	heartbeatInterval := time.Duration(welcome.HeartbeatIntervalSec) * time.Second
	if heartbeatInterval < 5*time.Second || heartbeatInterval > 60*time.Second {
		heartbeatInterval = 30 * time.Second
	}
	// Telemetry has its own 200ms publisher and does not wait for the heartbeat,
	// config sync, or command polling cycle.
	telemetryCtx, stopTelemetry := context.WithCancel(context.Background())
	defer stopTelemetry()
	go runAgentTelemetryPublisher(telemetryCtx, conn)

	for {
		// Refresh the controller's resolved A/AAAA addresses on each heartbeat
		// cycle, without changing the hash of the controller-provided YAML.
		if routeErr := refreshAndApplyCentralRouteExclusions(cfg.CentralURL); routeErr != nil {
			setAgentRouteSyncError("主控直连路由更新失败: " + routeErr.Error())
			fmt.Printf("刷新主控直连排除地址失败: %s\n", safeMihomoValidationDiagnostic([]byte(routeErr.Error())))
		} else {
			setAgentRouteSyncError("")
		}
		// 1. Status/heartbeat is WebSocket-only.
		status := collectMihomoStatus()
		configSyncError, routeSyncError := agentControlSyncErrors()
		controlError := configSyncError
		if routeSyncError != "" {
			if controlError != "" {
				controlError += "; "
			}
			controlError += routeSyncError
		}
		applyAgentControlError(status, controlError)
		heartbeatID := fmt.Sprintf("hb-%d", time.Now().UnixNano())
		if err := writeAgentWSJSON(conn, map[string]any{
			"type": "heartbeat", "id": heartbeatID, "status": status,
		}); err != nil {
			return fmt.Errorf("发送状态心跳失败：%w", err)
		}
		var heartbeatAck struct {
			Type    string `json:"type"`
			ID      string `json:"id"`
			OK      bool   `json:"ok"`
			Message string `json:"message"`
		}
		if err := readAgentWSJSON(conn, &heartbeatAck, 90*time.Second); err != nil {
			return fmt.Errorf("读取状态心跳确认失败：%w", err)
		}
		if heartbeatAck.Type != "heartbeat.ack" || heartbeatAck.ID != heartbeatID || !heartbeatAck.OK {
			return fmt.Errorf("主控端状态心跳确认无效: %s", heartbeatAck.Message)
		}

		// 2. Fetch config on the same socket. A hash prevents needless YAML transfers.
		localHash := ""
		if localData, readErr := configHashSource(); readErr == nil && len(localData) > 0 {
			localHash = controllerConfigHash(localData)
		}
		configRequestID := fmt.Sprintf("cfg-%d", time.Now().UnixNano())
		if err := writeAgentWSJSON(conn, map[string]string{
			"type": "config.request", "id": configRequestID, "config_sha256": localHash,
		}); err != nil {
			return recordAgentConfigSyncFailure(fmt.Errorf("请求配置失败：%w", err))
		}
		var configResponse struct {
			Type    string `json:"type"`
			ID      string `json:"id"`
			SHA256  string `json:"sha256"`
			YAML    string `json:"yaml"`
			Message string `json:"message"`
		}
		if err := readAgentWSJSON(conn, &configResponse, 90*time.Second); err != nil {
			return recordAgentConfigSyncFailure(fmt.Errorf("读取配置响应失败：%w", err))
		}
		if configResponse.ID != configRequestID {
			return recordAgentConfigSyncFailure(fmt.Errorf("WebSocket 配置响应 ID 不匹配"))
		}
		if configResponse.Type == "error" {
			return recordAgentConfigSyncFailure(controllerWebSocketResponseError("配置请求", configResponse.Message))
		}
		switch configResponse.Type {
		case "config.unchanged":
			clearAgentConfigSyncError()
		case "config.sync":
			if strings.TrimSpace(configResponse.YAML) == "" {
				return recordAgentConfigSyncFailure(fmt.Errorf("主控端返回空配置"))
			}
			configHash := controllerConfigHash([]byte(configResponse.YAML))
			if !strings.EqualFold(configHash, strings.TrimSpace(configResponse.SHA256)) {
				// Keep strict verification, and expose hashes/size rather than the YAML
				// body so operators can diagnose stale Agent builds or payload mutation.
				return recordAgentConfigSyncFailure(fmt.Errorf("WebSocket 配置 SHA-256 不匹配，拒绝应用（收到=%s，计算=%s，字节数=%d）", strings.TrimSpace(configResponse.SHA256), configHash, len(configResponse.YAML)))
			}
			oldManagedRoutes := readManagedRouteCIDRs()
			oldManagedRouteValues := make([]string, 0, len(oldManagedRoutes))
			for cidr := range oldManagedRoutes {
				oldManagedRouteValues = append(oldManagedRouteValues, cidr)
			}
			changed, applyErr := mergeConfigWithCentralURL([]byte(configResponse.YAML), cfg.CentralURL)
			if applyErr != nil {
				setAgentConfigSyncError("主控配置应用失败: " + applyErr.Error())
				fmt.Printf("WebSocket 配置校验/写入失败: %s\n", safeMihomoValidationDiagnostic([]byte(applyErr.Error())))
				break
			}
			if changed {
				if commitErr := persistControllerConfigAfterReload(
					[]byte(configResponse.YAML), reloadMihomo, writeControllerConfig,
				); commitErr != nil {
					setAgentConfigSyncError("Mihomo 配置重载或配置哈希提交失败，已尝试回滚: " + commitErr.Error())
					fmt.Printf("Mihomo 配置提交失败，正在回滚: %s\n", safeMihomoValidationDiagnostic([]byte(commitErr.Error())))
					if rollbackErr := rollbackConfigAfterReloadFailure(); rollbackErr != nil {
						return recordAgentConfigSyncFailure(fmt.Errorf("配置提交失败且回滚失败: %w", rollbackErr))
					}
					if stateErr := writeManagedRouteCIDRs(oldManagedRouteValues); stateErr != nil {
						return recordAgentConfigSyncFailure(fmt.Errorf("配置已回滚，但动态主控地址记录恢复失败: %w", stateErr))
					}
					if retryErr := reloadMihomo(); retryErr != nil {
						return recordAgentConfigSyncFailure(fmt.Errorf("旧配置已恢复但重载失败: %w", retryErr))
					}
				} else {
					clearAgentConfigSyncError()
					_ = os.Remove(mihomoConfigPath() + ".previous")
					fmt.Println("WebSocket 下发的 Mihomo 配置已应用")
				}

			} else {
				clearAgentConfigSyncError()
			}
		default:
			return recordAgentConfigSyncFailure(fmt.Errorf("未知的 WebSocket 配置响应类型: %s", configResponse.Type))
		}

		// 3. Fetch and acknowledge commands over this same persistent socket.
		commandRequestID := fmt.Sprintf("cmd-%d", time.Now().UnixNano())
		if err := writeAgentWSJSON(conn, map[string]string{
			"type": "command.request", "id": commandRequestID,
		}); err != nil {
			return fmt.Errorf("请求待执行命令失败：%w", err)
		}
		var commandEnvelope struct {
			Type    string        `json:"type"`
			ID      string        `json:"id"`
			Command *agentCommand `json:"command"`
			Message string        `json:"message"`
		}
		if err := readAgentWSJSON(conn, &commandEnvelope, 90*time.Second); err != nil {
			return fmt.Errorf("读取命令响应失败：%w", err)
		}
		if commandEnvelope.ID != commandRequestID {
			return fmt.Errorf("WebSocket 命令响应 ID 不匹配")
		}
		if commandEnvelope.Type == "error" {
			return controllerWebSocketResponseError("命令请求", commandEnvelope.Message)
		}
		switch commandEnvelope.Type {
		case "command.none":
		case "command.deliver":
			if commandEnvelope.Command == nil || strings.TrimSpace(commandEnvelope.Command.ID) == "" {
				return fmt.Errorf("WebSocket 命令缺少有效 ID")
			}
			cmd := *commandEnvelope.Command
			var commandErr error
			message := ""
			var commandConfig string
			switch cmd.Type {
			case "update_mihomo":
				message, commandErr = updateMihomoKernel(cmd)
			case "read_smartdns_config":
				var smartDNSConfig []byte
				smartDNSConfig, commandErr = readSmartDNSConfig()
				if commandErr == nil {
					commandConfig = string(smartDNSConfig)
					message = "已读取 Agent 当前 SmartDNS 配置"
				}
			case "configure_smartdns":
				var configHash string
				configHash, commandErr = writeSmartDNSConfig([]byte(cmd.Config))
				if commandErr == nil {
					message = "SmartDNS 配置已校验并应用，SHA-256: " + configHash
				}
			default:
				commandErr = fmt.Errorf("不支持的 Agent 命令类型: %s", cmd.Type)
			}
			commandStatus := "success"
			if commandErr != nil {
				commandStatus = "failed"
				message = safeMihomoValidationDiagnostic([]byte(commandErr.Error()))
			}
			if len(message) > 2048 {
				message = message[:2048]
			}
			ackPayload := map[string]any{
				"type": "command.ack", "id": cmd.ID,
				"command_status": commandStatus, "message": message,
			}
			if cmd.Type == "read_smartdns_config" && commandErr == nil {
				ackPayload["config"] = commandConfig
			}
			if err := writeAgentWSJSON(conn, ackPayload); err != nil {
				return fmt.Errorf("命令已执行但 ACK 发送失败（服务端将按命令 ID 幂等重投）: %w", err)
			}
			var ack struct {
				Type    string `json:"type"`
				ID      string `json:"id"`
				OK      bool   `json:"ok"`
				Message string `json:"message"`
			}
			if err := readAgentWSJSON(conn, &ack, 30*time.Second); err != nil {
				return fmt.Errorf("读取命令 ACK 确认失败：%w", err)
			}
			if ack.Type != "command.acknowledged" || ack.ID != cmd.ID || !ack.OK {
				return fmt.Errorf("主控端命令 ACK 确认无效: %s", ack.Message)
			}
			if commandErr != nil {
				fmt.Printf("Agent 命令 %s 执行失败: %s\n", cmd.ID, message)
			}
		default:
			return fmt.Errorf("未知的 WebSocket 命令响应类型: %s", commandEnvelope.Type)
		}

		// Heartbeats on every cycle keep the socket alive; no HTTP status/config/command fallback.
		time.Sleep(heartbeatInterval)
	}
}

// Serialize the complete registration exchange and credential commit. Concurrent
// bind requests must not interleave controller registrations and local token writes.
var agentBindMu sync.Mutex

func lockAgentBind() func() {
	agentBindMu.Lock()
	return agentBindMu.Unlock
}

// Track the single active control-plane socket so a successful rebind can
// terminate the old authenticated session immediately. The reconnect loop then
// rereads agent.json and authenticates with the newly committed token.
var agentActiveWSMu sync.Mutex
var agentActiveWSConn *websocket.Conn
var agentBindingGeneration atomic.Uint64

func setAgentActiveWebSocket(conn *websocket.Conn, expectedGeneration uint64) bool {
	agentActiveWSMu.Lock()
	defer agentActiveWSMu.Unlock()
	if agentBindingGeneration.Load() != expectedGeneration {
		return false
	}
	agentActiveWSConn = conn
	return true
}

func markAgentWebSocketConnected(conn *websocket.Conn, expectedGeneration uint64) bool {
	agentActiveWSMu.Lock()
	defer agentActiveWSMu.Unlock()
	if agentActiveWSConn != conn || agentBindingGeneration.Load() != expectedGeneration {
		return false
	}
	agentConnected.Store(true)
	return true
}

func clearAgentActiveWebSocket(conn *websocket.Conn) {
	agentActiveWSMu.Lock()
	if agentActiveWSConn == conn {
		agentActiveWSConn = nil
		agentConnected.Store(false)
	}
	agentActiveWSMu.Unlock()
}

func closeAgentActiveWebSocketForRebind() {
	agentActiveWSMu.Lock()
	conn := agentActiveWSConn
	agentActiveWSConn = nil
	agentConnected.Store(false)
	agentActiveWSMu.Unlock()
	if conn == nil {
		return
	}
	_ = conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Agent credentials rebound"),
		time.Now().Add(time.Second))
	_ = conn.Close()
}

var agentConnected atomic.Bool

func agentConfigHandler(w http.ResponseWriter, r *http.Request) {
	configPath := filepath.Join(mihomoHome(), "agent.json")
	data, readErr := os.ReadFile(configPath)
	configExists := readErr == nil
	configReadable := true
	configValid := true
	var cfg Config
	if readErr != nil && !os.IsNotExist(readErr) {
		configReadable = false
	}
	if readErr == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			configValid = false
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"has_token":       strings.TrimSpace(cfg.Token) != "",
		"central_url":     cfg.CentralURL,
		"connected":       agentConnected.Load(),
		"config_exists":   configExists,
		"config_readable": configReadable,
		"config_valid":    configValid,
	})
}

func writeAgentWSJSON(conn *websocket.Conn, value any) error {
	agentWSWriteMu.Lock()
	defer agentWSWriteMu.Unlock()
	if err := conn.SetWriteDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return err
	}
	return conn.WriteJSON(value)
}

func readAgentWSJSON(conn *websocket.Conn, target any, timeout time.Duration) error {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	return conn.ReadJSON(target)
}

func main() {
	// 启动 80 端口提供 Web 注册界面
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "/app/index.html")
		})

		// ====== 提供前端页面的 API ======
		http.HandleFunc("/api/machine-id", machineIDHandler)
		http.HandleFunc("/api/hostname", hostnameHandler)

		http.HandleFunc("/api/config", agentConfigHandler)

		http.HandleFunc("/api/bind", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				http.Error(w, "仅允许 POST", http.StatusMethodNotAllowed)
				return
			}
			// Hold the lock through remote registration and the atomic local commit:
			// otherwise overlapping requests can leave the controller and agent.json
			// referring to different registration tokens.
			unlockBind := lockAgentBind()
			defer unlockBind()
			r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
			var in struct {
				CentralURL string `json:"central_url"`
				Secret     string `json:"secret"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				http.Error(w, "参数错误", http.StatusBadRequest)
				return
			}
			centralURL, urlErr := normalizeCentralURLInput(in.CentralURL)
			if urlErr != nil || strings.TrimSpace(in.Secret) == "" {
				http.Error(w, "主控地址或授权密钥无效；默认要求 HTTPS，可信内网如需 HTTP 必须显式设置 S5M_ALLOW_INSECURE_HTTP=1；地址不能包含凭据、查询参数或片段", http.StatusBadRequest)
				return
			}
			machineID, machineErr := getMachineID()
			if machineErr != nil {
				http.Error(w, "无法生成或读取有效机器码: "+machineErr.Error(), http.StatusInternalServerError)
				return
			}
			requestData, err := json.Marshal(map[string]string{"machine_code": machineID, "secret": in.Secret})
			if err != nil {
				http.Error(w, "生成注册请求失败", http.StatusInternalServerError)
				return
			}
			registerReq, err := http.NewRequest(http.MethodPost, centralURL+"/api/v1/agent/register", bytes.NewReader(requestData))
			if err != nil {
				http.Error(w, "主控地址无效", http.StatusBadRequest)
				return
			}
			registerReq.Header.Set("Content-Type", "application/json")
			resp, err := newAgentRegistrationHTTPClient().Do(registerReq)
			if err != nil {
				http.Error(w, "连接主控端失败，请检查地址和网络", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				http.Error(w, "主控端拒绝注册，请检查授权密钥", http.StatusUnauthorized)
				return
			}
			var result struct {
				Token string `json:"token"`
			}
			if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&result); err != nil || strings.TrimSpace(result.Token) == "" {
				http.Error(w, "主控端返回的注册凭证无效", http.StatusBadGateway)
				return
			}
			if err := os.MkdirAll(mihomoHome(), 0700); err != nil {
				http.Error(w, "创建 Agent 数据目录失败", http.StatusInternalServerError)
				return
			}
			b, err := json.Marshal(Config{CentralURL: centralURL, Token: result.Token})
			if err != nil {
				http.Error(w, "序列化绑定配置失败", http.StatusInternalServerError)
				return
			}
			configPath := filepath.Join(mihomoHome(), "agent.json")
			// The binding token is a credential: use the same fsync + atomic
			// replacement path as controller-managed configuration writes.
			if err := atomicWriteFile(configPath, b, 0600); err != nil {
				http.Error(w, "保存绑定配置失败", http.StatusInternalServerError)
				return
			}
			// Only after the new token is durably committed do we close the old
			// session. Failed registration or disk writes leave it untouched.
			agentBindingGeneration.Add(1)
			closeAgentActiveWebSocketForRebind()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "绑定成功"})
		})
		fmt.Println("Agent Web 服务已启动: :80")
		if err := http.ListenAndServe(":80", nil); err != nil {
			fmt.Println("Agent Web 服务启动失败:", err)
		}
	}()

	// 确保 data 目录存在
	os.MkdirAll(mihomoHome(), 0700)

	// 控制面采用单条持久 WebSocket：状态、配置同步、命令投递与 ACK 均走该连接。
	// HTTP 仅用于主控连通性探测和首次注册；绝不通过 HTTP 回退传输状态/配置/命令。
	backoff := 2 * time.Second
	for {
		bindingGeneration := agentBindingGeneration.Load()
		data, readErr := os.ReadFile(filepath.Join(mihomoHome(), "agent.json"))
		if readErr != nil || len(data) == 0 {
			time.Sleep(5 * time.Second)
			continue
		}
		var cfg Config
		if err := json.Unmarshal(data, &cfg); err != nil || strings.TrimSpace(cfg.Token) == "" {
			time.Sleep(5 * time.Second)
			continue
		}
		if routeErr := refreshAndApplyCentralRouteExclusions(cfg.CentralURL); routeErr != nil {
			fmt.Printf("刷新主控直连排除地址失败（将继续重试）: %s\n", safeMihomoValidationDiagnostic([]byte(routeErr.Error())))
		}
		if err := probeControllerHTTP(cfg); err != nil {
			fmt.Printf("主控 HTTP 连通性探测失败（仅用于诊断，不传输状态/配置/命令）: %s\n", safeMihomoValidationDiagnostic([]byte(err.Error())))
			// Jitter probe failures too, so large Agent fleets do not retry in lockstep.
			time.Sleep(reconnectDelayWithJitter(backoff))
			backoff = nextReconnectDelay(backoff)
			continue
		}
		// A bind may complete while the HTTP probe is running. Never start a
		// session using credentials read before the latest successful bind.
		if agentBindingGeneration.Load() != bindingGeneration {
			continue
		}
		sessionStarted := time.Now()
		if err := runAgentWebSocketSession(cfg, bindingGeneration); err != nil {
			fmt.Printf("Agent WebSocket 会话断开: %s\n", safeMihomoValidationDiagnostic([]byte(err.Error())))
		}
		// A session that stayed healthy for at least two minutes resets the
		// exponential backoff; short-lived sessions continue backing off.
		if time.Since(sessionStarted) >= 2*time.Minute {
			backoff = 2 * time.Second
		}
		time.Sleep(reconnectDelayWithJitter(backoff))
		backoff = nextReconnectDelay(backoff)
	}
}
