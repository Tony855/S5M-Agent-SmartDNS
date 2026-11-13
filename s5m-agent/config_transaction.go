package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

const transactionSnapshotMaxBytes = 4 << 20

// readTransactionFileNoFollow reads only a bounded regular file and refuses
// symlinks. Transaction snapshots must never follow a replaced config/sidecar
// path outside the Agent data directory.
func readTransactionFileNoFollow(path string, maxBytes int64) ([]byte, error) {
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
		return nil, fmt.Errorf("事务快照路径不是普通文件")
	}
	if info.Size() < 0 || info.Size() > maxBytes {
		return nil, fmt.Errorf("事务快照文件超过 %d 字节", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("事务快照文件超过 %d 字节", maxBytes)
	}
	return data, nil
}

// snapshotFileForTransaction preserves the exact previous bytes and whether
// the live file existed. The sidecar is durable before any live file changes.
func snapshotFileForTransaction(path string) ([]byte, bool, error) {
	data, err := readTransactionFileNoFollow(path, transactionSnapshotMaxBytes)
	if os.IsNotExist(err) {
		backupPath := path + ".previous"
		if removeErr := os.Remove(backupPath); removeErr == nil {
			if syncErr := syncTransactionDirectory(filepath.Dir(backupPath)); syncErr != nil {
				return nil, false, fmt.Errorf("同步过期事务备份目录失败: %w", syncErr)
			}
		} else if !os.IsNotExist(removeErr) {
			return nil, false, fmt.Errorf("清理过期事务备份失败: %w", removeErr)
		}
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := writeTransactionBackupPreservingPrior(path+".previous", data, atomicWriteFile); err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// writeTransactionBackupPreservingPrior keeps an existing recovery sidecar
// intact if writing its replacement fails at any point, including after rename
// but before the containing-directory fsync completes.
func writeTransactionBackupPreservingPrior(path string, data []byte, write func(string, []byte, os.FileMode) error) error {
	previous, readErr := readTransactionFileNoFollow(path, transactionSnapshotMaxBytes)
	previousExists := readErr == nil
	if readErr != nil && !os.IsNotExist(readErr) {
		return fmt.Errorf("读取已有事务备份失败: %w", readErr)
	}
	if err := write(path, data, 0600); err != nil {
		var restoreErr error
		if previousExists {
			restoreErr = atomicWriteFile(path, previous, 0600)
		} else {
			restoreErr = os.Remove(path)
			if os.IsNotExist(restoreErr) {
				restoreErr = nil
			}
			if restoreErr == nil {
				restoreErr = syncTransactionDirectory(filepath.Dir(path))
			}
		}
		if restoreErr != nil {
			return fmt.Errorf("写入事务备份失败: %v；恢复原备份副本失败: %w", err, restoreErr)
		}
		return err
	}
	return nil
}

func syncTransactionDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func restoreFileSnapshot(path string, data []byte, existed bool) error {
	if existed {
		return atomicWriteFile(path, data, 0600)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func removeTransactionBackup(path string) error {
	if err := os.Remove(path + ".previous"); err != nil && !os.IsNotExist(err) {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Transaction operation seams keep rollback behavior fault-injectable in tests.
var (
	transactionMergeMihomo = mergeConfigWithCentralURLLocked
	transactionReloadMihomo = reloadMihomo
	transactionApplySmartDNS = writeSmartDNSConfigLockedWithBackupCleanup
	transactionWaitSmartDNSHealthy = waitForSmartDNSHealthy
	transactionRestartSmartDNS = func() error {
		return exec.Command("/command/s6-svc", "-r", "/run/service/smartdns").Run()
	}
	transactionWriteControllerConfig = writeControllerConfig
	transactionRemoveBackup = removeTransactionBackup
	transactionSnapshotFile = snapshotFileForTransaction
	transactionProbeMihomoDNS = probeMihomoDNSFallback
)

// applyAgentConfigTransaction serializes the complete Mihomo+SmartDNS update.
// Lock order is always SmartDNS then Mihomo. The caller must not hold either
// lock. Both rollback points and managed-route state remain available until
// Mihomo runtime rules and SmartDNS DNS probes have passed.
func applyAgentConfigTransaction(mihomoYAML, smartDNSConfig []byte, updateSmartDNS bool, centralURL string) error {
	controllerPayload := mihomoYAML
	if !smartDNSFeatureSupported() {
		if updateSmartDNS {
			return fmt.Errorf("当前 Agent 镜像不包含 SmartDNS，拒绝应用 SmartDNS 配置")
		}
		var err error
		mihomoYAML, err = normalizeNoSmartDNSYAML(mihomoYAML)
		if err != nil { return fmt.Errorf("清理主控下发配置中的 SmartDNS DNS 引用失败: %w", err) }
	}
	return applyAgentConfigTransactionWithControllerPayload(mihomoYAML, smartDNSConfig, updateSmartDNS, centralURL, false, controllerPayload, false)
}

func applyAgentConfigTransactionWithFallbackProbe(mihomoYAML, smartDNSConfig []byte, updateSmartDNS bool, centralURL string, verifyFallbackDNS bool) error {
	return applyAgentConfigTransactionWithControllerPayload(mihomoYAML, smartDNSConfig, updateSmartDNS, centralURL, verifyFallbackDNS, mihomoYAML, true)
}

// Runtime YAML may be sanitized for an image capability while the exact
// controller payload is retained separately for WebSocket SHA-256 consistency.
func applyAgentConfigTransactionWithControllerPayload(mihomoYAML, smartDNSConfig []byte, updateSmartDNS bool, centralURL string, verifyFallbackDNS bool, controllerPayload []byte, skipSmartDNSHealth bool) error {
	return applyAgentConfigTransactionWithSmartDNSApply(mihomoYAML, smartDNSConfig, updateSmartDNS, centralURL, verifyFallbackDNS, controllerPayload, skipSmartDNSHealth, transactionApplySmartDNS)
}

// applyAgentConfigTransactionWithIngress validates per-client configuration
// against the explicit Master-provided ingress contract, then uses the same
// durable Mihomo+SmartDNS transaction and rollback journal as shared mode.
func applyAgentConfigTransactionWithIngress(mihomoYAML, smartDNSConfig []byte, updateSmartDNS bool, centralURL string, contract smartDNSPerClientIngressContract) error {
	validator := func(data []byte) error { return validateSmartDNSConfigWithIngress(data, contract) }
	if err := validator(smartDNSConfig); err != nil {
		return fmt.Errorf("per-client SmartDNS ingress contract validation failed: %w", err)
	}
	apply := func(data []byte, cleanupBackup bool) (string, error) {
		return writeSmartDNSConfigLockedWithValidator(data, cleanupBackup, validator)
	}
	return applyAgentConfigTransactionWithSmartDNSApply(mihomoYAML, smartDNSConfig, updateSmartDNS, centralURL, false, mihomoYAML, false, apply)
}

func applyAgentConfigTransactionWithSmartDNSApply(mihomoYAML, smartDNSConfig []byte, updateSmartDNS bool, centralURL string, verifyFallbackDNS bool, controllerPayload []byte, skipSmartDNSHealth bool, applySmartDNS func([]byte, bool) (string, error)) error {
	if applySmartDNS == nil {
		return fmt.Errorf("SmartDNS transaction apply function is unavailable")
	}
	smartDNSConfigMu.Lock()
	defer smartDNSConfigMu.Unlock()
	mihomoConfigApplyMu.Lock()
	defer mihomoConfigApplyMu.Unlock()

	smartPath := smartDNSConfigPath
	mihomoPath := mihomoConfigPath()
	managedPath := managedRouteCIDRsPath()
	controllerPath := controllerConfigPath()

	preparedBackups := []string{}
	cleanupPrepared := func(cause error) error {
		var cleanupErrors []error
		for _, path := range preparedBackups {
			if cleanupErr := transactionRemoveBackup(path); cleanupErr != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("清理未启动事务的备份 %s 失败: %w", filepath.Base(path), cleanupErr))
			}
		}
		if len(cleanupErrors) > 0 {
			return fmt.Errorf("%w；事务预备阶段清理失败: %w", cause, errors.Join(cleanupErrors...))
		}
		return cause
	}
	oldSmartDNS, hadSmartDNS, err := backupSmartDNSConfig(smartPath, smartPath+".previous")
	if err != nil {
		return fmt.Errorf("保存 SmartDNS 事务回滚点失败: %w", err)
	}
	if hadSmartDNS {
		preparedBackups = append(preparedBackups, smartPath)
	}
	oldMihomo, hadMihomo, err := transactionSnapshotFile(mihomoPath)
	if err != nil {
		return cleanupPrepared(fmt.Errorf("保存 Mihomo 事务回滚点失败: %w", err))
	}
	if !hadMihomo {
		return cleanupPrepared(fmt.Errorf("Mihomo 当前配置不存在，拒绝开始联合事务"))
	}
	preparedBackups = append(preparedBackups, mihomoPath)
	oldManaged, hadManaged, err := transactionSnapshotFile(managedPath)
	if err != nil {
		return cleanupPrepared(fmt.Errorf("保存 managed CIDR 事务回滚点失败: %w", err))
	}
	if hadManaged {
		preparedBackups = append(preparedBackups, managedPath)
	}
	oldController, hadController, err := transactionSnapshotFile(controllerPath)
	if err != nil {
		return cleanupPrepared(fmt.Errorf("保存主控配置哈希事务回滚点失败: %w", err))
	}
	if hadController {
		preparedBackups = append(preparedBackups, controllerPath)
	}

	// Persist the complete pre-transaction state before the first live mutation.
	journal := configTransactionRecoveryRecord{
		Version: 1, Phase: "prepared",
		SmartDNS: transactionRecoveryFile{Data: oldSmartDNS, Existed: hadSmartDNS},
		Mihomo: transactionRecoveryFile{Data: oldMihomo, Existed: hadMihomo},
		ManagedRoutes: transactionRecoveryFile{Data: oldManaged, Existed: hadManaged},
		Controller: transactionRecoveryFile{Data: oldController, Existed: hadController},
	}
	if err := transactionWriteRecoveryRecord(journal); err != nil {
		return cleanupPrepared(fmt.Errorf("持久化联合配置事务恢复记录失败，拒绝修改运行配置: %w", err))
	}

	rollback := func(cause error) error {
		var rollbackErrors []error
		// If the commit-marker rename reached disk but its directory fsync
		// returned an error, force the recovery record back to prepared before
		// attempting rollback. Otherwise a later boot could mistake old state
		// restoration for a committed transaction.
		journal.Phase = "prepared"
		if err := transactionWriteRecoveryRecord(journal); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("重置事务恢复阶段失败: %w", err))
		}
		// Keep the old Mihomo bytes in .previous while restoring the live file:
		// reloadMihomo uses both secrets during an ambiguous reload transition.
		if err := atomicWriteFile(mihomoPath+".previous", oldMihomo, 0600); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("重建 Mihomo 回滚备份失败: %w", err))
		}
		if err := restoreFileSnapshot(mihomoPath, oldMihomo, hadMihomo); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("恢复 Mihomo 配置失败: %w", err))
		}
		if err := restoreFileSnapshot(managedPath, oldManaged, hadManaged); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("恢复 managed CIDR 记录失败: %w", err))
		}
		if err := restoreFileSnapshot(controllerPath, oldController, hadController); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("恢复主控配置哈希失败: %w", err))
		}
		restored, restoreErr := restoreSmartDNSConfigVerified(smartPath, oldSmartDNS, hadSmartDNS)
		if !restored {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("恢复 SmartDNS 配置失败: %w", restoreErr))
		} else if !skipSmartDNSHealth && smartDNSFeatureSupported() && (hadSmartDNS || updateSmartDNS) && smartDNSRuntimeEnabled() {
			if err := transactionRestartSmartDNS(); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("重启回滚后的 SmartDNS 失败: %w", err))
			} else if !transactionWaitSmartDNSHealthy(5 * time.Second) {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("回滚后的 SmartDNS 未通过 UDP/TCP DNS 健康检查"))
			}
		}
		if err := transactionReloadMihomo(); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("回滚后的 Mihomo 未通过运行规则验证: %w", err))
		}
		if restored && restoreErr != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("SmartDNS 配置内容已恢复但目录持久化未确认: %w", restoreErr))
		}
		if len(rollbackErrors) > 0 {
			return fmt.Errorf("%w；联合回滚存在错误，恢复记录保留供下次启动重试: %w", cause, errors.Join(rollbackErrors...))
		}
		if err := removeConfigTransactionRecoveryRecord(); err != nil {
			return fmt.Errorf("%w；联合回滚已恢复，但清理事务恢复记录失败: %w", cause, err)
		}
		return cause
	}

	if _, err := transactionMergeMihomo(mihomoYAML, centralURL); err != nil {
		return rollback(fmt.Errorf("应用 Mihomo 配置失败: %w", err))
	}
	if err := transactionReloadMihomo(); err != nil {
		return rollback(fmt.Errorf("Mihomo 联合事务健康检查失败: %w", err))
	}
	if verifyFallbackDNS && (transactionProbeMihomoDNS == nil || !transactionProbeMihomoDNS(mihomoYAML)) {
		return rollback(fmt.Errorf("Mihomo 备用 DNS 的 A/AAAA 实际查询探测失败，拒绝停止 SmartDNS"))
	}

	if updateSmartDNS {
		if _, err := applySmartDNS(smartDNSConfig, false); err != nil {
			return rollback(fmt.Errorf("应用 SmartDNS 配置失败: %w", err))
		}
	}
	if !skipSmartDNSHealth && smartDNSFeatureSupported() && (hadSmartDNS || updateSmartDNS) && smartDNSRuntimeEnabled() {
		if !transactionWaitSmartDNSHealthy(5 * time.Second) {
			return rollback(fmt.Errorf("SmartDNS 联合事务 UDP/TCP DNS 健康检查失败"))
		}
	}
	if err := transactionWriteControllerConfig(controllerPayload); err != nil {
		return rollback(fmt.Errorf("提交主控配置哈希失败: %w", err))
	}

	// The durable commit marker separates accepted new state from a transaction
	// that must be rolled back after an unclean process exit.
	journal.Phase = "committed"
	if err := transactionWriteRecoveryRecord(journal); err != nil {
		return rollback(fmt.Errorf("提交联合配置事务恢复记录失败: %w", err))
	}

	// Both services and the controller hash are now committed. Only this point
	// is allowed to remove either service's rollback copy.
	var cleanupErrors []error
	for _, path := range []string{smartPath, mihomoPath, managedPath, controllerPath} {
		if err := transactionRemoveBackup(path); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	if len(cleanupErrors) > 0 {
		// The joint apply is already healthy. Retain any sidecar that could not
		// be removed and report a warning without misreporting the apply itself.
		fmt.Printf("联合配置已健康应用，但部分事务备份清理失败: %v\n", errors.Join(cleanupErrors...))
	}
	if err := removeConfigTransactionRecoveryRecord(); err != nil {
		fmt.Printf("联合配置已健康提交，但清理事务恢复记录失败: %v\n", err)
	}
	return nil
}



// rollbackFailedSmartDNSEnable restores the durable disabled intent and asks
// s6 to stop a service whose first enable attempt did not complete. Cleanup
// failures are joined with the initiating error: silently ignoring either one
// can leave SmartDNS running or cause it to be started again after a restart.
func rollbackFailedSmartDNSEnable(cause error, persistDisabled func(bool) error, stopService func() error) error {
	if cause == nil {
		cause = fmt.Errorf("SmartDNS 启用失败")
	}
	var cleanupErrors []error
	if persistDisabled == nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("恢复 SmartDNS 禁用标记操作不可用"))
	} else if err := persistDisabled(true); err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("恢复 SmartDNS 禁用标记失败: %w", err))
	}
	if stopService == nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("停止失败的 SmartDNS 服务操作不可用"))
	} else if err := stopService(); err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("停止失败的 SmartDNS 服务失败: %w", err))
	}
	if len(cleanupErrors) > 0 {
		return fmt.Errorf("%w；启用回滚失败: %w", cause, errors.Join(cleanupErrors...))
	}
	return cause
}

func ensureSmartDNSServiceStarted(wasEnabled bool) error {
	if !wasEnabled {
		if err := persistSmartDNSDisabled(false); err != nil {
			return err
		}
		// When disabled, the s6 run script remains alive waiting for this marker
		// to disappear. -u treats that waiter as already up; -r is required to
		// rerun the script and launch the actual SmartDNS daemon.
		if err := smartDNSServiceRestart(); err != nil {
			startErr := fmt.Errorf("重新启动 SmartDNS s6 服务失败: %w", err)
			return rollbackFailedSmartDNSEnable(startErr, persistSmartDNSDisabled, smartDNSServiceStop)
		}
		return nil
	}
	if err := smartDNSServiceStart(); err != nil {
		return fmt.Errorf("启动/确认 SmartDNS s6 服务失败: %w", err)
	}
	return nil
}

// applyAgentSmartDNSDisableTransition commits and probes fallback DNS before
// persisting the disabled marker. A crash after the marker is written can
// therefore never leave Mihomo pointing at a resolver that s6 will suppress.
func applyAgentSmartDNSDisableTransition(
	applyFallback func() error,
	persistDisabled func(bool) error,
	stopService func() error,
	processRunning func() bool,
	waitStopped func(time.Duration) bool,
) error {
	if applyFallback == nil || persistDisabled == nil || stopService == nil || processRunning == nil || waitStopped == nil {
		return fmt.Errorf("SmartDNS 禁用事务缺少必要操作")
	}
	if err := applyFallback(); err != nil {
		return fmt.Errorf("切换 Mihomo 备用 DNS 失败，SmartDNS 未停止: %w", err)
	}
	if err := persistDisabled(true); err != nil {
		return fmt.Errorf("备用 DNS 已切换，但持久化 SmartDNS 禁用标记失败，服务保持运行: %w", err)
	}
	if err := stopService(); err != nil {
		if !processRunning() {
			return nil
		}
		return fmt.Errorf("Mihomo 已切换备用 DNS；SmartDNS 禁用标记已保留，但停止服务命令失败，进程仍在运行: %w", err)
	}
	if !waitStopped(5 * time.Second) {
		return fmt.Errorf("Mihomo 已切换备用 DNS，SmartDNS 禁用标记已保留，但进程在 5 秒内仍未退出")
	}
	return nil
}

var smartDNSRuntimeTransitionMu sync.Mutex

// applyAgentSmartDNSEnabled changes Mihomo DNS and the SmartDNS daemon as one
// recoverable operation. Enabling starts and verifies SmartDNS before Mihomo
// begins using it. Disabling commits the fallback Mihomo config before stopping
// the daemon, and the marker survives container restarts.
func applyAgentSmartDNSEnabled(enabled bool, mihomoYAML, smartDNSConfig []byte, centralURL string) error {
	return applyAgentSmartDNSEnabledWithValidator(enabled, mihomoYAML, smartDNSConfig, centralURL, validateSmartDNSConfig,
		func(mihomo, smart []byte, central string) error { return applyAgentConfigTransaction(mihomo, smart, true, central) })
}

func applyAgentSmartDNSEnabledWithIngress(enabled bool, mihomoYAML, smartDNSConfig []byte, centralURL string, contract smartDNSPerClientIngressContract) error {
	validator := func(data []byte) error { return validateSmartDNSConfigWithIngress(data, contract) }
	return applyAgentSmartDNSEnabledWithValidator(enabled, mihomoYAML, smartDNSConfig, centralURL, validator,
		func(mihomo, smart []byte, central string) error { return applyAgentConfigTransactionWithIngress(mihomo, smart, true, central, contract) })
}

func applyAgentSmartDNSEnabledWithValidator(enabled bool, mihomoYAML, smartDNSConfig []byte, centralURL string, validator func([]byte) error, applyTransaction func([]byte, []byte, string) error) error {
	if validator == nil || applyTransaction == nil {
		return fmt.Errorf("SmartDNS enable validator or transaction is unavailable")
	}
	smartDNSRuntimeTransitionMu.Lock()
	defer smartDNSRuntimeTransitionMu.Unlock()

	if !smartDNSFeatureSupported() || !smartDNSBinaryAvailable() {
		return fmt.Errorf("当前 Agent 镜像未安装 SmartDNS，不能切换启停状态")
	}
	if len(mihomoYAML) == 0 {
		return fmt.Errorf("缺少主控下发的 Mihomo 配置，拒绝切换 SmartDNS")
	}
	if err := validateAgentSmartDNSDNSMode(mihomoYAML, enabled); err != nil {
		return fmt.Errorf("Mihomo DNS 配置与 SmartDNS 目标状态不一致: %w", err)
	}
	wasEnabled := smartDNSRuntimeEnabled()
	if enabled {
		if len(smartDNSConfig) == 0 {
			var err error
			smartDNSConfig, err = readSmartDNSConfig()
			if err != nil {
				return fmt.Errorf("启用 SmartDNS 前读取现有配置失败: %w", err)
			}
		}
		if err := validator(smartDNSConfig); err != nil {
			return fmt.Errorf("启用 SmartDNS 的配置未通过安全校验: %w", err)
		}
		if !smartDNSConfigHasDomesticListener(smartDNSConfig) {
			return fmt.Errorf("当前 Mihomo DNS 配置需要 127.0.0.1:6054 国内解析，但 SmartDNS 配置没有完整的 UDP/TCP china-dot 监听")
		}
		// Always ask s6 to ensure the service is up, even when the durable
		// desired state already says enabled.
		if err := ensureSmartDNSServiceStarted(wasEnabled); err != nil {
			return err
		}
		if !waitForSmartDNSHealthy(5 * time.Second) {
			healthErr := fmt.Errorf("SmartDNS 当前未通过 UDP/TCP DNS 健康检查，未切换 Mihomo")
			if !wasEnabled {
				return rollbackFailedSmartDNSEnable(healthErr, persistSmartDNSDisabled, smartDNSServiceStop)
			}
			return healthErr
		}
		if err := applyTransaction(mihomoYAML, smartDNSConfig, centralURL); err != nil {
			transactionErr := fmt.Errorf("启用 SmartDNS 的联合配置事务失败: %w", err)
			if !wasEnabled {
				return rollbackFailedSmartDNSEnable(transactionErr, persistSmartDNSDisabled, smartDNSServiceStop)
			}
			return transactionErr
		}
		return nil
	}

	return applyAgentSmartDNSDisableTransition(
		func() error {
			return applyAgentConfigTransactionWithFallbackProbe(mihomoYAML, nil, false, centralURL, true)
		},
		persistSmartDNSDisabled,
		smartDNSServiceStop,
		func() bool { return exec.Command("pidof", "smartdns").Run() == nil },
		func(timeout time.Duration) bool {
			deadline := time.Now().Add(timeout)
			for time.Now().Before(deadline) {
				if exec.Command("pidof", "smartdns").Run() != nil {
					return true
				}
				time.Sleep(100 * time.Millisecond)
			}
			return exec.Command("pidof", "smartdns").Run() != nil
		},
	)
}
