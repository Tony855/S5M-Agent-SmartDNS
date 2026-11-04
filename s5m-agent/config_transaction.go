package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// snapshotFileForTransaction preserves the exact previous bytes and whether
// the live file existed. The sidecar is durable before any live file changes.
func snapshotFileForTransaction(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
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
	previous, readErr := os.ReadFile(path)
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
	return applyAgentConfigTransactionWithFallbackProbe(mihomoYAML, smartDNSConfig, updateSmartDNS, centralURL, false)
}

func applyAgentConfigTransactionWithFallbackProbe(mihomoYAML, smartDNSConfig []byte, updateSmartDNS bool, centralURL string, verifyFallbackDNS bool) error {
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

	rollback := func(cause error) error {
		var rollbackErrors []error
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
		} else if (hadSmartDNS || updateSmartDNS) && smartDNSRuntimeEnabled() {
			if err := transactionRestartSmartDNS(); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("重启回滚后的 SmartDNS 失败: %w", err))
			} else if !transactionWaitSmartDNSHealthy(5 * time.Second) {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("回滚后的 SmartDNS 未通过 UDP/TCP DNS 健康检查"))
			}
		}
		if err := transactionReloadMihomo(); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("回滚后的 Mihomo 未通过运行规则验证: %w", err))
		}
		if len(rollbackErrors) > 0 {
			return fmt.Errorf("%w；联合回滚存在错误: %w", cause, errors.Join(rollbackErrors...))
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
		if _, err := transactionApplySmartDNS(smartDNSConfig, false); err != nil {
			return rollback(fmt.Errorf("应用 SmartDNS 配置失败: %w", err))
		}
	}
	if (hadSmartDNS || updateSmartDNS) && smartDNSRuntimeEnabled() {
		if !transactionWaitSmartDNSHealthy(5 * time.Second) {
			return rollback(fmt.Errorf("SmartDNS 联合事务 UDP/TCP DNS 健康检查失败"))
		}
	}
	if err := transactionWriteControllerConfig(mihomoYAML); err != nil {
		return rollback(fmt.Errorf("提交主控配置哈希失败: %w", err))
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
	return nil
}



// applyAgentSmartDNSEnabled changes Mihomo DNS and the SmartDNS daemon as one
// recoverable operation. Enabling starts and verifies SmartDNS before Mihomo
// begins using it. Disabling commits the fallback Mihomo config before stopping
// the daemon, and the marker survives container restarts.
func applyAgentSmartDNSEnabled(enabled bool, mihomoYAML, smartDNSConfig []byte, centralURL string) error {
	if !smartDNSBinaryAvailable() {
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
			if err != nil { return fmt.Errorf("启用 SmartDNS 前读取现有配置失败: %w", err) }
		}
		if err := validateSmartDNSConfig(smartDNSConfig); err != nil {
			return fmt.Errorf("启用 SmartDNS 的配置未通过安全校验: %w", err)
		}
		if !smartDNSConfigHasDomesticListener(smartDNSConfig) {
			return fmt.Errorf("当前 Mihomo DNS 配置需要 127.0.0.1:6054 国内解析，但 SmartDNS 配置没有完整的 UDP/TCP china-dot 监听")
		}
		if !wasEnabled {
			if err := persistSmartDNSDisabled(false); err != nil { return err }
			if err := smartDNSServiceStart(); err != nil {
				_ = persistSmartDNSDisabled(true)
				_ = smartDNSServiceStop()
				return fmt.Errorf("启动 SmartDNS s6 服务失败: %w", err)
			}
		}
		if !waitForSmartDNSHealthy(5 * time.Second) {
			if !wasEnabled {
				_ = persistSmartDNSDisabled(true)
				_ = smartDNSServiceStop()
			}
			return fmt.Errorf("SmartDNS 当前未通过 UDP/TCP DNS 健康检查，未切换 Mihomo")
		}
		if err := applyAgentConfigTransaction(mihomoYAML, smartDNSConfig, true, centralURL); err != nil {
			if !wasEnabled {
				_ = persistSmartDNSDisabled(true)
				_ = smartDNSServiceStop()
			}
			return fmt.Errorf("启用 SmartDNS 的联合配置事务失败: %w", err)
		}
		return nil
	}

	// Persist the disabled marker before changing Mihomo so a concurrent
	// heartbeat/config refresh cannot try to auto-restart the resolver.
	if err := persistSmartDNSDisabled(true); err != nil { return err }
	if err := applyAgentConfigTransactionWithFallbackProbe(mihomoYAML, nil, false, centralURL, true); err != nil {
		if wasEnabled {
			if restoreErr := persistSmartDNSDisabled(false); restoreErr != nil {
				return fmt.Errorf("切换备用 DNS 失败: %v；恢复 SmartDNS 启用标记也失败: %w", err, restoreErr)
			}
			if startErr := smartDNSServiceStart(); startErr != nil {
				return fmt.Errorf("切换备用 DNS 失败: %v；恢复 SmartDNS 服务失败: %w", err, startErr)
			}
			if !waitForSmartDNSHealthy(5 * time.Second) {
				return fmt.Errorf("切换备用 DNS 失败，SmartDNS 服务已尝试恢复但未通过 DNS 健康检查: %w", err)
			}
		}
		return fmt.Errorf("切换 Mihomo 备用 DNS 失败，SmartDNS 未停止: %w", err)
	}
	if err := smartDNSServiceStop(); err != nil {
		if wasEnabled {
			_ = persistSmartDNSDisabled(false)
			if startErr := smartDNSServiceStart(); startErr != nil {
				return fmt.Errorf("Mihomo 已切换备用 DNS，但停止 SmartDNS 失败: %v；重新启动 SmartDNS 失败: %w", err, startErr)
			}
			if !waitForSmartDNSHealthy(5 * time.Second) {
				return fmt.Errorf("Mihomo 已切换备用 DNS，但 SmartDNS 停止失败且服务恢复未通过健康检查: %w", err)
			}
		}
		return fmt.Errorf("Mihomo 已切换备用 DNS，但停止 SmartDNS 服务失败: %w", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if exec.Command("pidof", "smartdns").Run() != nil { return nil }
		time.Sleep(100 * time.Millisecond)
	}
	if wasEnabled {
		_ = persistSmartDNSDisabled(false)
		_ = smartDNSServiceStart()
		_ = waitForSmartDNSHealthy(5 * time.Second)
	}
	return fmt.Errorf("已下发停止命令，但 SmartDNS 进程在 5 秒内仍未退出")
}
