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
	if err := atomicWriteFile(path+".previous", data, 0600); err != nil {
		return nil, false, err
	}
	return data, true, nil
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
)

// applyAgentConfigTransaction serializes the complete Mihomo+SmartDNS update.
// Lock order is always SmartDNS then Mihomo. The caller must not hold either
// lock. Both rollback points and managed-route state remain available until
// Mihomo runtime rules and SmartDNS DNS probes have passed.
func applyAgentConfigTransaction(mihomoYAML, smartDNSConfig []byte, updateSmartDNS bool, centralURL string) error {
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
		} else if hadSmartDNS || updateSmartDNS {
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

	if updateSmartDNS {
		if _, err := transactionApplySmartDNS(smartDNSConfig, false); err != nil {
			return rollback(fmt.Errorf("应用 SmartDNS 配置失败: %w", err))
		}
	}
	if hadSmartDNS || updateSmartDNS {
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

