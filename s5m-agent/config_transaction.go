package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"\n\t"time"
)

// snapshotFileForTransaction preserves the exact previous bytes and whether
// the live file existed. The sidecar is durable before any live file changes.
func snapshotFileForTransaction(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		_ = os.Remove(path + ".previous")
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

	oldSmartDNS, hadSmartDNS, err := backupSmartDNSConfig(smartPath, smartPath+".previous")
	if err != nil {
		return fmt.Errorf("保存 SmartDNS 事务回滚点失败: %w", err)
	}
	oldMihomo, hadMihomo, err := snapshotFileForTransaction(mihomoPath)
	if err != nil {
		return fmt.Errorf("保存 Mihomo 事务回滚点失败: %w", err)
	}
	if !hadMihomo {
		return fmt.Errorf("Mihomo 当前配置不存在，拒绝开始联合事务")
	}
	oldManaged, hadManaged, err := snapshotFileForTransaction(managedPath)
	if err != nil {
		return fmt.Errorf("保存 managed CIDR 事务回滚点失败: %w", err)
	}
	oldController, hadController, err := snapshotFileForTransaction(controllerPath)
	if err != nil {
		return fmt.Errorf("保存主控配置哈希事务回滚点失败: %w", err)
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
		} else if updateSmartDNS {
			if err := exec.Command("/command/s6-svc", "-r", "/run/service/smartdns").Run(); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("重启回滚后的 SmartDNS 失败: %w", err))
			} else if !waitForSmartDNSHealthy(5 * time.Second) {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("回滚后的 SmartDNS 未通过 UDP/TCP DNS 健康检查"))
			}
		}
		if err := reloadMihomo(); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("回滚后的 Mihomo 未通过运行规则验证: %w", err))
		}
		if len(rollbackErrors) > 0 {
			return fmt.Errorf("%w；联合回滚存在错误: %w", cause, errors.Join(rollbackErrors...))
		}
		return cause
	}

	if _, err := mergeConfigWithCentralURLLocked(mihomoYAML, centralURL); err != nil {
		return rollback(fmt.Errorf("应用 Mihomo 配置失败: %w", err))
	}
	if err := reloadMihomo(); err != nil {
		return rollback(fmt.Errorf("Mihomo 联合事务健康检查失败: %w", err))
	}

	if updateSmartDNS {
		if _, err := writeSmartDNSConfigLockedWithBackupCleanup(smartDNSConfig, false); err != nil {
			return rollback(fmt.Errorf("应用 SmartDNS 配置失败: %w", err))
		}
	}
	if hadSmartDNS || updateSmartDNS {
		if !waitForSmartDNSHealthy(5 * time.Second) {
			return rollback(fmt.Errorf("SmartDNS 联合事务 UDP/TCP DNS 健康检查失败"))
		}
	}
	if err := writeControllerConfig(mihomoYAML); err != nil {
		return rollback(fmt.Errorf("提交主控配置哈希失败: %w", err))
	}

	// Both services and the controller hash are now committed. Only this point
	// is allowed to remove either service's rollback copy.
	var cleanupErrors []error
	for _, path := range []string{smartPath, mihomoPath, managedPath, controllerPath} {
		if err := removeTransactionBackup(path); err != nil {
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

