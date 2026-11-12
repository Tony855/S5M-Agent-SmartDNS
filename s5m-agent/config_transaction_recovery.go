package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const configTransactionRecoveryMaxBytes = 24 << 20

type transactionRecoveryFile struct {
	Data    []byte `json:"data"`
	Existed bool   `json:"existed"`
}

type configTransactionRecoveryRecord struct {
	Version       int                    `json:"version"`
	Phase         string                 `json:"phase"`
	SmartDNS      transactionRecoveryFile `json:"smartdns"`
	Mihomo        transactionRecoveryFile `json:"mihomo"`
	ManagedRoutes transactionRecoveryFile `json:"managed_routes"`
	Controller    transactionRecoveryFile `json:"controller"`
}

var configTransactionRecoveryMu sync.Mutex

func configTransactionRecoveryPath() string {
	return filepath.Join(mihomoHome(), ".s5m-config-transaction.json")
}

func writeConfigTransactionRecoveryRecord(record configTransactionRecoveryRecord) error {
	if record.Version != 1 || (record.Phase != "prepared" && record.Phase != "committed") {
		return fmt.Errorf("联合配置事务恢复记录版本或阶段无效")
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > configTransactionRecoveryMaxBytes {
		return fmt.Errorf("联合配置事务恢复记录超过大小限制")
	}
	return atomicWriteFile(configTransactionRecoveryPath(), data, 0600)
}

func removeConfigTransactionRecoveryRecord() error {
	path := configTransactionRecoveryPath()
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

func readConfigTransactionRecoveryRecord() (configTransactionRecoveryRecord, error) {
	var record configTransactionRecoveryRecord
	data, err := readTransactionFileNoFollow(configTransactionRecoveryPath(), configTransactionRecoveryMaxBytes)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return record, fmt.Errorf("解析联合配置事务恢复记录失败: %w", err)
	}
	if record.Version != 1 || (record.Phase != "prepared" && record.Phase != "committed") {
		return record, fmt.Errorf("联合配置事务恢复记录版本或阶段无效")
	}
	for name, snapshot := range map[string]transactionRecoveryFile{
		"SmartDNS": record.SmartDNS,
		"Mihomo": record.Mihomo,
		"managed routes": record.ManagedRoutes,
		"controller": record.Controller,
	} {
		if len(snapshot.Data) > transactionSnapshotMaxBytes || (!snapshot.Existed && len(snapshot.Data) != 0) {
			return record, fmt.Errorf("%s 联合事务快照内容无效", name)
		}
	}
	return record, nil
}

// recoverInterruptedConfigTransaction runs before the Agent reconnects to the
// controller. A prepared record means the process exited before the durable
// commit marker and the entire old config set must be restored. A committed
// record means the new config set was accepted; only stale recovery files are
// cleaned. The journal is retained on every recovery error for the next boot.
func recoverInterruptedConfigTransaction() error {
	configTransactionRecoveryMu.Lock()
	defer configTransactionRecoveryMu.Unlock()

	path := configTransactionRecoveryPath()
	record, err := readConfigTransactionRecoveryRecord()
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("发现联合配置事务恢复记录但无法安全读取，拒绝继续启动: %w", err)
	}

	smartPath := smartDNSConfigPath
	mihomoPath := mihomoConfigPath()
	managedPath := managedRouteCIDRsPath()
	controllerPath := controllerConfigPath()

	if record.Phase == "prepared" {
		smartDNSConfigMu.Lock()
		defer smartDNSConfigMu.Unlock()
		mihomoConfigApplyMu.Lock()
		defer mihomoConfigApplyMu.Unlock()

		var restoreErrors []error
		if err := restoreFileSnapshot(mihomoPath, record.Mihomo.Data, record.Mihomo.Existed); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("恢复 Mihomo 配置失败: %w", err))
		}
		if err := restoreFileSnapshot(managedPath, record.ManagedRoutes.Data, record.ManagedRoutes.Existed); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("恢复 managed CIDR 记录失败: %w", err))
		}
		if err := restoreFileSnapshot(controllerPath, record.Controller.Data, record.Controller.Existed); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("恢复主控配置哈希失败: %w", err))
		}
		restoredSmartDNS, smartErr := restoreSmartDNSConfigVerified(smartPath, record.SmartDNS.Data, record.SmartDNS.Existed)
		if !restoredSmartDNS {
			restoreErrors = append(restoreErrors, fmt.Errorf("恢复 SmartDNS 配置失败: %w", smartErr))
		}
		if len(restoreErrors) > 0 {
			return fmt.Errorf("联合配置事务启动恢复未完成，恢复记录保留: %w", errorsJoin(restoreErrors))
		}

		if record.SmartDNS.Existed && smartDNSFeatureSupported() && smartDNSRuntimeEnabled() {
			if err := transactionRestartSmartDNS(); err != nil {
				return fmt.Errorf("重启恢复后的 SmartDNS 失败，恢复记录保留: %w", err)
			}
			if !transactionWaitSmartDNSHealthy(5 * time.Second) {
				return fmt.Errorf("恢复后的 SmartDNS 未通过 UDP/TCP DNS 健康检查，恢复记录保留")
			}
		}
		if err := transactionReloadMihomo(); err != nil {
			return fmt.Errorf("恢复后的 Mihomo 未通过运行规则验证，恢复记录保留: %w", err)
		}
		fmt.Println("检测到未完成的联合配置事务，已恢复上一次有效配置")
	}

	// The committed phase is durable before backup cleanup begins. On either
	// path, only now is it safe to remove sidecars and then the journal.
	for _, configPath := range []string{smartPath, mihomoPath, managedPath, controllerPath} {
		if err := transactionRemoveBackup(configPath); err != nil {
			return fmt.Errorf("清理联合配置事务备份失败（恢复记录保留）: %w", err)
		}
	}
	if err := removeConfigTransactionRecoveryRecord(); err != nil {
		return fmt.Errorf("清理联合配置事务恢复记录失败: %w", err)
	}
	_ = path
	return nil
}

func errorsJoin(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%v", errs)
}
