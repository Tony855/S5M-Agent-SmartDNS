package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
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
	Version         int                    `json:"version"`
	Phase           string                 `json:"phase"`
	SmartDNS        transactionRecoveryFile `json:"smartdns"`
	SmartDNSUpdated bool                   `json:"smartdns_updated,omitempty"`
	Mihomo          transactionRecoveryFile `json:"mihomo"`
	ManagedRoutes   transactionRecoveryFile `json:"managed_routes"`
	Controller      transactionRecoveryFile `json:"controller"`
}

var (
	configTransactionRecoveryMu sync.Mutex
	transactionWriteRecoveryRecord = writeConfigTransactionRecoveryRecord
	transactionStopSmartDNS = smartDNSServiceStop
	transactionSmartDNSProcessRunning = func() bool { return exec.Command("pidof", "smartdns").Run() == nil }
)

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
	return recoverInterruptedConfigTransactionWithRuntimeChecks(true)
}

// recoverInterruptedConfigTransactionBeforeServices is invoked by s6 cont-init
// before Mihomo/SmartDNS long-running services are started. It restores files
// durably; the supervised services will then start directly from the recovered
// configuration, so no runtime reload/restart is needed here.
func recoverInterruptedConfigTransactionBeforeServices() error {
	return recoverInterruptedConfigTransactionWithRuntimeChecks(false)
}

func recoverInterruptedConfigTransactionWithRuntimeChecks(checkRuntime bool) error {
	configTransactionRecoveryMu.Lock()
	defer configTransactionRecoveryMu.Unlock()

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
		var durabilityWarnings []error
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
		} else if smartErr != nil {
			durabilityWarnings = append(durabilityWarnings, fmt.Errorf("SmartDNS 配置内容已恢复但目录持久化未确认: %w", smartErr))
		}
		if len(restoreErrors) > 0 {
			return fmt.Errorf("联合配置事务启动恢复未完成，恢复记录保留: %w", errors.Join(restoreErrors...))
		}

		if checkRuntime && smartDNSFeatureSupported() {
			if record.SmartDNS.Existed && smartDNSRuntimeEnabled() {
				if err := transactionRestartSmartDNS(); err != nil {
					return fmt.Errorf("重启恢复后的 SmartDNS 失败，恢复记录保留: %w", err)
				}
				if !transactionWaitSmartDNSHealthy(5 * time.Second) {
					return fmt.Errorf("恢复后的 SmartDNS 未通过 UDP/TCP DNS 健康检查，恢复记录保留")
				}
			} else if !record.SmartDNS.Existed && record.SmartDNSUpdated {
				// The transaction may have created and started SmartDNS for the
				// first time. Restoring an absent prior config is not enough while
				// the daemon is still serving the uncommitted candidate in memory.
				if err := transactionStopSmartDNS(); err != nil && transactionSmartDNSProcessRunning() {
					return fmt.Errorf("恢复到原本不存在的 SmartDNS 配置后停止残留服务失败，恢复记录保留: %w", err)
				}
				deadline := time.Now().Add(5 * time.Second)
				for transactionSmartDNSProcessRunning() && time.Now().Before(deadline) {
					time.Sleep(100 * time.Millisecond)
				}
				if transactionSmartDNSProcessRunning() {
					return fmt.Errorf("恢复到原本不存在的 SmartDNS 配置后，残留进程未在 5 秒内退出，恢复记录保留")
				}
			}
		}
		if checkRuntime {
			if err := transactionReloadMihomo(); err != nil {
				return fmt.Errorf("恢复后的 Mihomo 未通过运行规则验证，恢复记录保留: %w", err)
			}
		}
		if len(durabilityWarnings) > 0 {
			return fmt.Errorf("联合配置已恢复，但持久化确认失败，保留恢复记录等待重试: %w", errors.Join(durabilityWarnings...))
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
	return nil
}
