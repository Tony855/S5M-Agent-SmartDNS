package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

const (
	agentCommandJournalMaxBytes = 64 << 10
	agentCommandJournalHistoryLimit = 64
)

type agentCommandJournalSeen struct {
	ID          string `json:"id"`
	PayloadHash string `json:"payload_hash"`
}

type agentCommandJournalEntry struct {
	History     []agentCommandJournalSeen `json:"history,omitempty"`
	ID          string `json:"id"`
	PayloadHash string `json:"payload_hash"`
	State       string `json:"state"`
	Status      string `json:"status,omitempty"`
	Message     string `json:"message,omitempty"`
	Config      string `json:"config,omitempty"`
}

var agentCommandJournalMu sync.Mutex

func agentCommandJournalPath() string {
	return filepath.Join(mihomoHome(), "agent-command-journal.json")
}

// readAgentCommandJournal treats the persistent journal as untrusted input:
// do not follow a volume-provided symlink, allocate based on an untrusted file
// size, or accept a journal that is readable by other container users.
func readAgentCommandJournal() (agentCommandJournalEntry, error) {
	var entry agentCommandJournalEntry
	path := agentCommandJournalPath()
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return entry, nil
	}
	if err != nil {
		return entry, fmt.Errorf("读取 Agent 命令执行记录失败: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return entry, fmt.Errorf("检查 Agent 命令执行记录失败: %w", err)
	}
	if !info.Mode().IsRegular() {
		return entry, fmt.Errorf("Agent 命令执行记录不是普通文件，拒绝读取")
	}
	if info.Mode().Perm()&0077 != 0 {
		return entry, fmt.Errorf("Agent 命令执行记录权限过宽，必须限制为仅所有者可访问")
	}
	if info.Size() <= 0 || info.Size() > agentCommandJournalMaxBytes {
		return entry, fmt.Errorf("Agent 命令执行记录为空或超过 64 KiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, agentCommandJournalMaxBytes+1))
	if err != nil {
		return entry, fmt.Errorf("读取 Agent 命令执行记录失败: %w", err)
	}
	if len(data) == 0 || len(data) > agentCommandJournalMaxBytes {
		return entry, fmt.Errorf("Agent 命令执行记录为空或超过 64 KiB")
	}
	if err := json.Unmarshal(data, &entry); err != nil {
		return entry, fmt.Errorf("Agent 命令执行记录损坏，拒绝覆盖: %w", err)
	}
	if strings.TrimSpace(entry.ID) == "" || len(entry.ID) > 256 ||
		len(entry.PayloadHash) != 64 || (entry.State != "running" && entry.State != "completed") {
		return entry, fmt.Errorf("Agent 命令执行记录字段无效，拒绝覆盖")
	}
	if _, err := hex.DecodeString(entry.PayloadHash); err != nil {
		return entry, fmt.Errorf("Agent 命令执行记录 payload hash 无效，拒绝覆盖")
	}
	if entry.State == "completed" && entry.Status != "success" && entry.Status != "failed" {
		return entry, fmt.Errorf("Agent 命令执行记录完成状态无效，拒绝覆盖")
	}
	if len(entry.History) > agentCommandJournalHistoryLimit {
		return entry, fmt.Errorf("Agent 命令执行记录历史超过允许数量，拒绝读取")
	}
	seenIDs := make(map[string]struct{}, len(entry.History))
	for _, seen := range entry.History {
		if strings.TrimSpace(seen.ID) == "" || len(seen.ID) > 256 || len(seen.PayloadHash) != 64 {
			return entry, fmt.Errorf("Agent 命令执行记录历史字段无效，拒绝读取")
		}
		if seen.ID == entry.ID {
			return entry, fmt.Errorf("Agent 命令执行记录当前命令与历史记录冲突，拒绝读取")
		}
		if _, exists := seenIDs[seen.ID]; exists {
			return entry, fmt.Errorf("Agent 命令执行记录历史包含重复命令 ID，拒绝读取")
		}
		seenIDs[seen.ID] = struct{}{}
		if _, err := hex.DecodeString(seen.PayloadHash); err != nil {
			return entry, fmt.Errorf("Agent 命令执行记录历史 hash 无效，拒绝读取")
		}
	}
	if len(entry.Message) > 2048 || len(entry.Config) > 8<<10 {
		return entry, fmt.Errorf("Agent 命令执行记录结果超过允许大小，拒绝读取")
	}
	return entry, nil
}

func writeAgentCommandJournal(entry agentCommandJournalEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > agentCommandJournalMaxBytes {
		return fmt.Errorf("Agent 命令执行记录超过 64 KiB，拒绝写入")
	}
	dir := filepath.Dir(agentCommandJournalPath())
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("创建 Agent 命令记录目录失败: %w", err)
	}
	file, err := os.CreateTemp(dir, ".agent-command-journal-*")
	if err != nil {
		return fmt.Errorf("创建 Agent 命令记录临时文件失败: %w", err)
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return fmt.Errorf("设置 Agent 命令记录权限失败: %w", err)
	}
	n, err := file.Write(data)
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("写入 Agent 命令记录失败: %w", err)
	}
	if n != len(data) {
		_ = file.Close()
		return fmt.Errorf("写入 Agent 命令记录不完整: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("同步 Agent 命令记录失败: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("关闭 Agent 命令记录失败: %w", err)
	}
	if err := os.Rename(tempPath, agentCommandJournalPath()); err != nil {
		return fmt.Errorf("提交 Agent 命令记录失败: %w", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("打开 Agent 命令记录目录以同步提交状态失败: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return fmt.Errorf("同步 Agent 命令记录目录失败: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("关闭 Agent 命令记录目录失败: %w", closeErr)
	}
	return nil
}

// executeAgentCommandWithJournal records intent before side effects and the final
// result before ACK. A crash in "running" is reconciled by rerunning the
// idempotent desired-state operation; a completed command replays its saved ACK.
func executeAgentCommandWithJournal(cmd agentCommand, execute func() (string, string, error)) (status, message, config string, err error) {
	agentCommandJournalMu.Lock()
	defer agentCommandJournalMu.Unlock()

	if strings.TrimSpace(cmd.ID) == "" || len(cmd.ID) > 256 || strings.TrimSpace(cmd.Type) == "" {
		return "failed", "", "", fmt.Errorf("Agent 命令缺少有效 ID 或类型")
	}
	if execute == nil {
		return "failed", "", "", fmt.Errorf("Agent 命令执行函数为空")
	}
	payload, err := json.Marshal(cmd)
	if err != nil {
		return "failed", "", "", fmt.Errorf("编码 Agent 命令失败: %w", err)
	}
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])
	entry, err := readAgentCommandJournal()
	if err != nil {
		return "failed", "", "", err
	}
	if entry.ID == cmd.ID {
		if entry.PayloadHash != hash {
			return "failed", "", "", fmt.Errorf("命令 ID 重复但命令内容不一致，拒绝执行")
		}
		if entry.State == "completed" {
			return entry.Status, entry.Message, entry.Config, nil
		}
	} else {
		// A different command must never overwrite an interrupted running
		// command. The Master allows only one pending command per Agent, so
		// seeing this state means recovery/reconciliation is required first.
		if entry.ID != "" && entry.State == "running" {
			return "failed", "", "", fmt.Errorf("上一条 Agent 命令仍处于未完成状态，拒绝覆盖执行记录")
		}
		for _, seen := range entry.History {
			if seen.ID == cmd.ID {
				if seen.PayloadHash != hash {
					return "failed", "", "", fmt.Errorf("历史命令 ID 重复但命令内容不一致，拒绝执行")
				}
				// The original result may have been evicted from the single-result
				// slot, but the ID/hash tombstone still prevents stale redelivery
				// from repeating its side effects.
				return "failed", "检测到已完成旧命令的重复投递，已阻止再次执行", "", nil
			}
		}
		if entry.ID != "" {
			entry.History = append(entry.History, agentCommandJournalSeen{ID: entry.ID, PayloadHash: entry.PayloadHash})
			if len(entry.History) > agentCommandJournalHistoryLimit {
				entry.History = append([]agentCommandJournalSeen(nil), entry.History[len(entry.History)-agentCommandJournalHistoryLimit:]...)
			}
		}
		entry.ID, entry.PayloadHash = cmd.ID, hash
		entry.State, entry.Status, entry.Message, entry.Config = "running", "", "", ""
	}
	entry.State = "running"
	entry.Status, entry.Message, entry.Config = "", "", ""
	if err := writeAgentCommandJournal(entry); err != nil {
		return "failed", "", "", err
	}

	message, config, executeErr := execute()
	status = "success"
	if executeErr != nil {
		status = "failed"
		message = executeErr.Error()
	}
	if len(message) > 2048 {
		message = message[:2048]
	}
	if len(config) > 8<<10 {
		status = "failed"
		message = "Agent 返回配置超过 8 KiB，未保存命令成功结果"
		config = ""
	}
	entry.State, entry.Status, entry.Message, entry.Config = "completed", status, message, config
	if err := writeAgentCommandJournal(entry); err != nil {
		return "failed", "", "", fmt.Errorf("命令结果已产生，但持久化执行结果失败，拒绝发送 ACK: %w", err)
	}
	return status, message, config, nil
}
