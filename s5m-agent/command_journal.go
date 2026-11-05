package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type agentCommandJournalEntry struct {
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

func readAgentCommandJournal() (agentCommandJournalEntry, error) {
	var entry agentCommandJournalEntry
	data, err := os.ReadFile(agentCommandJournalPath())
	if os.IsNotExist(err) {
		return entry, nil
	}
	if err != nil {
		return entry, fmt.Errorf("读取 Agent 命令执行记录失败: %w", err)
	}
	if len(data) > 16<<10 {
		return entry, fmt.Errorf("Agent 命令执行记录超过 16 KiB")
	}
	if err := json.Unmarshal(data, &entry); err != nil {
		return entry, fmt.Errorf("Agent 命令执行记录损坏，拒绝覆盖: %w", err)
	}
	if entry.ID == "" || entry.PayloadHash == "" || (entry.State != "running" && entry.State != "completed") {
		return entry, fmt.Errorf("Agent 命令执行记录字段无效，拒绝覆盖")
	}
	return entry, nil
}

func writeAgentCommandJournal(entry agentCommandJournalEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
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
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("写入 Agent 命令记录失败: %w", err)
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
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

// executeAgentCommandWithJournal records intent before side effects and the final
// result before ACK. A crash in "running" is reconciled by rerunning the
// idempotent desired-state operation; a completed command replays its saved ACK.
func executeAgentCommandWithJournal(cmd agentCommand, execute func() (string, string, error)) (status, message, config string, err error) {
	agentCommandJournalMu.Lock()
	defer agentCommandJournalMu.Unlock()

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
		entry = agentCommandJournalEntry{ID: cmd.ID, PayloadHash: hash, State: "running"}
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
