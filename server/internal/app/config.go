package app

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type Config struct {
	Addr             string
	DBPath           string
	ConfigPath       string
	BackupDir        string
	JWTSecret        string
	AdminUser        string
	AdminPass        string
	MihomoAPI        string
	MihomoSecret     string
	MihomoConfigPath string
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// randomHexFrom makes entropy failures explicit and testable. A partially read
// buffer must never be accepted as a JWT signing secret.
func randomHexFrom(source io.Reader, n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("随机密钥长度必须大于零")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(source, b); err != nil {
		return "", fmt.Errorf("读取安全随机数失败: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func randomHex(n int) string {
	value, err := randomHexFrom(rand.Reader, n)
	if err != nil {
		// Starting with an empty or predictable JWT secret would make every
		// administrator session forgeable. Fail closed instead.
		panic(fmt.Errorf("生成 JWT 签名密钥失败: %w", err))
	}
	return value
}

func LoadEnv() Config {
	return Config{
		Addr:             env("S5M_ADDR", ":80"),
		DBPath:           env("S5M_DB", "/var/lib/s5m-server/s5m.db"),
		ConfigPath:       env("S5M_CONFIG", "/var/lib/s5m-server/config.yaml"),
		BackupDir:        env("S5M_BACKUP", "/var/lib/s5m-server/backups"),
		JWTSecret:        env("S5M_JWT_SECRET", randomHex(32)),
		AdminUser:        env("S5M_ADMIN_USER", "admin"),
		AdminPass:        env("S5M_ADMIN_PASSWORD", ""),
		MihomoAPI:        env("MIHOMO_API", "http://127.0.0.1:8088"),
		MihomoSecret:     env("MIHOMO_SECRET", ""),
		MihomoConfigPath: env("MIHOMO_CONFIG_PATH", "/var/lib/s5m-server/config.yaml"),
	}
}
