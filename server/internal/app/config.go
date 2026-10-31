package app

import (
	"crypto/rand"
	"encoding/hex"
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

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
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
