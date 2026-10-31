package main

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"

	"s5m-server/internal/app"
)

//go:embed web
var webFS embed.FS

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg := app.LoadEnv()
	a, err := app.New(cfg)
	if err != nil {
		logger.Error("初始化失败", "err", err)
		os.Exit(1)
	}

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		logger.Error("静态资源加载失败", "err", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           a.Router(sub),
		ReadHeaderTimeout: 10 * time.Second,
	}
	logger.Info("S5M-Server 已启动", "addr", cfg.Addr)
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("服务退出", "err", err)
		os.Exit(1)
	}
}
