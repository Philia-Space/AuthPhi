package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/philiaspace/authphi/config"
	"github.com/philiaspace/authphi/handlers"
	"github.com/philiaspace/phi-core/observability"
)

func main() {
	logger := observability.NewLogger(os.Getenv("LOG_LEVEL"))
	ctx := context.Background()

	cfg := config.Load()

	logger.Info(ctx, "starting AuthPhi service",
		"port", cfg.ServerPort,
		"env", cfg.Environment,
	)

	authHandler := handlers.NewAuthHandler(cfg, logger)

	mux := http.NewServeMux()
	authHandler.RegisterRoutes(mux)

	addr := fmt.Sprintf(":%s", cfg.ServerPort)
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		logger.Info(ctx, "server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error(ctx, "server failed", "error", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info(ctx, "shutting down server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error(ctx, "server shutdown failed", "error", err)
		os.Exit(1)
	}

	logger.Info(ctx, "server stopped gracefully")
}
