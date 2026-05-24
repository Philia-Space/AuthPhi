package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/philiaspace/authphi/auth"
	"github.com/philiaspace/authphi/config"
	"github.com/philiaspace/authphi/handlers"
	"github.com/philiaspace/phi-core/observability"
	"github.com/philiaspace/phi-middleware"
)

func main() {
	logger := observability.NewLogger(os.Getenv("LOG_LEVEL"))
	ctx := context.Background()

	cfg := config.Load()

	logger.Info(ctx, "starting AuthPhi service",
		"port", cfg.ServerPort,
		"env", cfg.Environment,
		"issuer", cfg.IssuerURL,
	)

	// Initialize RSA key manager
	km, err := auth.NewKeyManager(cfg.KeyPath)
	if err != nil {
		logger.Error(ctx, "failed to initialize key manager", "error", err)
		os.Exit(1)
	}

	logger.Info(ctx, "key manager initialized", "kid", km.GetActiveKid())

	// Initialize user store with seeder
	userStore := auth.NewUserStore()
	userStore.SeedAdmin(cfg.AdminUsername, cfg.AdminPassword)
	if cfg.AdminUsername != "" {
		logger.Info(ctx, "superadmin seeded", "username", cfg.AdminUsername)
	}

	authHandler := handlers.NewAuthHandler(cfg, logger, km, userStore)

	mux := http.NewServeMux()
	authHandler.RegisterRoutes(mux)

	// Apply middleware chain
	handler := middleware.Chain(mux,
		middleware.Recovery(logger),
		middleware.Logger(logger),
		middleware.CORS(),
		middleware.RateLimit(100),
		middleware.AuthJWKS(middleware.JWKSAuthConfig{
			IssuerURL:      cfg.IssuerURL,
			JWKSEndpoint:   "/.well-known/jwks.json",
			ExpectedIssuer: cfg.IssuerURL,
			Audience:       cfg.Audience,
			CacheTTL:       5 * time.Minute,
			SkipPaths:      []string{"/health", "/.well-known", "/api/auth/login", "/api/auth/logout", "/api/auth/discord/authorize", "/api/auth/discord/callback", "/api/auth/discord/exchange"},
		}),
	)

	addr := fmt.Sprintf(":%s", cfg.ServerPort)
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
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
