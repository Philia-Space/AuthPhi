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
	// Load .env file if present (development convenience)
	if err := config.LoadDotEnv(".env"); err != nil {
		// Only fatal if .env is explicitly required; warn otherwise
		fmt.Fprintf(os.Stderr, "warn: could not load .env file: %v\n", err)
	}

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

	// AuthCodeStore doubles as the JWT JTI blocklist (logout revocation).
	// The store is shared between the auth handler (which calls BlockJTI
	// on logout) and the JWKS middleware (which calls IsBlocked on every
	// validated request).
	authCodes := auth.NewAuthCodeStore()

	authHandler := handlers.NewAuthHandler(cfg, logger, km, userStore, authCodes)

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
			Blocklist:      authCodes,
			SkipPaths:      []string{"/health", "/.well-known", "/api/auth/login", "/api/auth/logout", "/api/auth/discord/authorize", "/api/auth/discord/callback", "/api/auth/discord/redeem", "/api/auth/discord/verify-role"},
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
