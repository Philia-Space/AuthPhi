package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/philiaspace/authphi/config"
	"github.com/philiaspace/phi-core/observability"
	"github.com/philiaspace/phi-core/transport"
)

// AuthHandler handles authentication HTTP routes.
type AuthHandler struct {
	cfg    *config.Config
	logger *observability.SlogLogger
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(cfg *config.Config, logger *observability.SlogLogger) *AuthHandler {
	return &AuthHandler{
		cfg:    cfg,
		logger: logger,
	}
}

// RegisterRoutes registers auth routes on the router.
func (h *AuthHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", h.Health)
	mux.HandleFunc("GET /auth/discord", h.DiscordLogin)
	mux.HandleFunc("GET /auth/discord/callback", h.DiscordCallback)
	mux.HandleFunc("POST /auth/refresh", h.RefreshToken)
	mux.HandleFunc("POST /auth/logout", h.Logout)
	mux.HandleFunc("GET /auth/me", h.GetMe)
}

// Health returns service health status.
func (h *AuthHandler) Health(w http.ResponseWriter, r *http.Request) {
	transport.OK(w, map[string]string{
		"status":      "healthy",
		"service":     "AuthPhi",
		"environment": h.cfg.Environment,
	})
}

// DiscordLogin initiates Discord OAuth flow.
func (h *AuthHandler) DiscordLogin(w http.ResponseWriter, r *http.Request) {
	// TODO: Generate state, redirect to Discord OAuth
	transport.OK(w, map[string]string{
		"message": "Discord OAuth initiated",
	})
}

// DiscordCallback handles Discord OAuth callback.
func (h *AuthHandler) DiscordCallback(w http.ResponseWriter, r *http.Request) {
	// TODO: Exchange code for token, create/find user, issue JWT
	code := r.URL.Query().Get("code")
	if code == "" {
		transport.BadRequest(w, "missing code parameter")
		return
	}

	transport.OK(w, map[string]string{
		"message": "OAuth callback received",
	})
}

// RefreshToken refreshes an access token.
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	// TODO: Validate refresh token, issue new access token
	transport.OK(w, map[string]string{
		"message": "Token refreshed",
	})
}

// Logout invalidates user session.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// TODO: Invalidate session
	transport.OK(w, map[string]string{
		"message": "Logged out",
	})
}

// GetMe returns the current authenticated user.
func (h *AuthHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	// TODO: Extract user from JWT, return user info
	transport.OK(w, map[string]string{
		"message": "User info endpoint",
	})
}

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
