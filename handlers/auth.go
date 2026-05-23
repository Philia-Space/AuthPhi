package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/philiaspace/authphi/auth"
	"github.com/philiaspace/authphi/config"
	"github.com/philiaspace/phi-core/observability"
	"github.com/philiaspace/phi-core/transport"
	"github.com/philiaspace/phi-middleware"
)

// AuthHandler handles authentication HTTP routes
type AuthHandler struct {
	cfg        *config.Config
	logger     *observability.SlogLogger
	keyManager *auth.KeyManager
	userStore  *auth.UserStore
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(cfg *config.Config, logger *observability.SlogLogger, km *auth.KeyManager, store *auth.UserStore) *AuthHandler {
	return &AuthHandler{
		cfg:        cfg,
		logger:     logger,
		keyManager: km,
		userStore:  store,
	}
}

// RegisterRoutes registers auth routes
func (h *AuthHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", h.Health)
	mux.HandleFunc("POST /api/auth/login", h.Login)
	mux.HandleFunc("POST /api/auth/logout", h.Logout)
	mux.HandleFunc("GET /api/auth/me", h.GetMe)
	mux.HandleFunc("GET /.well-known/jwks.json", h.GetJWKS)
	mux.HandleFunc("GET /.well-known/openid-configuration", h.GetOIDCConfig)
}

// Health returns service health status
func (h *AuthHandler) Health(w http.ResponseWriter, r *http.Request) {
	transport.OK(w, map[string]string{
		"status":      "healthy",
		"service":     "AuthPhi",
		"environment": h.cfg.Environment,
	})
}

// Login authenticates a user and returns a JWT token
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		transport.BadRequest(w, "invalid request body")
		return
	}

	user, err := h.userStore.Login(req.Username, req.Password)
	if err != nil {
		transport.BadRequest(w, "invalid credentials")
		return
	}

	token, err := auth.GenerateAccessToken(user, h.keyManager, h.cfg.IssuerURL, h.cfg.Audience, 24*time.Hour)
	if err != nil {
		h.logger.Error(r.Context(), "failed to generate token", "error", err)
		transport.InternalError(w, "failed to generate token")
		return
	}

	transport.OK(w, map[string]interface{}{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   86400,
		"user": map[string]interface{}{
			"id":       user.ID,
			"username": user.Username,
			"name":     user.Name,
			"roles":    user.Roles,
		},
	})
}

// Logout invalidates user session (placeholder for now)
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	transport.OK(w, map[string]string{"message": "logged out"})
}

// GetMe returns the current authenticated user
func (h *AuthHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.GetUserFromContext(r.Context())
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error": map[string]string{
				"code":    "UNAUTHORIZED",
				"message": "not authenticated",
			},
		})
		return
	}

	transport.OK(w, map[string]interface{}{
		"user": map[string]interface{}{
			"id":       claims.UserID,
			"username": claims.Username,
			"name":     claims.Name,
			"roles":    claims.Roles,
		},
	})
}

// GetJWKS returns the JSON Web Key Set
func (h *AuthHandler) GetJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := h.keyManager.GetJWKS()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

// OIDCConfiguration represents OpenID Connect discovery configuration
type OIDCConfiguration struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

// GetOIDCConfig returns the OpenID Connect discovery configuration
func (h *AuthHandler) GetOIDCConfig(w http.ResponseWriter, r *http.Request) {
	config := OIDCConfiguration{
		Issuer:                           h.cfg.IssuerURL,
		JWKSURI:                          h.cfg.IssuerURL + "/.well-known/jwks.json",
		AuthorizationEndpoint:            h.cfg.IssuerURL + "/api/auth/authorize",
		TokenEndpoint:                    h.cfg.IssuerURL + "/api/auth/login",
		UserInfoEndpoint:                 h.cfg.IssuerURL + "/api/auth/me",
		ResponseTypesSupported:           []string{"code", "token"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "profile", "email"},
		ClaimsSupported: []string{
			"iss", "sub", "aud", "exp", "nbf", "iat", "jti",
			"user_id", "username", "name", "roles", "type",
		},
	}
	transport.OK(w, config)
}
