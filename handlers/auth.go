package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/philiaspace/authphi/auth"
	"github.com/philiaspace/authphi/config"
	"github.com/philiaspace/phi-core/observability"
	"github.com/philiaspace/phi-core/transport"
	"github.com/philiaspace/phi-middleware"
)

type AuthHandler struct {
	cfg              *config.Config
	logger           *observability.SlogLogger
	keyManager       *auth.KeyManager
	userStore        *auth.UserStore
	supabaseVerifier *auth.SupabaseVerifier
	authCodes        *auth.AuthCodeStore
}

func NewAuthHandler(cfg *config.Config, logger *observability.SlogLogger, km *auth.KeyManager, store *auth.UserStore) *AuthHandler {
	h := &AuthHandler{
		cfg:        cfg,
		logger:     logger,
		keyManager: km,
		userStore:  store,
		authCodes:  auth.NewAuthCodeStore(),
	}

	if cfg.SupabaseURL != "" {
		h.supabaseVerifier = auth.NewSupabaseVerifier(cfg.SupabaseURL)
	}

	return h
}

// decodeBody reads and decodes a JSON request body with a 1MB size limit
// to prevent denial-of-service attacks via oversized payloads.
func decodeBody(w http.ResponseWriter, r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB max
	return json.NewDecoder(r.Body).Decode(v)
}

func (h *AuthHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", h.Health)
	mux.HandleFunc("POST /api/auth/login", h.Login)
	mux.HandleFunc("POST /api/auth/logout", h.Logout)
	mux.HandleFunc("GET /api/auth/me", h.GetMe)
	mux.HandleFunc("GET /api/auth/discord/authorize", h.DiscordAuthorize)
	mux.HandleFunc("GET /api/auth/discord/callback", h.DiscordCallback)
	mux.HandleFunc("POST /api/auth/discord/exchange", h.DiscordExchange)
	mux.HandleFunc("POST /api/auth/discord/redeem", h.DiscordRedeem)
	mux.HandleFunc("GET /.well-known/jwks.json", h.GetJWKS)
	mux.HandleFunc("GET /.well-known/openid-configuration", h.GetOIDCConfig)
}

func (h *AuthHandler) Health(w http.ResponseWriter, r *http.Request) {
	transport.OK(w, map[string]string{
		"status":      "healthy",
		"service":     "AuthPhi",
		"environment": h.cfg.Environment,
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := decodeBody(w, r, &req); err != nil {
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

	// Set httpOnly cookie so Logout can clear it and frontends can use cookie-based auth
	http.SetCookie(w, &http.Cookie{
		Name:     "phi_token",
		Value:    token,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   h.cfg.Environment == "production",
		SameSite: http.SameSiteLaxMode,
	})

	transport.OK(w, map[string]interface{}{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   86400,
		"user": map[string]interface{}{
			"id":       user.ID,
			"username": user.Username,
			"name":     user.Name,
			"avatar":   user.Avatar,
			"roles":    user.Roles,
		},
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Extract and block the token JTI if present
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		tokenStr := authHeader[7:]
		if claims, err := auth.ParseAccessToken(tokenStr, h.keyManager); err == nil && claims.JTI != "" {
			h.authCodes.BlockJTI(claims.JTI, 24*time.Hour)
		}
	}

	// Also check cookie
	if cookie, err := r.Cookie("phi_token"); err == nil && cookie.Value != "" {
		if claims, err := auth.ParseAccessToken(cookie.Value, h.keyManager); err == nil && claims.JTI != "" {
			h.authCodes.BlockJTI(claims.JTI, 24*time.Hour)
		}
	}

	// Clear auth cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "phi_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cfg.Environment == "production",
		SameSite: http.SameSiteLaxMode,
	})
	transport.OK(w, map[string]string{"message": "logged out"})
}

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

func (h *AuthHandler) DiscordAuthorize(w http.ResponseWriter, r *http.Request) {
	if h.cfg.SupabaseURL == "" {
		transport.InternalError(w, "Discord OAuth not configured (missing SUPABASE_URL)")
		return
	}

	callbackURL := h.cfg.DiscordRedirectURL
	if callbackURL == "" {
		callbackURL = h.cfg.IssuerURL + "/api/auth/discord/callback"
	}

	frontendRedirect := r.URL.Query().Get("redirect_to")
	if frontendRedirect == "" {
		frontendRedirect = "/"
	}

	params := url.Values{
		"provider":    {"discord"},
		"redirect_to": {callbackURL + "?frontend_redirect=" + url.QueryEscape(frontendRedirect)},
	}

	supabaseAuthURL := h.cfg.SupabaseURL + "/auth/v1/authorize?" + params.Encode()
	http.Redirect(w, r, supabaseAuthURL, http.StatusTemporaryRedirect)
}

func (h *AuthHandler) DiscordCallback(w http.ResponseWriter, r *http.Request) {
	errorParam := r.URL.Query().Get("error")
	if errorParam != "" {
		transport.BadRequest(w, "Discord authorization denied: "+errorParam)
		return
	}

	accessToken := r.URL.Query().Get("access_token")
	refreshToken := r.URL.Query().Get("refresh_token")

	if accessToken == "" {
		accessToken = r.URL.Query().Get("token")
	}

	if accessToken == "" {
		transport.BadRequest(w, "missing access_token from Supabase")
		return
	}

	if h.supabaseVerifier == nil {
		transport.InternalError(w, "Supabase verifier not configured")
		return
	}

	claims, err := h.supabaseVerifier.VerifyToken(r.Context(), accessToken)
	if err != nil {
		h.logger.Error(r.Context(), "failed to verify Supabase token", "error", err)
		transport.InternalError(w, "failed to verify Supabase token")
		return
	}

	discordID := claims.DiscordID()
	displayName := claims.DisplayName()
	avatarURL := claims.AvatarURL()
	email := claims.UserEmail()

	username := displayName
	if username == "" {
		if len(discordID) >= 8 {
			username = "discord_" + discordID[len(discordID)-8:]
		} else {
			username = "discord_" + discordID
		}
	}

	user := h.userStore.GetOrCreateDiscordUser("discord_"+discordID, username, displayName, email)
	if avatarURL != "" {
		h.userStore.UpdateAvatar(user.ID, avatarURL)
	}

	jwtToken, err := auth.GenerateAccessToken(user, h.keyManager, h.cfg.IssuerURL, h.cfg.Audience, 24*time.Hour)
	if err != nil {
		h.logger.Error(r.Context(), "failed to generate token", "error", err)
		transport.InternalError(w, "failed to generate token")
		return
	}

	_ = refreshToken

	frontendRedirect := r.URL.Query().Get("frontend_redirect")
	if frontendRedirect == "" {
		frontendRedirect = "/"
	}

	code := h.authCodes.Generate(jwtToken, user.ID, user.Username, user.Name)
	redirectTo := frontendRedirect + "?code=" + url.QueryEscape(code)

	http.Redirect(w, r, redirectTo, http.StatusTemporaryRedirect)
}

func (h *AuthHandler) DiscordExchange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SupabaseToken string `json:"supabase_token"`
		DiscordID     string `json:"discord_id"`
		Username      string `json:"username"`
		Email         string `json:"email"`
	}

	if err := decodeBody(w, r, &req); err != nil {
		transport.BadRequest(w, "invalid request body")
		return
	}

	if req.SupabaseToken == "" {
		transport.BadRequest(w, "supabase_token is required")
		return
	}

	if h.supabaseVerifier == nil {
		transport.InternalError(w, "Supabase verifier not configured")
		return
	}

	claims, err := h.supabaseVerifier.VerifyToken(r.Context(), req.SupabaseToken)
	if err != nil {
		h.logger.Error(r.Context(), "failed to verify Supabase token", "error", err)
		transport.BadRequest(w, "invalid Supabase token")
		return
	}

	discordID := req.DiscordID
	if discordID == "" {
		discordID = claims.DiscordID()
	}

	displayName := claims.DisplayName()
	if displayName == "" {
		displayName = req.Username
	}
	if displayName == "" {
		if len(discordID) >= 8 {
			displayName = "discord_" + discordID[len(discordID)-8:]
		} else {
			displayName = "discord_" + discordID
		}
	}

	email := req.Email
	if email == "" {
		email = claims.UserEmail()
	}

	user := h.userStore.GetOrCreateDiscordUser("discord_"+discordID, displayName, displayName, email)

	jwtToken, err := auth.GenerateAccessToken(user, h.keyManager, h.cfg.IssuerURL, h.cfg.Audience, 24*time.Hour)
	if err != nil {
		h.logger.Error(r.Context(), "failed to generate token", "error", err)
		transport.InternalError(w, "failed to generate token")
		return
	}

	transport.OK(w, map[string]interface{}{
		"access_token": jwtToken,
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

// DiscordRedeem exchanges a one-time authorization code for a JWT token.
// This is the back-channel endpoint that the frontend calls after receiving
// the code from the OAuth callback redirect.
func (h *AuthHandler) DiscordRedeem(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeBody(w, r, &req); err != nil {
		transport.BadRequest(w, "invalid request body")
		return
	}

	entry, valid := h.authCodes.Redeem(req.Code)
	if !valid {
		transport.BadRequest(w, "invalid or expired code")
		return
	}

	transport.OK(w, map[string]interface{}{
		"access_token": entry.Token,
		"token_type":   "Bearer",
		"expires_in":   86400,
		"user": map[string]interface{}{
			"id":       entry.UserID,
			"username": entry.Username,
			"name":     entry.Name,
		},
	})
}

func (h *AuthHandler) GetJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := h.keyManager.GetJWKS()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

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
