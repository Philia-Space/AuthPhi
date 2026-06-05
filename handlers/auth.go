package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/philiaspace/authphi/auth"
	"github.com/philiaspace/authphi/config"
	discord "github.com/philiaspace/authphi/discord"
	"github.com/philiaspace/phi-core/observability"
	"github.com/philiaspace/phi-core/transport"
	"github.com/philiaspace/phi-middleware"
)

type AuthHandler struct {
	cfg            *config.Config
	logger         *observability.SlogLogger
	keyManager     *auth.KeyManager
	userStore      *auth.UserStore
	authCodes      *auth.AuthCodeStore
	discordClient  *discord.DiscordClient
}

func NewAuthHandler(cfg *config.Config, logger *observability.SlogLogger, km *auth.KeyManager, store *auth.UserStore, authCodes *auth.AuthCodeStore) *AuthHandler {
	h := &AuthHandler{
		cfg:        cfg,
		logger:     logger,
		keyManager: km,
		userStore:  store,
		authCodes:  authCodes,
	}

	if cfg.DiscordClientID != "" {
		h.discordClient = discord.NewDiscordClient(cfg.DiscordClientID, cfg.DiscordClientSecret, cfg.DiscordBotToken, cfg.DiscordGuildID)
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
	mux.HandleFunc("POST /api/auth/discord/redeem", h.DiscordRedeem)
	mux.HandleFunc("GET /api/auth/discord/verify-role", h.VerifyDiscordRole)
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

	// Mark as local login (skip Discord role verification)
	user.LoginMethod = "local"

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
		if claims, err := auth.ParseAccessToken(tokenStr, h.keyManager); err == nil && claims.ID != "" {
			h.authCodes.BlockJTI(claims.ID, 24*time.Hour)
		}
	}

	// Also check cookie
	if cookie, err := r.Cookie("phi_token"); err == nil && cookie.Value != "" {
		if claims, err := auth.ParseAccessToken(cookie.Value, h.keyManager); err == nil && claims.ID != "" {
			h.authCodes.BlockJTI(claims.ID, 24*time.Hour)
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

// DiscordAuthorize redirects the user to Discord's OAuth2 consent page.
// The frontend passes a redirect_to query param to control where Discord sends
// the user back after authentication.
func (h *AuthHandler) DiscordAuthorize(w http.ResponseWriter, r *http.Request) {
	if h.discordClient == nil || !h.discordClient.IsOAuthConfigured() {
		transport.InternalError(w, "Discord OAuth not configured (missing DISCORD_CLIENT_ID/DISCORD_CLIENT_SECRET)")
		return
	}

	callbackURL := h.cfg.DiscordRedirectURL
	if callbackURL == "" {
		callbackURL = h.cfg.IssuerURL + "/api/auth/discord/callback"
	}

	frontendRedirect := r.URL.Query().Get("redirect_to")
	if frontendRedirect == "" {
		frontendRedirect = h.cfg.IssuerURL
	}

	// Pass the frontend redirect URL as the OAuth state so we can forward it back
	state := url.QueryEscape(frontendRedirect)

	discordAuthURL := h.discordClient.BuildAuthorizeURL(callbackURL, state)
	http.Redirect(w, r, discordAuthURL, http.StatusTemporaryRedirect)
}

// DiscordCallback handles the redirect from Discord OAuth2 after user consent.
// It exchanges the authorization code for an access token, fetches the user's
// Discord profile, creates/updates the local user, issues a JWT, generates a
// one-time auth code, and redirects the user back to the LyraPhi frontend.
func (h *AuthHandler) DiscordCallback(w http.ResponseWriter, r *http.Request) {
	errorParam := r.URL.Query().Get("error")
	if errorParam != "" {
		transport.BadRequest(w, "Discord authorization denied: "+errorParam)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		transport.BadRequest(w, "missing authorization code from Discord")
		return
	}

	if h.discordClient == nil || !h.discordClient.IsOAuthConfigured() {
		transport.InternalError(w, "Discord OAuth not configured")
		return
	}

	callbackURL := h.cfg.DiscordRedirectURL
	if callbackURL == "" {
		callbackURL = h.cfg.IssuerURL + "/api/auth/discord/callback"
	}

	// Step 1: Exchange authorization code for access token
	tokenResp, err := h.discordClient.ExchangeCode(code, callbackURL)
	if err != nil {
		h.logger.Error(r.Context(), "failed to exchange Discord code", "error", err)
		transport.InternalError(w, "failed to authenticate with Discord")
		return
	}

	// Step 2: Fetch Discord user profile
	discordUser, err := h.discordClient.GetCurrentUser(tokenResp.AccessToken)
	if err != nil {
		h.logger.Error(r.Context(), "failed to fetch Discord user", "error", err)
		transport.InternalError(w, "failed to fetch Discord user profile")
		return
	}

	discordID := discordUser.ID
	displayName := discordUser.Username
	if displayName == "" {
		if len(discordID) >= 8 {
			displayName = "discord_" + discordID[len(discordID)-8:]
		} else {
			displayName = "discord_" + discordID
		}
	}
	avatarURL := discordUser.AvatarURL()

	// Step 3: Create or update local user
	user := h.userStore.GetOrCreateDiscordUser("discord_"+discordID, displayName, displayName, "")
	if avatarURL != "" {
		h.userStore.UpdateAvatar(user.ID, avatarURL)
	}

	// Set Discord-specific claims on the cloned user for JWT generation
	user.LoginMethod = "discord"
	user.DiscordID = discordID

	// Step 4: Issue JWT
	jwtToken, err := auth.GenerateAccessToken(user, h.keyManager, h.cfg.IssuerURL, h.cfg.Audience, 24*time.Hour)
	if err != nil {
		h.logger.Error(r.Context(), "failed to generate token", "error", err)
		transport.InternalError(w, "failed to generate token")
		return
	}

	// Step 5: Generate one-time auth code and redirect to frontend
	frontendRedirect := r.URL.Query().Get("state")
	if frontendRedirect == "" {
		frontendRedirect = "/"
	} else {
		unescaped, err := url.QueryUnescape(frontendRedirect)
		if err == nil {
			frontendRedirect = unescaped
		}
	}

	authCode := h.authCodes.Generate(jwtToken, user.ID, user.Username, user.Name)
	redirectTo := frontendRedirect + "?code=" + url.QueryEscape(authCode)

	h.logger.Info(r.Context(), "discord OAuth callback success",
		"discord_id", discordID,
		"username", displayName,
		"redirect_to", redirectTo,
	)

	http.Redirect(w, r, redirectTo, http.StatusTemporaryRedirect)
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

// VerifyDiscordRole checks whether a Discord-authenticated user has the required
// guild roles to access PhiliaSpace. Local login and admin users are always allowed.
// This endpoint is public (in SkipPaths) and does its own JWT parsing.
//
// Role IDs from config (DISCORD_ALLOWED_ROLE_IDS) are compared directly against
// the member's role IDs returned by Discord's API.
func (h *AuthHandler) VerifyDiscordRole(w http.ResponseWriter, r *http.Request) {
	// Extract JWT from Authorization header
	authHeader := r.Header.Get("Authorization")
	var tokenStr string
	if len(authHeader) > 7 && strings.HasPrefix(authHeader, "Bearer ") {
		tokenStr = authHeader[7:]
	}
	if tokenStr == "" {
		// Try cookie fallback
		if cookie, err := r.Cookie("phi_token"); err == nil && cookie.Value != "" {
			tokenStr = cookie.Value
		}
	}
	if tokenStr == "" {
		transport.Unauthorized(w, "missing authorization token")
		return
	}

	// Parse JWT using our own claims (not middleware claims, to access login_method/discord_id)
	claims, err := auth.ParseAccessToken(tokenStr, h.keyManager)
	if err != nil {
		h.logger.Warn(r.Context(), "verify-role: invalid token", "error", err)
		transport.Unauthorized(w, "invalid or expired token")
		return
	}

	// Build allowed role ID set from config
	allowedRoleIDs := h.cfg.AllowedRoleIDSet()
	allowedRoleIDList := allowedRoleSlice(allowedRoleIDs)

	// Always allow admins (users with "admin" or "superadmin" role in JWT)
	if discord.HasAdminRole(claims.Roles) {
		transport.OK(w, map[string]interface{}{
			"allowed":  true,
			"is_admin": true,
		})
		return
	}

	// Local (username/password) login always allowed — no role check needed
	if claims.LoginMethod == "local" {
		transport.OK(w, map[string]interface{}{
			"allowed":      true,
			"is_admin":     false,
			"login_method": "local",
		})
		return
	}

	// Non-Discord login with no explicit login method — treat as allowed (backward compat)
	if claims.LoginMethod != "discord" && claims.DiscordID == "" {
		transport.OK(w, map[string]interface{}{
			"allowed":      true,
			"is_admin":     false,
			"login_method": claims.LoginMethod,
		})
		return
	}

	// Discord login — check guild membership and roles
	if claims.DiscordID == "" {
		transport.OK(w, map[string]interface{}{
			"allowed":        false,
			"in_guild":       false,
			"message":        "Discord user ID not found in token. Please log in again.",
			"guild_id":       h.cfg.DiscordGuildID,
			"required_roles": allowedRoleIDList,
		})
		return
	}

	if h.discordClient == nil || !h.discordClient.IsConfigured() {
		// Fallback: if Discord API is not configured, fail open for Discord users
		h.logger.Warn(r.Context(), "verify-role: Discord client not configured, failing open")
		transport.OK(w, map[string]interface{}{
			"allowed":  true,
			"is_admin": false,
			"note":     "discord_role_check_disabled",
		})
		return
	}

	// Fetch guild member
	member, err := h.discordClient.GetGuildMember(claims.DiscordID)
	if err != nil {
		h.logger.Error(r.Context(), "verify-role: Discord API error, failing open", "error", err)
		transport.OK(w, map[string]interface{}{
			"allowed":  true,
			"is_admin": false,
			"note":     "discord_api_unavailable",
		})
		return
	}

	// User not in guild
	if member == nil {
		transport.OK(w, map[string]interface{}{
			"allowed":        false,
			"in_guild":       false,
			"message":        "You are not a member of the PhiliaSpace Discord server. Please join to access JLPT practice exams.",
			"guild_id":       h.cfg.DiscordGuildID,
			"required_roles": allowedRoleIDList,
		})
		return
	}

	// Check role intersection (direct ID comparison)
	hasAllowedRole := member.HasAllowedRole(allowedRoleIDs)
	matchedRoleIDs := member.IntersectRoleIDs(allowedRoleIDs)

	h.logger.Info(r.Context(), "verify-role: member role check",
		"discord_id", claims.DiscordID,
		"member_role_ids", strings.Join(member.Roles, ", "),
		"allowed_role_ids", strings.Join(allowedRoleIDList, ", "),
		"has_allowed_role", hasAllowedRole,
	)

	transport.OK(w, map[string]interface{}{
		"allowed":        hasAllowedRole,
		"in_guild":       true,
		"user_roles":     member.Roles,
		"matched_roles":  matchedRoleIDs,
		"required_roles": allowedRoleIDList,
		"guild_id":       h.cfg.DiscordGuildID,
		"discord_user": map[string]interface{}{
			"id":       claims.DiscordID,
			"username": claims.Username,
		},
	})
}

// allowedRoleSlice returns the allowed role strings as a string slice.
func allowedRoleSlice(set map[string]bool) []string {
	if set == nil {
		return nil
	}
	roles := make([]string, 0, len(set))
	for r := range set {
		roles = append(roles, r)
	}
	return roles
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
