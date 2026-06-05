package discord

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// GuildMember represents a Discord guild member as returned by the API.
type GuildMember struct {
	Roles []string `json:"roles"`
	User  *struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	} `json:"user"`
}

// GuildRole represents a Discord guild role (from GET /guilds/{id}/roles).
type GuildRole struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// DiscordUser represents a Discord user from GET /users/@me.
type DiscordUser struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Avatar        string `json:"avatar"`
	Discriminator string `json:"discriminator"`
}

// OAuthTokenResponse is the response from Discord's token exchange endpoint.
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// DiscordClient interacts with the Discord REST API.
type DiscordClient struct {
	clientID     string
	clientSecret string
	botToken     string
	guildID      string
	httpClient   *http.Client
}

// NewDiscordClient creates a new Discord API client.
func NewDiscordClient(clientID, clientSecret, botToken, guildID string) *DiscordClient {
	return &DiscordClient{
		clientID:     clientID,
		clientSecret: clientSecret,
		botToken:     botToken,
		guildID:      guildID,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

// IsOAuthConfigured returns true if client ID and secret are set for Discord OAuth.
func (c *DiscordClient) IsOAuthConfigured() bool {
	return c.clientID != "" && c.clientSecret != ""
}

// IsConfigured returns true if both bot token and guild ID are set.
func (c *DiscordClient) IsConfigured() bool {
	return c.botToken != "" && c.guildID != ""
}

// BuildAuthorizeURL constructs the Discord OAuth2 authorization URL.
func (c *DiscordClient) BuildAuthorizeURL(redirectURI, state string) string {
	params := url.Values{
		"client_id":     {c.clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"identify"},
	}
	if state != "" {
		params.Set("state", state)
	}
	return "https://discord.com/api/oauth2/authorize?" + params.Encode()
}

// ExchangeCode exchanges an OAuth2 authorization code for an access token.
func (c *DiscordClient) ExchangeCode(code, redirectURI string) (*OAuthTokenResponse, error) {
	data := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}

	req, err := http.NewRequest("POST", "https://discord.com/api/oauth2/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discord token exchange error %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp OAuthTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

// GetCurrentUser fetches the authenticated user's profile from Discord.
func (c *DiscordClient) GetCurrentUser(accessToken string) (*DiscordUser, error) {
	req, err := http.NewRequest("GET", "https://discord.com/api/v10/users/@me", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discord user request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read user response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discord user API error %d: %s", resp.StatusCode, string(body))
	}

	var user DiscordUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("failed to parse user: %w", err)
	}

	return &user, nil
}

// AvatarURL builds the CDN URL for a Discord user's avatar.
func (u *DiscordUser) AvatarURL() string {
	if u.Avatar == "" {
		return ""
	}
	ext := "png"
	if strings.HasPrefix(u.Avatar, "a_") {
		ext = "gif"
	}
	return fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.%s", u.ID, u.Avatar, ext)
}

// GetGuildMember fetches a guild member from the Discord API.
// Returns nil member and nil error if the user is not in the guild (404).
// Returns nil member and an error for other failure modes (403, rate limit, network error).
func (c *DiscordClient) GetGuildMember(discordUserID string) (*GuildMember, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("discord client not configured")
	}

	url := fmt.Sprintf("https://discord.com/api/v10/guilds/%s/members/%s", c.guildID, discordUserID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bot "+c.botToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discord API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var member GuildMember
		if err := json.Unmarshal(body, &member); err != nil {
			return nil, fmt.Errorf("failed to parse guild member: %w", err)
		}
		return &member, nil

	case http.StatusNotFound:
		// User is not a member of the guild
		return nil, nil

	case http.StatusTooManyRequests:
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		return nil, &RateLimitError{RetryAfter: retryAfter}

	default:
		return nil, fmt.Errorf("discord API error %d: %s", resp.StatusCode, string(body))
	}
}

// parseRetryAfter parses the Retry-After header (seconds or HTTP-date).
func parseRetryAfter(header string) time.Duration {
	if header == "" {
		return 5 * time.Second
	}
	if seconds, err := strconv.ParseFloat(header, 64); err == nil {
		return time.Duration(seconds * float64(time.Second))
	}
	if t, err := time.Parse(time.RFC1123, header); err == nil {
		return time.Until(t)
	}
	return 5 * time.Second
}

// RateLimitError is returned when the Discord API rate limits the request.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("discord rate limited, retry after %s", e.RetryAfter)
}

// FetchGuildRoles fetches all roles for the configured guild.
// Returns a list of roles with both ID and Name populated.
func (c *DiscordClient) FetchGuildRoles() ([]GuildRole, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("discord client not configured")
	}

	apiURL := fmt.Sprintf("https://discord.com/api/v10/guilds/%s/roles", c.guildID)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create roles request: %w", err)
	}
	req.Header.Set("Authorization", "Bot "+c.botToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discord roles request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read roles response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discord roles API error %d: %s", resp.StatusCode, string(body))
	}

	var roles []GuildRole
	if err := json.Unmarshal(body, &roles); err != nil {
		return nil, fmt.Errorf("failed to parse guild roles: %w", err)
	}

	return roles, nil
}

// BuildRoleNameToID converts a list of guild roles into a name→ID lookup map.
func BuildRoleNameToID(roles []GuildRole) map[string]string {
	m := make(map[string]string, len(roles))
	for _, r := range roles {
		m[r.Name] = r.ID
	}
	return m
}

// BuildRoleIDToName converts a list of guild roles into an ID→name lookup map.
func BuildRoleIDToName(roles []GuildRole) map[string]string {
	m := make(map[string]string, len(roles))
	for _, r := range roles {
		m[r.ID] = r.Name
	}
	return m
}

// ResolveRoleIDs converts a set of role names to a set of role IDs using
// the name→ID mapping from FetchGuildRoles.
func ResolveRoleIDs(roleNames map[string]bool, nameToID map[string]string) map[string]bool {
	if roleNames == nil || nameToID == nil {
		return nil
	}
	ids := make(map[string]bool)
	for name := range roleNames {
		if id, ok := nameToID[name]; ok {
			ids[id] = true
		}
	}
	return ids
}

// HasAllowedRole checks if the member has at least one of the allowed role IDs.
func (m *GuildMember) HasAllowedRole(allowedRoleIDs map[string]bool) bool {
	if m == nil || allowedRoleIDs == nil {
		return false
	}
	for _, role := range m.Roles {
		if allowedRoleIDs[role] {
			return true
		}
	}
	return false
}

// IntersectRoleIDs returns the intersection of the member's role IDs with the allowed set.
func (m *GuildMember) IntersectRoleIDs(allowedRoleIDs map[string]bool) []string {
	if m == nil {
		return nil
	}
	var matched []string
	for _, role := range m.Roles {
		if allowedRoleIDs[role] {
			matched = append(matched, role)
		}
	}
	return matched
}

// ResolveRoleNames maps a list of role IDs to their human-readable names.
func ResolveRoleNames(roleIDs []string, idToName map[string]string) []string {
	if idToName == nil {
		return roleIDs
	}
	names := make([]string, 0, len(roleIDs))
	for _, id := range roleIDs {
		if name, ok := idToName[id]; ok {
			names = append(names, name)
		} else {
			names = append(names, id)
		}
	}
	return names
}

// RolesAsSet converts a list of strings to a set map.
func RolesAsSet(roles []string) map[string]bool {
	set := make(map[string]bool, len(roles))
	for _, r := range roles {
		set[r] = true
	}
	return set
}

// HasRole checks if the user's local roles contain any admin-level role.
func HasAdminRole(roles []string) bool {
	for _, r := range roles {
		lower := strings.ToLower(r)
		if lower == "admin" || lower == "superadmin" {
			return true
		}
	}
	return false
}
